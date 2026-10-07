import { log } from 'apify';
import pg from 'pg';

const UA = 'CertificateTransparencyMonitor/0.2 (+https://github.com/timmKal01/certificate-transparency-monitor)';

const TRANSIENT_STATUSES = new Set([404, 502, 503, 504]);
const WEB_MAX_ATTEMPTS = 3;
const MAX_BACKOFF_MS = 8000;
const REQUEST_TIMEOUT_MS = 20000;

/**
 * Apify's daily health check expects a finished run with data inside 5 minutes, and users on a
 * schedule want an answer, not a hang. Everything below shares one budget that stays under that.
 */
const TOTAL_BUDGET_MS = 240_000;
const DB_CONNECT_TIMEOUT_MS = 20000;

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * crt.sh is a free community service that returns bare error pages (HTML, not JSON) under load —
 * observed as both 404 and 502 for the *same* query on different attempts, so these are not a
 * reliable "zero results" signal. Retry transient-looking failures instead of treating them as
 * empty results, since silently reporting "no certificates" on a backend hiccup would be actively
 * misleading for a security-monitoring tool.
 *
 * Each attempt has its own timeout: a test run once hung indefinitely with no response at all,
 * which plain fetch() has no protection against.
 *
 * Down from 8 attempts to 3 (2026-10-07): long outages of the website are now covered by the
 * database fallback below, so retrying the website for minutes only used up the time budget.
 */
async function fetchWithRetry(url, deadline) {
    let lastError;
    for (let attempt = 1; attempt <= WEB_MAX_ATTEMPTS && Date.now() < deadline; attempt++) {
        const controller = new AbortController();
        const timeoutMs = Math.min(REQUEST_TIMEOUT_MS, deadline - Date.now());
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
        let res;
        try {
            res = await fetch(url, { headers: { 'User-Agent': UA }, signal: controller.signal });
        } catch (err) {
            lastError = err.name === 'AbortError'
                ? new Error(`crt.sh request timed out after ${timeoutMs}ms`)
                : err;
            if (attempt < WEB_MAX_ATTEMPTS) {
                await sleep(Math.min(1000 * 2 ** (attempt - 1), MAX_BACKOFF_MS));
            }
            continue;
        } finally {
            clearTimeout(timeoutId);
        }
        if (res.ok) return res;
        if (!TRANSIENT_STATUSES.has(res.status)) {
            throw new Error(`crt.sh request failed: ${res.status}`);
        }
        lastError = new Error(`crt.sh request failed: ${res.status}`);
        if (attempt < WEB_MAX_ATTEMPTS) {
            await sleep(Math.min(1000 * 2 ** (attempt - 1), MAX_BACKOFF_MS));
        }
    }
    throw new Error(`crt.sh website unavailable after ${WEB_MAX_ATTEMPTS} attempts: ${lastError?.message ?? 'out of time'}`);
}

async function fetchFromWebsite(domain, deadline) {
    const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json&exclude=expired`;
    const res = await fetchWithRetry(url, deadline);
    return res.json();
}

/**
 * Same identity search the crt.sh website runs (the domain and every subdomain, unexpired only),
 * against crt.sh's public read-only PostgreSQL interface. Matches are capped at 5,000 in no
 * particular order: sorting them newest-first made crt.sh cancel the query at its server-side
 * statement timeout (tested 2026-10-07), so very large domains can miss some recent certificates
 * on this fallback path.
 */
const DB_QUERY = `
    SELECT c.id,
           x509_commonName(c.certificate) AS common_name,
           ca.name AS issuer_name,
           encode(x509_serialNumber(c.certificate), 'hex') AS serial_number,
           x509_notBefore(c.certificate) AS not_before,
           x509_notAfter(c.certificate) AS not_after,
           array_to_string(ARRAY(SELECT DISTINCT lower(n) FROM x509_altNames(c.certificate) n), chr(10)) AS name_value
    FROM certificate c
    JOIN ca ON ca.id = c.issuer_ca_id
    WHERE c.id IN (
        SELECT cai.certificate_id
        FROM certificate_and_identities cai
        WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.certificate)
          AND (cai.name_value ILIKE '%.' || $1 OR lower(cai.name_value) = lower($1))
        LIMIT 5000)
      AND x509_notAfter(c.certificate) > now()
      AND x509_notBefore(c.certificate) >= $2::timestamp
    ORDER BY x509_notBefore(c.certificate) DESC
    LIMIT $3`;

/** The database returns timestamps as Date objects; match the website's "2026-10-03T07:08:23" form. */
const toCrtshTime = (value) => (value instanceof Date ? value.toISOString().slice(0, 19) : value);

/**
 * The crt.sh website (its JSON output) is the part that falls over under load; the database behind
 * it, which crt.sh opens to the public as guest@crt.sh:5432/certwatch, kept answering during
 * website outages (checked 2026-10-07: every website request returned 502 while the database
 * answered in 25-35 seconds). It is slower, so it is the fallback rather than the first choice.
 */
export async function fetchFromDatabase({ domain, startDate, maxResults }, deadline) {
    let lastError;
    // One retry when there's time for it: a connection occasionally times out right after crt.sh cancels a query.
    for (let attempt = 1; attempt <= 2 && deadline - Date.now() > 30_000; attempt++) {
        try {
            return await queryDatabase({ domain, startDate, maxResults }, deadline);
        } catch (err) {
            lastError = err;
            log.warning(`crt.sh database attempt ${attempt} failed`, { error: err.message });
        }
    }
    throw lastError ?? new Error('out of time');
}

async function queryDatabase({ domain, startDate, maxResults }, deadline) {
    const client = new pg.Client({
        host: 'crt.sh',
        port: 5432,
        user: 'guest',
        database: 'certwatch',
        application_name: 'certificate-transparency-monitor',
        connectionTimeoutMillis: DB_CONNECT_TIMEOUT_MS,
        query_timeout: Math.max(deadline - Date.now(), 1000),
    });
    // crt.sh's connection pooler drops idle or cancelled connections with an error event; without a
    // listener, Node treats that as an unhandled error and kills the whole run.
    client.on('error', (err) => log.debug('crt.sh database connection closed', { error: err.message }));
    try {
        await client.connect();
        // Precertificates and final certificates share a serial, so ask for extra rows before de-duplicating.
        const { rows } = await client.query(DB_QUERY, [domain.toLowerCase(), startDate.toISOString(), maxResults * 3]);
        return rows.map((row) => ({ ...row, not_before: toCrtshTime(row.not_before), not_after: toCrtshTime(row.not_after) }));
    } finally {
        await client.end().catch(() => {});
    }
}

export async function fetchCertificates({ domain, startDate, maxResults }) {
    const deadline = Date.now() + TOTAL_BUDGET_MS;

    let entries;
    let source = 'crt.sh website';
    try {
        // Leave most of the budget for the slower database fallback.
        entries = await fetchFromWebsite(domain, Date.now() + 75_000);
    } catch (websiteError) {
        log.warning(`crt.sh website unavailable, querying the crt.sh database instead`, { error: websiteError.message });
        source = 'crt.sh database';
        try {
            entries = await fetchFromDatabase({ domain, startDate, maxResults }, deadline);
        } catch (databaseError) {
            throw new Error(`crt.sh is unavailable right now. Website: ${websiteError.message}. Database: ${databaseError.message}`);
        }
    }

    const bySerial = new Map();
    for (const e of entries) {
        if (!bySerial.has(e.serial_number)) bySerial.set(e.serial_number, e);
    }

    // crt.sh's JSON output for this query no longer includes `entry_timestamp` (observed:
    // present in some crt.sh response shapes, absent from this one), which silently made every
    // entry fail `new Date(undefined) >= startDate` and return zero results regardless of the
    // real data available. `not_before` (when the cert becomes valid) is always present and is
    // issued essentially at CT-log time, so it's used as the log-time proxy for both the date
    // filter and the sort instead.
    const certificates = [...bySerial.values()]
        .filter((e) => new Date(e.not_before) >= startDate)
        .sort((a, b) => new Date(b.not_before) - new Date(a.not_before))
        .slice(0, maxResults)
        .map((e) => ({
            commonName: e.common_name,
            subjectAlternativeNames: [...new Set((e.name_value ?? '').split('\n').filter(Boolean))],
            issuerName: e.issuer_name,
            serialNumber: e.serial_number,
            notBefore: e.not_before,
            notAfter: e.not_after,
            entryTimestamp: e.not_before,
            crtshUrl: `https://crt.sh/?id=${e.id}`,
            source,
        }));
    return { certificates, source };
}
