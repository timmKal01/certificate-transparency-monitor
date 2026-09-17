const UA = 'CertificateTransparencyMonitor/0.1 (+contact: ct-monitor-admin@example.com)';

const TRANSIENT_STATUSES = new Set([404, 502, 503, 504]);
const MAX_ATTEMPTS = 8;
const MAX_BACKOFF_MS = 8000;
const REQUEST_TIMEOUT_MS = 25000;

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
 * Bumped from 4 to 8 attempts (capped backoff instead of pure exponential) after live testing
 * during a bad patch showed 6 consecutive 502s before a success — the original 4-attempt budget
 * wasn't enough to ride out real outages, which matched the actor's 30-day failure rate climbing
 * to ~46%. A successful response can also take 10-20s on its own once crt.sh is under load, so
 * the retry budget needs real headroom, not just more attempts fired quickly.
 *
 * Also added a per-attempt timeout: a follow-up test run hung indefinitely with no response at
 * all (not a 502, not a slow success — just never resolved), which plain fetch() has no
 * protection against. Without a timeout, one hung connection silently defeats the whole retry
 * loop by never reaching the point where it would retry.
 */
async function fetchWithRetry(url) {
    let lastError;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
        let res;
        try {
            res = await fetch(url, { headers: { 'User-Agent': UA }, signal: controller.signal });
        } catch (err) {
            lastError = err.name === 'AbortError'
                ? new Error(`crt.sh request timed out after ${REQUEST_TIMEOUT_MS}ms`)
                : err;
            if (attempt < MAX_ATTEMPTS) {
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
        if (attempt < MAX_ATTEMPTS) {
            await sleep(Math.min(1000 * 2 ** (attempt - 1), MAX_BACKOFF_MS));
        }
    }
    throw new Error(`crt.sh unavailable after ${MAX_ATTEMPTS} attempts: ${lastError.message}`);
}

export async function fetchCertificates({ domain, startDate, maxResults }) {
    const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json&exclude=expired`;
    const res = await fetchWithRetry(url);
    const entries = await res.json();

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
    return [...bySerial.values()]
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
        }));
}
