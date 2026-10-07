import { Actor, log } from 'apify';
import { fetchCertificates } from './crtsh.js';

await Actor.init();

const input = (await Actor.getInput()) ?? {};
const { daysBack = 30, maxResults = 50 } = input;
// apify.com, not example.com: example.com went 59 days without a new certificate, so the daily
// health check's 30-day lookback could come back empty. apify.com's longest gap was 19.5 days.
const domain = input.domain?.trim() || 'apify.com';

/** Must match the event name configured in this Actor's pay-per-event pricing on Apify. */
const CERT_SEARCH_EVENT = 'cert-search';

const startDate = new Date(Date.now() - daysBack * 24 * 60 * 60 * 1000);

const { certificates, source } = await fetchCertificates({
    domain: domain.replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, ''),
    startDate,
    maxResults: Math.min(maxResults, 200),
});

for (const cert of certificates) {
    await Actor.pushData(cert);
}

await Actor.charge({ eventName: CERT_SEARCH_EVENT });

log.info(`Pushed ${certificates.length} certificate(s) from the ${source}`);

await Actor.exit();
