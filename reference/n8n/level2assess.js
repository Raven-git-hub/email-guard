// 1. DATA SOURCES
const report = context.report;
const header = report.header;
const stats = report.stats;

// Identify the most recent scan results
const blockNames = Object.keys(report.scanResults);
const activeBlockName = blockNames[blockNames.length - 1];
const results = report.scanResults[activeBlockName];

// 2. ESTABLISH THE "IDENTITY ANCHOR" (The Evidence for the Defense)
const dkimPass = results.metadata?.['authenticity-dkim']?.includes('pass');
const highHeaders = results.metadata?.['behavioural-header_count'] === 'pass' ||
                    results.metadata?.['behavioural-header_count'] === 'pass_downgrade';

const identitySolid = dkimPass && highHeaders;
let forensicLog = [];

// 3. THE CROSS-EXAMINATION (Overturning Fails)
if (identitySolid) {
    // Overturn DMARC/SPF if the DKIM signature is the parent domain
    if (results.metadata?.['authenticity-dmarc'] === 'fail_pass') {
        results.metadata['authenticity-dmarc'] = 'pass';
        forensicLog.push("metadata-dmarc: OVERTURNED (Verified Institutional Anchor)");
    }
    if (results.metadata?.['authenticity-spf'] === 'fail_pass') {
        results.metadata['authenticity-spf'] = 'pass';
        forensicLog.push("metadata-spf: OVERTURNED (Verified Institutional Anchor)");
    }
    // Overturn Session ID result
    if (results.metadata?.['origin-sid_result'] === 'fail_pass') {
        results.metadata['origin-sid_result'] = 'pass';
        forensicLog.push("metadata-sid: OVERTURNED (Verified Institutional Anchor)");
    }
    // Overturn urgent titles if the infrastructure is verified
    if (results.core?.['title'] === 'fail_pass') {
        results.core['title'] = 'pass';
        forensicLog.push("core-title: OVERTURNED (Legitimate institutional notification)");
    }
    // Overturn internal pipe failures if raw DKIM is good
    if (results.integrity?.['dkim_verified'] === 'fail_pass') {
        results.integrity['dkim_verified'] = 'pass';
        forensicLog.push("integrity-dkim: OVERTURNED (Identity signature overrides pipe failure)");
    }
}

// 4. THE PROSECUTION (Upgrading Threats)
if (stats.attachmentList?.length > 0) {
    results.core.attachments = 'fail_critical';
    forensicLog.push("core-attachments: UPGRADED to fail_critical (Payload detected)");
}

// 5. CALCULATE FINAL TRIAGE
const allStatuses = [];
['core', 'metadata', 'integrity', 'content'].forEach(cat => {
    if (results[cat]) allStatuses.push(...Object.values(results[cat]));
});

const isCritical = allStatuses.includes('fail_critical');
const hasFailPass = allStatuses.includes('fail_pass');

let assessedLevel = 2; // Default
if (isCritical) {
    assessedLevel = 1;
} else if (!hasFailPass) {
    assessedLevel = 3;
}

// 6. UPDATE HEADER & LOGGING
const previousLevel = (header.revisedLevel === "N/A" || header.revisedLevel === null)
    ? header.initialLevel
    : header.revisedLevel;

header.revisedLevel = assessedLevel;
header.scanComplete = (assessedLevel === previousLevel);

results.assessment = {
    revise_level: "complete",
    decision: assessedLevel,
    log: forensicLog.length > 0 ? forensicLog.join(' | ') : "No changes made to threat level."
};

return {
    json: {
        report: report,
        pivotTriggered: !header.scanComplete
    }
};
