// 1. DATA SOURCES
const report = context.report;
const header = report.header;

// Identify the most recent scan results block
const blockNames = Object.keys(report.scanResults);
const activeBlockName = blockNames[blockNames.length - 1];
const activeBlock = report.scanResults[activeBlockName];

let forensicLog = [];
let confidenceScore = 0;
let hasAnyFail = false;
let hasCriticalFail = false;

// 2. THE JURY DELIBERATION

// Score Title & Text
if (activeBlock.core?.title === 'pass' || activeBlock.core?.title === 'pass_service') {
    confidenceScore += 1;
}
if (activeBlock.core?.clean_text === 'pass' || activeBlock.core?.clean_text === 'pass_service') {
    confidenceScore += 1;
}

// Score Auth Alignment
if (activeBlock.metadata?.['authenticity-auth_string'] === 'pass' || activeBlock.metadata?.['authenticity-auth_string'] === 'pass_service') {
    confidenceScore += 2;
} else if (activeBlock.metadata?.['authenticity-auth_string'] === 'fail_critical') {
    hasCriticalFail = true;
}

// Mailer & Complexity Logic
const isComplex = activeBlock.metadata?.['behavioural-header_count'] === 'pass' || activeBlock.metadata?.['behavioural-header_count'] === 'pass_service';
const isHiddenMailer = activeBlock.metadata?.['behavioural-mailer'] === 'fail_spam' || activeBlock.metadata?.['behavioural-mailer'] === 'fail';

if (isComplex && isHiddenMailer) {
    confidenceScore += 1;
    // THE OVERWRITE: This forces the report to show 'pass'
    activeBlock.metadata['behavioural-mailer'] = 'pass';
    forensicLog.push("OVERTURN: Mailer fail ignored due to high header complexity.");
} else if (isHiddenMailer) {
    hasAnyFail = true;
}

// Check Links
if (activeBlock.content?.links === 'fail' || activeBlock.content?.links === 'fail_critical') {
    hasCriticalFail = true;
}

// 3. THE FINAL SCRUB (Convert all fancy tags to simple pass/fail)
const categories = ['core', 'metadata', 'content', 'integrity'];
categories.forEach(cat => {
    if (activeBlock[cat]) {
        Object.keys(activeBlock[cat]).forEach(key => {
            if (typeof activeBlock[cat][key] === 'string') {
                if (activeBlock[cat][key].includes('pass')) activeBlock[cat][key] = 'pass';
                if (activeBlock[cat][key].includes('fail')) activeBlock[cat][key] = 'fail';
            }
        });
    }
});

// 4. THE TRIAGE VERDICT
let assessedLevel = 3;

if (hasCriticalFail) {
    assessedLevel = 2;
    header.scanComplete = false;
    forensicLog.push("VERDICT: Critical markers found. Upgrading to Level 2.");
}
else if (confidenceScore >= 4 && !hasAnyFail) {
    assessedLevel = 4;
    header.scanComplete = false;
    forensicLog.push("VERDICT: Perfect profile. Downgrading to Level 4.");
}
else {
    assessedLevel = 3;
    header.scanComplete = true;
    forensicLog.push("VERDICT: Standard profile confirmed. Loop complete.");
}

header.revisedLevel = assessedLevel;

activeBlock.assessment = {
    revise_level: header.scanComplete ? "complete" : "pivot",
    decision: assessedLevel,
    log: forensicLog.join(' | ') || "Level 3 assessment finished."
};

return {
    json: {
        report: report,
        pivotTriggered: !header.scanComplete
    }
};
