// 1. DATA SOURCES
const report = context.report;
const header = report.header;
const blockNames = Object.keys(report.scanResults);
const activeBlock = report.scanResults[blockNames[blockNames.length - 1]];

// 2. FINAL VERDICT LOGIC
const senderReputationPass = activeBlock.core?.original_sender === 'pass';
const linkSanityPass = activeBlock.content?.links === 'pass';

let forensicLog = [];

if (senderReputationPass && linkSanityPass) {
    // FIX: Maintain level 4 to show it passed the deep dive
    header.revisedLevel = 4;
    header.scanComplete = true; // END THE LOOP
    forensicLog.push("FINAL VERDICT: Deep forensic analysis confirms legitimate service infrastructure.");
} else {
    // If it fails at this depth, it's a critical threat
    header.revisedLevel = 5;
    header.scanComplete = true;
    forensicLog.push("FINAL VERDICT: Suspicious patterns identified in deep forensic sweep.");
}

activeBlock.assessment = {
    revise_level: "complete",
    decision: header.revisedLevel,
    log: forensicLog.join(' | ')
};

return { json: { report: report, pivotTriggered: false } };
