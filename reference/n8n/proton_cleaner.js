const item = items[0].json;
const metadata = item.metadata || {};
const html = item.textHtml || "";
const rawSubject = item.subject || "";

// --- 1. EXTRACT REFERENCE LISTS ---
const whitelist = item.whitelist || [];
const greylist = item.greylist || [];
const blacklist = item.blacklist || [];

// --- 2. SENDER IDENTIFICATION ---
const rawFrom = item.from || metadata['from'] || "";
let originalSender = "unknown";

const emailMatch = rawFrom.match(/<([^>]*)>/);
if (emailMatch) {
    originalSender = emailMatch[1].toLowerCase().trim();
} else {
    originalSender = rawFrom.replace(/[<>]/g, '').toLowerCase().trim() || "unknown";
}

// --- 3. FRIENDLY NAME LOGIC (Standardized) ---
let finalFriendlyName = "Unknown";
const senderDomain = originalSender.split('@')[1] || "";

if (originalSender !== "unknown") {
    const parts = originalSender.split('@');
    if (parts.length === 2) {
        finalFriendlyName = `proton-${parts[0]}`;
    }
}

// FIX: Added optional chaining (?.) and domain-based fallback matching
const blackEntry = blacklist.find(e => (e.email?.toLowerCase() === originalSender) || (e.domain?.toLowerCase() === senderDomain));
if (blackEntry) finalFriendlyName = blackEntry.friendly_name;

const greyEntry = greylist.find(e => (e.email?.toLowerCase() === originalSender) || (e.domain?.toLowerCase() === senderDomain));
if (greyEntry) finalFriendlyName = greyEntry.friendly_name;

const whiteEntry = whitelist.find(e => (e.email?.toLowerCase() === originalSender) || (e.domain?.toLowerCase() === senderDomain));
if (whiteEntry) finalFriendlyName = whiteEntry.friendly_name;

// --- 4. ATTACHMENT SCANNER ---
let attachmentList = [];

if (metadata['x-attached']) {
    attachmentList.push({
        filename: metadata['x-attached'],
        contentType: "image/png"
    });
}

if (item.binary) {
    Object.keys(item.binary).forEach(key => {
        attachmentList.push({
            filename: item.binary[key].fileName || item.binary[key].filename || key,
            contentType: item.binary[key].mimeType || "unknown"
        });
    });
}

attachmentList = attachmentList.filter((v, i, a) => a.findIndex(t => t.filename === v.filename) === i);

// --- 5. OBFUSCATION LOGIC (Behavioral Intent Only) ---
// VISUAL: Detects Homoglyphs, Math-fonts, and non-standard symbols in the subject
const visualFlag = (function() {
    const safeChars = /[\u0000-\u007f\u00A0-\u00FF\u4e00-\u9fa5\u3040-\u30ff\uff00-\uffef\u{1F300}-\u{1F9FF}\u{1F600}-\u{1F64F}\u{1F680}-\u{1F6FF}\u2600-\u26FF\u2700-\u27BF]/gu;
    const stripped = rawSubject.replace(safeChars, '');
    return stripped.length > 0;
})();

// TACTICAL: High-pressure urgency keywords in the subject
const tacticalFlag = /(deleted|action|detected|declined|suspended|urgent|verify|immediately)/i.test(rawSubject);

const obfuscationFlags = {
    visual: visualFlag,
    tactical: tacticalFlag
};

// --- 6. CLEAN TEXT & DE-FANG LINKS ---
const urlRegex = /https?:\/\/[^\s"'<>]+/g;
const rawLinks = html.match(urlRegex) || [];
const defangedLinks = [...new Set(rawLinks)].map(l => l.replace(/http/g, 'h_ttp').replace(/\./g, '[.]'));

const cleanText = html
    .replace(/<style([\s\S]*?)<\/style>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

// --- 7. METADATA PILLARS ---
const refactoredMetadata = {
    authenticity: {
        dkim: "internal-pass",
        auth_string: "internal-proton-encryption"
    },
    origin: {
        ip: "proton-internal",
        sid_result: "pass"
    },
    path: {
        return_path: metadata['return-path'] || "internal",
        is_forwarded: (item.subject || "").toLowerCase().includes("fw:"),
        hop_count: 1
    },
    technical: {
        content_type: metadata['content-type'] || "multipart/mixed",
        is_multipart: true,
        encoding: "end-to-end-encrypted",
        mime_version: metadata['mime-version'] || "1.0"
    },
    behavioural: {
        header_count: Object.keys(metadata).length,
        mailer: "ProtonMail-Web-Interface",
        traffic_type: "Internal-Encrypted"
    }
};

// --- 8. FINAL OUTPUT ---
return [{
    json: {
        messageID: metadata['message-id'] || item.messageID || "N/A",
        timestamp: metadata['x-pm-date'] || item.date || new Date().toISOString(),
        original_sender: originalSender,
        friendly_name: finalFriendlyName,
        whitelist_hit: !!whiteEntry,
        greylist_hit: !!greyEntry,
        blacklist_hit: !!blackEntry,
        obfuscation_flags: obfuscationFlags,
        title: (item.subject || "").replace(/Fw:\s*|FW:\s*|Fwd:\s*/gi, ""),
        clean_text: cleanText.substring(0, 2000),
        attachments: attachmentList,
        links: defangedLinks,
        metadata: refactoredMetadata,
        integrity: {
            dkim_verified: true,
            source_pipe: "ProtonMail"
        },
        content: {
            links: defangedLinks,
            attachments: attachmentList,
            text: cleanText.substring(0, 2000),
            timestamp: metadata['x-pm-date'] || item.date || new Date().toISOString()
        }
    }
}];
