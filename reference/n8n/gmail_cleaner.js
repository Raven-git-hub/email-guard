const authResults = metadata['authentication-results'] || "";
const dkimResults = [...authResults.matchAll(/dkim=([a-zA-Z]+)/g)].map(m => m[1].toLowerCase());
const dkim = dkimResults.includes('pass') ? 'pass' : (dkimResults[0] || 'none');
const dmarc = authResults.match(/dmarc=([a-zA-Z]+)/)?.[1]?.toLowerCase() || "none";
const spf = authResults.match(/spf=([a-zA-Z]+)/)?.[1]?.toLowerCase() || "none";

const senderIP = metadata['x-sender-ip'] ||
                 (metadata['received'] || '').match(/\[([0-9.]+)\]/)?.[1] ||
                 "unknown";

const returnPath = metadata['return-path'] || "unknown";
const isForwarded = !!(metadata['x-forwarded-for'] || metadata['x-forwarded-to'] || metadata['resent-from']);
const hops = Array.isArray(metadata['received']) ? metadata['received'].length : 1;
const contentType = metadata['content-type'] || "unknown";
const headerCount = Object.keys(metadata).length;

return {
    metadata: {
        authenticity: {
            dmarc: dmarc,
            dkim: dkim,
            spf: spf,
            auth_string: authResults
        },
        origin: {
            ip: senderIP,
            sid_result: "unknown"
        },
        path: {
            return_path: returnPath,
            is_forwarded: isForwarded,
            hop_count: hops
        },
        technical: {
            content_type: contentType,
            is_multipart: contentType.toLowerCase().includes('multipart'),
            encoding: metadata['content-transfer-encoding'] || "quoted-printable",
            mime_version: metadata['mime-version'] || "1.0"
        },
        behavioural: {
            header_count: headerCount,
            mailer: metadata['x-mailer'] || "hidden",
            traffic_type: "Email"
        }
    },
    integrity: {
        dkim_verified: dkim === "pass",
        source_pipe: "GMAIL"
    }
};
