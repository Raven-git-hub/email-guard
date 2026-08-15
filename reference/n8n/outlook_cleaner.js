const authResults = metadata['authentication-results'] || "";
const dkimResults = [...authResults.matchAll(/dkim=([a-zA-Z]+)/g)].map(m => m[1].toLowerCase());
const dkim = dkimResults.includes('pass') ? 'pass' : (dkimResults[0] || 'none');
const dmarc = authResults.match(/dmarc=([a-zA-Z]+)/)?.[1]?.toLowerCase() || "none";
const spf = authResults.match(/spf=([a-zA-Z]+)/)?.[1]?.toLowerCase() || "none";

const senderIP = metadata['x-sender-ip'] ||
                 (metadata['received'] || '').match(/\[([0-9.]+)\]/)?.[1] ||
                 "unknown";

const returnPath = metadata['return-path'] || "unknown";
const isForwarded = returnPath.includes('SRS') || !!metadata['resent-from'];
const hops = Array.isArray(metadata['received']) ? metadata['received'].length : 1;
const contentType = metadata['content-type'] || "unknown";
const headerCount = parseInt(metadata['x-incomingheadercount']) || Object.keys(metadata).length;

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
            sid_result: (metadata['x-sid-result'] || "unknown").toLowerCase()
        },
        path: {
            return_path: returnPath,
            is_forwarded: isForwarded,
            hop_count: hops
        },
        technical: {
            content_type: contentType,
            is_multipart: contentType.toLowerCase().includes('multipart'),
            encoding: metadata['content-transfer-encoding'] || "7bit",
            mime_version: metadata['mime-version'] || "1.0"
        },
        behavioural: {
            header_count: headerCount,
            mailer: metadata['user-agent'] || metadata['x-mailer'] || "hidden",
            traffic_type: metadata['x-ms-publictraffictype'] || "unknown"
        }
    },
    integrity: {
        dkim_verified: dkim === "pass",
        source_pipe: "OUTLOOK"
    }
};
