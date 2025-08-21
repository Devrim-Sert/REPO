// netlify/functions/log-admin-capture.js
// Logs: logs/admin/<UTC-DAY>/<timestamp>.<status>.json
// Status values: empty | too_short | non_admin | admin_probe (GET) | admin_ok (POST)

const crypto = require("crypto");

// --- Public key helpers ------------------------------------------------------
function normalizePem(input) {
  if (!input) return "";
  let s = String(input).trim();
  // Çevresel tırnak/backtick gelmişse kırp
  s = s.replace(/^['"`]+|['"`]+$/g, "");
  // \r ve \n kaçışlarını gerçek newline'a çevir
  s = s.replace(/\\r/g, "\r").replace(/\\n/g, "\n");
  if (s.includes("BEGIN PUBLIC KEY")) return s;

  // Sadece base64 gövde ise BEGIN/END ile sar
  const body = s.replace(/[\r\n\s-]/g, "");
  const chunks = body.match(/.{1,64}/g) || [];
  return `-----BEGIN PUBLIC KEY-----\n${chunks.join("\n")}\n-----END PUBLIC KEY-----\n`;
}

function pemFromEnv() {
  const b64 = (process.env.AUDIT_PUBKEY_B64 || "").trim();
  if (b64) {
    try {
      return Buffer.from(b64, "base64").toString("utf8");
    } catch (e) {
      console.error("AUDIT_PUBKEY_B64 decode failed:", e.message);
    }
  }
  return normalizePem(process.env.AUDIT_PUBKEY_PEM || "");
}

// --- GitHub write helper -----------------------------------------------------
async function writeToGithub(path, jsonObj) {
  const owner  = process.env.GITHUB_OWNER;
  const repo   = process.env.GITHUB_REPO;
  const branch = process.env.GITHUB_BRANCH || "main";
  const token  = process.env.GITHUB_TOKEN;

  if (!owner || !repo || !token) {
    console.error("Missing GitHub envs (GITHUB_OWNER/REPO/TOKEN)");
    return { ok: false, status: 500, text: "Missing GitHub config" };
  }

  const contentB64 = Buffer.from(JSON.stringify(jsonObj, null, 2)).toString("base64");
  const url = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`;

  const res = await fetch(url, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${token}`,
      "User-Agent": "netlify-fn",
      Accept: "application/vnd.github+json",
    },
    body: JSON.stringify({
      message: `admin log ${jsonObj.ts} (${jsonObj.status})`,
      content: contentB64,
      branch,
    }),
  });

  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    console.error("GitHub write failed", res.status, txt.slice(0, 200));
    return { ok: false, status: 502, text: "GitHub write failed" };
  }
  return { ok: true, status: 200, text: "ok" };
}

// --- Status logic ------------------------------------------------------------
function deriveStatus(user, pwLen, isPost) {
  const u = (user || "").toLowerCase().trim();
  if (!u || !pwLen) return "empty";
  if (pwLen < 6) return "too_short";
  if (u !== "test") return "non_admin";
  return isPost ? "admin_ok" : "admin_probe";
}

exports.handler = async (event) => {
  try {
    // Common request metadata
    const nowIso = new Date().toISOString();
    const day = nowIso.slice(0, 10); // UTC gün
    const tsSafe = nowIso.replace(/[:.]/g, "-");
    const ip = event.headers["x-nf-client-connection-ip"] || event.headers["client-ip"] || "";
    const ua = event.headers["user-agent"] || "";

    // --- 0) GET ping: parola yok, sadece durum kaydı (her zaman düşsün) ---
    if (event.httpMethod === "GET") {
      const q = event.queryStringParameters || {};
      const username = (q.u || "").toString().trim();
      const pw_len = parseInt(q.l || "0", 10) || 0;

      const status = deriveStatus(username, pw_len, /*isPost*/ false);
      const rec = {
        ts: nowIso,
        user: username,
        pw_len,
        status,        // empty | too_short | non_admin | admin_probe
        ip,
        ua,
        via: "get",
      };

      const path = `logs/admin/${day}/${tsSafe}.${status}.json`;
      const wr = await writeToGithub(path, rec);
      return { statusCode: wr.status, body: wr.text === "ok" ? "ok-get" : wr.text };
    }

    // --- 1) POST: admin_ok için şifreyi şifrele, diğerlerinde parola yok ---
    if (event.httpMethod !== "POST") {
      return { statusCode: 405, body: "Method Not Allowed" };
    }

    let payload = {};
    try { payload = JSON.parse(event.body || "{}"); }
    catch { payload = {}; }

    const username = (payload.username || "").toString().trim();
    const password = typeof payload.password === "string" ? payload.password : null;
    const pw_len = password ? password.length :
                   Number.isFinite(payload.pw_len) ? payload.pw_len : 0;

    // Eğer admin değilse, POST gelse dahi parola kaydetme
    let status = deriveStatus(username, pw_len, /*isPost*/ true);
    const rec = {
      ts: nowIso,
      user: username,
      pw_len,
      status: status === "admin_ok" ? "admin_ok" : status, // non_admin/too_short/empty da olabilir
      ip,
      ua,
      via: "post",
    };

    // Sadece admin_ok'te parolayı şifrele
    if (status === "admin_ok") {
      const pubPem = pemFromEnv();
      if (!pubPem) return { statusCode: 500, body: "Missing public key" };

      let key;
      try { key = crypto.createPublicKey(pubPem); }
      catch (e) {
        console.error("createPublicKey failed:", e.message);
        return { statusCode: 500, body: "Bad public key" };
      }

      let enc;
      try {
        enc = crypto.publicEncrypt(
          { key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
          Buffer.from(password || "", "utf8")
        );
      } catch (e) {
        console.error("publicEncrypt failed:", e.message);
        return { statusCode: 500, body: "Encrypt failed" };
      }

      rec.pw_enc_b64 = enc.toString("base64");
    }

    const path = `logs/admin/${day}/${tsSafe}.${rec.status}.json`;
    const wr = await writeToGithub(path, rec);
    return { statusCode: wr.status, body: wr.text === "ok" ? "ok" : wr.text };

  } catch (e) {
    console.error("server error:", e && e.stack ? e.stack : e);
    return { statusCode: 500, body: "server error" };
  }
};
