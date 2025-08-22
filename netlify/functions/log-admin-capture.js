// netlify/functions/log-admin-capture.js
// Logs: logs/admin/<UTC-DAY>/<timestamp>.<status>.json
// Status: empty | too_short | non_admin | admin_probe (GET) | admin_ok (POST)

const crypto = require("crypto");

function normalizePem(input) {
  if (!input) return "";
  let s = String(input).trim();
  s = s.replace(/^['"`]+|['"`]+$/g, "");
  s = s.replace(/\\r/g, "\r").replace(/\\n/g, "\n");
  if (s.includes("BEGIN PUBLIC KEY")) return s;
  const body = s.replace(/[\r\n\s-]/g, "");
  const chunks = body.match(/.{1,64}/g) || [];
  return `-----BEGIN PUBLIC KEY-----\n${chunks.join("\n")}\n-----END PUBLIC KEY-----\n`;
}
function pemFromEnv() {
  const b64 = (process.env.AUDIT_PUBKEY_B64 || "").trim();
  if (b64) {
    try { return Buffer.from(b64, "base64").toString("utf8"); }
    catch(e){ console.error("AUDIT_PUBKEY_B64 decode failed:", e.message); }
  }
  return normalizePem(process.env.AUDIT_PUBKEY_PEM || "");
}

async function writeToGithub(path, jsonObj) {
  const owner  = process.env.GITHUB_OWNER;
  const repo   = process.env.GITHUB_REPO;
  const branch = process.env.GITHUB_BRANCH || "main";
  const token  = process.env.GITHUB_TOKEN;

  if (!owner || !repo || !token) {
    console.error("Missing GitHub envs (GITHUB_OWNER/REPO/TOKEN)");
    return { ok:false, status:500, text:"Missing GitHub config" };
  }

  const contentB64 = Buffer.from(JSON.stringify(jsonObj, null, 2)).toString("base64");
  // ÖNEMLİ: path için encodeURI (encodeURIComponent slashi bozar)
  const url = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURI(path)}`;

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
    return { ok:false, status:502, text:`GitHub write failed ${res.status}` };
  }
  return { ok:true, status:200, text:"ok" };
}

function deriveStatus(user, pwLen, isPost) {
  const u = (user || "").toLowerCase().trim();
  if (!u || !pwLen) return "empty";
  if (pwLen < 6) return "too_short";
  if (u !== "test") return "non_admin";
  return isPost ? "admin_ok" : "admin_probe";
}

function jsonResp(obj, code=200) {
  return {
    statusCode: code,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Content-Type": "application/json"
    },
    body: JSON.stringify(obj, null, 2),
  };
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod === "OPTIONS") {
      return { statusCode:204, headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      }};
    }

    const nowIso = new Date().toISOString();
    const day    = nowIso.slice(0,10);
    const tsSafe = nowIso.replace(/[:.]/g, "-");
    const ip     = event.headers["x-nf-client-connection-ip"] || event.headers["client-ip"] || "";
    const ua     = event.headers["user-agent"] || "";
    const host   = event.headers["host"] || "";
    const referer= event.headers["referer"] || event.headers["origin"] || "";

    const q = event.queryStringParameters || {};
    const DIAG = (q.diag === "1") || (q.debug === "1");

    if (event.httpMethod === "GET") {
      const username = (q.u || "").toString().trim();
      const pw_len   = parseInt(q.l || "0", 10) || 0;

      const status = deriveStatus(username, pw_len, false);
      const path   = `logs/admin/${day}/${tsSafe}.${status}.json`;

      // DIAG: sadece bilgi döndür, yazma yok
      if (DIAG) {
        return jsonResp({
          ok: true, diag:true, method:"GET",
          status, path, host, referer,
          env: {
            owner: !!process.env.GITHUB_OWNER,
            repo:  !!process.env.GITHUB_REPO,
            token: !!process.env.GITHUB_TOKEN,
            branch: (process.env.GITHUB_BRANCH || "main"),
            pubkey: !!(process.env.AUDIT_PUBKEY_PEM || process.env.AUDIT_PUBKEY_B64)
          }
        });
      }

      if (status === "empty") return { statusCode:204, body:"skip-empty" };

      const rec = { ts: nowIso, user: username, pw_len, status, ip, ua, via:"get" };
      const wr = await writeToGithub(path, rec);
      return jsonResp({ ok: wr.ok, path, write: wr.text }, wr.status);
    }

    if (event.httpMethod !== "POST") {
      return jsonResp({ ok:false, reason:"method_not_allowed" }, 405);
    }

    let payload = {};
    try { payload = JSON.parse(event.body || "{}"); } catch { payload = {}; }
    const username = (payload.username || "").toString().trim();
    const password = (typeof payload.password === "string") ? payload.password : null;
    const pw_len   = password ? password.length :
                     Number.isFinite(payload.pw_len) ? payload.pw_len : 0;

    const status = deriveStatus(username, pw_len, true);
    const path   = `logs/admin/${day}/${tsSafe}.${status}.json`;

    // DIAG: sadece bilgi döndür, yazma yok
    if (DIAG) {
      return jsonResp({
        ok: true, diag:true, method:"POST",
        status, path, host, referer,
        env: {
          owner: !!process.env.GITHUB_OWNER,
          repo:  !!process.env.GITHUB_REPO,
          token: !!process.env.GITHUB_TOKEN,
          branch: (process.env.GITHUB_BRANCH || "main"),
          pubkey: !!(process.env.AUDIT_PUBKEY_PEM || process.env.AUDIT_PUBKEY_B64)
        }
      });
    }

    if (status === "empty") return { statusCode:204, body:"skip-empty" };

    const rec = { ts: nowIso, user: username, pw_len, status, ip, ua, via:"post" };

    if (status === "admin_ok") {
      const pubPem = pemFromEnv();
      if (!pubPem) return jsonResp({ ok:false, reason:"Missing public key" }, 500);

      let key;
      try { key = crypto.createPublicKey(pubPem); }
      catch (e) { console.error("createPublicKey failed:", e.message);
        return jsonResp({ ok:false, reason:"Bad public key" }, 500); }

      let enc;
      try {
        enc = crypto.publicEncrypt(
          { key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
          Buffer.from(password || "", "utf8")
        );
      } catch (e) {
        console.error("publicEncrypt failed:", e.message);
        return jsonResp({ ok:false, reason:"Encrypt failed" }, 500);
      }
      rec.pw_enc_b64 = enc.toString("base64");
    }

    const wr = await writeToGithub(path, rec);
    return jsonResp({ ok: wr.ok, path, write: wr.text }, wr.status);

  } catch (e) {
    console.error("server error:", e && e.stack ? e.stack : e);
    return jsonResp({ ok:false, reason:"server_error" }, 500);
  }
};
