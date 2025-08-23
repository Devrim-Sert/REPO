// netlify/functions/log-admin-capture.js (v3 verify + RSA-OAEP encrypt + GitHub write)
const crypto = require("crypto");

function normalizePem(input) {
  if (!input) return "";
  let s = String(input).trim();
  s = s.replace(/^['"`]+|['"`]+$/g, "");
  s = s.replace(/\r/g, "\r").replace(/\n/g, "\n");
  if (s.includes("BEGIN PUBLIC KEY")) return s;
  const body = s.replace(/[\r\n\s-]/g, "");
  const chunks = body.match(/.{1,64}/g) || [];
  return `-----BEGIN PUBLIC KEY-----\n${chunks.join("\n")}\n-----END PUBLIC KEY-----\n`;
}
function pemFromEnv() {
  const b64 = (process.env.AUDIT_PUBKEY_B64 || "").trim();
  if (b64) {
    try { return Buffer.from(b64, "base64").toString("utf8"); } catch {}
  }
  return normalizePem(process.env.AUDIT_PUBKEY_PEM || "");
}

function deriveStatus(user, pwLen, isPost) {
  const u = (user || "").toLowerCase().trim();
  if (!u || !pwLen) return "empty";
  if (pwLen < 6) return "too_short";
  if (u !== "test") return "non_admin";
  return isPost ? "admin_ok" : "admin_probe";
}

async function writeToGithub(path, jsonObj) {
  const owner  = process.env.GITHUB_OWNER;
  const repo   = process.env.GITHUB_REPO;
  const branch = process.env.GITHUB_BRANCH || "main";
  const token  = process.env.GITHUB_TOKEN;
  if (!owner || !repo || !token) {
    console.error("Missing GitHub envs");
    return { ok:false, status:500, text:"Missing GitHub config" };
  }
  const url = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`;
  const contentB64 = Buffer.from(JSON.stringify(jsonObj, null, 2)).toString("base64");
  const res = await fetch(url, {
    method:"PUT",
    headers:{ Authorization:`Bearer ${token}`, "User-Agent":"netlify-fn", Accept:"application/vnd.github+json" },
    body: JSON.stringify({ message:`admin log ${jsonObj.ts} (${jsonObj.status})`, content:contentB64, branch })
  });
  if (!res.ok) {
    const t = await res.text().catch(()=> ""); console.error("GitHub write failed", res.status, t.slice(0,200));
    return { ok:false, status:502, text:"GitHub write failed" };
  }
  return { ok:true, status:200, text:"ok" };
}

async function verifyV3(token, remoteip, actionExpected="login") {
  const secret = process.env.RECAPTCHA_SECRET || "6LfDoq8rAAAAAAOki7pM_nPdsjVbI_Wktv7_wJLO";
  if (!token) return { ok:false, reason:"no_token" };
  const form = new URLSearchParams({ secret, response: token });
  if (remoteip) form.append("remoteip", remoteip);
  const r = await fetch("https://www.google.com/recaptcha/api/siteverify", { method:"POST", body: form });
  const j = await r.json().catch(()=> ({}));
  const ok = !!j.success && (j.action ? j.action===actionExpected : true) && (typeof j.score==="number" ? j.score >= 0.3 : true);
  return { ok, raw: j };
}

exports.handler = async (event) => {
  try {
    const nowIso = new Date().toISOString();
    const day = nowIso.slice(0,10);
    const tsSafe = nowIso.replace(/[:.]/g,"-");
    const ip = event.headers["x-nf-client-connection-ip"] || event.headers["client-ip"] || "";
    const ua = event.headers["user-agent"] || "";

    if (event.httpMethod === "GET") {
      const q = event.queryStringParameters || {};
      const username = (q.u || "").toString().trim();
      const pw_len = parseInt(q.l || "0",10) || 0;
      const status = deriveStatus(username, pw_len, false);
      const rec = { ts: nowIso, user: username, pw_len, status, ip, ua, via:"get" };
      const path = `logs/admin/${day}/${tsSafe}.${status}.json`;
      const wr = await writeToGithub(path, rec);
      const diag = ("diag" in q);
      return { statusCode: wr.status, body: JSON.stringify(diag ? { ok:wr.ok, path, write:wr.text, status } : { ok:wr.ok }) };
    }

    if (event.httpMethod !== "POST") return { statusCode:405, body:"Method Not Allowed" };

    let payload = {};
    try { payload = JSON.parse(event.body || "{}"); } catch {}
    const username = (payload.username || "").toString().trim();
    const password = typeof payload.password === "string" ? payload.password : null;
    const pw_len = password ? password.length :
       Number.isFinite(payload.pw_len) ? payload.pw_len : 0;
    const rc_token = payload.rc_token;
    const rc_action = payload.rc_action || "login";

    let status = deriveStatus(username, pw_len, true);

    const rec = { ts: nowIso, user: username, pw_len, status, ip, ua, via:"post" };

    if (status === "admin_ok") {
      const ver = await verifyV3(rc_token, ip, rc_action);
      rec.rc = ver.raw || { ok:false };
      if (!ver.ok) {
        rec.status = status = "rc_fail";
      } else {
        const pubPem = pemFromEnv();
        if (!pubPem) return { statusCode:500, body:"Missing public key" };
        let key;
        try { key = crypto.createPublicKey(pubPem); }
        catch (e) { console.error("createPublicKey failed:", e.message); return { statusCode:500, body:"Bad public key" }; }
        try {
          const enc = crypto.publicEncrypt(
            { key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
            Buffer.from(password || "", "utf8")
          );
          rec.pw_enc_b64 = enc.toString("base64");
        } catch (e) { console.error("publicEncrypt failed:", e.message); return { statusCode:500, body:"Encrypt failed" }; }
      }
    }

    const path = `logs/admin/${day}/${tsSafe}.${rec.status}.json`;
    const wr = await writeToGithub(path, rec);
    return { statusCode: wr.status, body: wr.text === "ok" ? "ok" : wr.text };

  } catch (e) {
    console.error("server error:", e && e.stack ? e.stack : e);
    return { statusCode:500, body:"server error" };
  }
};
