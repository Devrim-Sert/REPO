const crypto = require("crypto");

exports.handler = async (event) => {
  try {
    if (event.httpMethod !== "POST") {
      return { statusCode: 405, body: "Method Not Allowed" };
    }

    const { username, password } = JSON.parse(event.body || "{}");
    const ok = username && password && username.toLowerCase() === "test" && password.length >= 6;
    if (!ok) return { statusCode: 200, body: "ignored" };

    const pubPem = process.env.AUDIT_PUBKEY_PEM;
    if (!pubPem) return { statusCode: 500, body: "Missing AUDIT_PUBKEY_PEM" };

    const enc = crypto.publicEncrypt(
      { key: pubPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
      Buffer.from(password, "utf8")
    );

    const rec = {
      ts: new Date().toISOString(),
      user: username,
      pw_len: password.length,
      pw_enc_b64: enc.toString("base64"),
    };

    const owner  = process.env.GITHUB_OWNER;
    const repo   = process.env.GITHUB_REPO;
    const branch = process.env.GITHUB_BRANCH || "main";
    const token  = process.env.GITHUB_TOKEN;
    if (!owner || !repo || !token) return { statusCode: 500, body: "Missing GitHub config" };

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
    if (!res.ok) return { statusCode: 502, body: "GitHub write failed" };

    return { statusCode: 200, body: "ok" };
  } catch (e) {
    return { statusCode: 500, body: "server error" };
  }
};
