// Netlify Forms -> submission-created tetikleyicisi
const crypto = require("crypto");

exports.handler = async (event) => {
  try {
    const body = JSON.parse(event.body || "{}");
    const data = body?.payload?.data || {};

    // Form alanlarını yakala (esnek isimler)
    const username =
      data.username || data.user || data.kullanici || data["kullanıcı adı"] || "";
    const password = data.password || data.sifre || data["şifre"] || "";

    // Yalnızca admin kontrolü: username=test ve şifre uzunluğu >= 6
    const ok =
      username && password && username.toLowerCase() === "test" && password.length >= 6;
    if (!ok) return { statusCode: 200, body: "ignored" };

    // Parolayı SENİN public key’inle şifrele (RSA-OAEP-SHA256)
    const pubPem = process.env.AUDIT_PUBKEY_PEM;
    if (!pubPem) return { statusCode: 500, body: "Missing AUDIT_PUBKEY_PEM" };

    const encBuf = crypto.publicEncrypt(
      { key: pubPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
      Buffer.from(password, "utf8")
    );

    // GitHub'a yazılacak kayıt (username açık, şifre şifreli)
    const rec = {
      ts: new Date().toISOString(),
      user: username,
      pw_len: password.length,                // opsiyonel
      pw_enc_b64: encBuf.toString("base64"),  // şifrelenmiş parola
      ip: body?.payload?.remote_ip || "",
      ua: body?.payload?.user_agent || "",
    };

    // GitHub bilgileri ENV’den
    const owner  = process.env.GITHUB_OWNER;
    const repo   = process.env.GITHUB_REPO;
    const branch = process.env.GITHUB_BRANCH || "main";
    const token  = process.env.GITHUB_TOKEN;
    if (!owner || !repo || !token) {
      return { statusCode: 500, body: "Missing GitHub config" };
    }

    // logs/admin/YYYY-MM-DD/<timestamp>.json
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
        body: JSON.stringify({
          message: `admin log ${rec.ts}`,
          content: contentB64,
          branch,
        }),
      }
    );

    if (!res.ok) {
      const txt = await res.text();
      console.error("GitHub error", res.status, txt);
      return { statusCode: 502, body: "GitHub write failed" };
    }

    return { statusCode: 200, body: "ok" };
  } catch (e) {
    console.error(e);
    return { statusCode: 500, body: "server error" };
  }
};
