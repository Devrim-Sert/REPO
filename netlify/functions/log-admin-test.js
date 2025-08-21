exports.handler = async () => {
  try {
    const owner  = process.env.GITHUB_OWNER;
    const repo   = process.env.GITHUB_REPO;
    const branch = process.env.GITHUB_BRANCH || "main";
    const token  = process.env.GITHUB_TOKEN;
    if (!owner || !repo || !token) {
      return { statusCode: 500, body: "Missing GitHub envs" };
    }
    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    const path = `logs/admin/_selftest/${ts}.txt`;
    const contentB64 = Buffer.from("selftest ok\n").toString("base64");

    const res = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`,
      {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${token}`,
          "User-Agent": "netlify-fn",
          Accept: "application/vnd.github+json",
        },
        body: JSON.stringify({ message: `selftest ${ts}`, content: contentB64, branch }),
      }
    );

    if (!res.ok) return { statusCode: 502, body: `GitHub write failed: ${res.status}` };
    return { statusCode: 200, body: "selftest wrote a file" };
  } catch (e) {
    return { statusCode: 500, body: "err: " + e.message };
  }
};
