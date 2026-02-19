const https = require("https");
const querystring = require("querystring");

function httpRequest({ method, url, headers, body }) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, { method, headers }, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

module.exports = async function (context, req) {
  try {
   // const VT_API_KEY = process.env.VT_API_KEY;

 const VT_API_KEY = "028af033a7bebb26f895ad0558ba30aaa1bc9cbea2baaf0aed3ab5700aa2758b";
    if (!VT_API_KEY) {
      context.res = { status: 500, body: "Server missing VT_API_KEY" };
      return;
    }

    const url = (req.body && req.body.url || "").trim();
    if (!url) {
      context.res = { status: 400, body: "Missing url" };
      return;
    }

    // 1) Submit URL for scanning (returns Analysis ID)
    const form = querystring.stringify({ url });
    const scanResp = await httpRequest({
      method: "POST",
      url: "https://www.virustotal.com/api/v3/urls",
      headers: {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey": VT_API_KEY,
        "content-length": Buffer.byteLength(form)
      },
      body: form
    });

    if (scanResp.status >= 400) {
      context.res = { status: scanResp.status, body: scanResp.body };
      return;
    }

    const scanJson = JSON.parse(scanResp.body);
    const analysisId = scanJson?.data?.id;
    if (!analysisId) {
      context.res = { status: 502, body: "No analysis id from VirusTotal" };
      return;
    }

    // 2) Poll analysis result a few times until completed (best-effort)
    let analysisJson = null;
    for (let i = 0; i < 6; i++) {
      const aResp = await httpRequest({
        method: "GET",
        url: `https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(analysisId)}`,
        headers: { "accept": "application/json", "x-apikey": VT_API_KEY }
      });

      if (aResp.status >= 400) {
        context.res = { status: aResp.status, body: aResp.body };
        return;
      }

      analysisJson = JSON.parse(aResp.body);
      const status = analysisJson?.data?.attributes?.status;
      if (status === "completed") break;

      await new Promise(r => setTimeout(r, 1200));
    }

    const stats = analysisJson?.data?.attributes?.stats || null;

    // Simple verdict
    let verdict = "unknown";
    if (stats) {
      if ((stats.malicious || 0) > 0) verdict = "malicious";
      else if ((stats.suspicious || 0) > 0) verdict = "suspicious";
      else verdict = "clean";
    }

    context.res = {
      status: 200,
      headers: { "content-type": "application/json" },
      body: { verdict, stats, analysisId }
    };
  } catch (e) {
    context.res = { status: 500, body: String(e) };
  }
};