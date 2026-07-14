/**
 * ReconX backend
 * Free / no-key public data sources only:
 *  - RDAP (rdap.org)            -> domain WHOIS/registration data
 *  - ip-api.com                 -> IP geolocation / ISP info
 *  - Node's built-in dns module -> DNS records
 *  - Node's built-in tls module -> live SSL/TLS certificate inspection
 *  - urlscan.io public search   -> historical URL scan reputation (no key required for search)
 */

const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const dns = require("dns").promises;
const tls = require("tls");
const { URL } = require("url");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const TIMEOUT_MS = 9000;

function withTimeout(promise, ms = TIMEOUT_MS) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error("Request timed out")), ms)),
  ]);
}

function getClientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (xff) return xff.split(",")[0].trim();
  return req.socket.remoteAddress?.replace("::ffff:", "") || "";
}

function isValidIp(ip) {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const v4Match = ip.match(v4);
  if (v4Match) {
    return v4Match.slice(1).every((octet) => Number(octet) >= 0 && Number(octet) <= 255);
  }
  const v6 = /^[0-9a-fA-F:]+$/;
  return v6.test(ip) && ip.includes(":");
}

function isValidDomain(domain) {
  if (domain.length > 253) return false;
  const labels = domain.split(".");
  if (labels.length < 2) return false;
  return labels.every((label) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label));
}

async function safeJson(response) {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error("Upstream data source returned an unexpected response. Please try again shortly.");
  }
}

// ---------- MY IP ----------
app.get("/api/myip", async (req, res) => {
  try {
    let ip = getClientIp(req);
    if (ip === "127.0.0.1" || ip === "::1" || !ip) {
      // local/dev fallback so the demo still works behind localhost
      const r = await withTimeout(fetch("https://api.ipify.org?format=json"));
      const j = await safeJson(r);
      ip = j.ip;
    }
    const geoRes = await withTimeout(
      fetch(
        `http://ip-api.com/json/${ip}?fields=status,message,continent,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query,reverse`
      )
    );
    const geo = await safeJson(geoRes);
    res.json({ ok: true, ip, geo });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ---------- IP LOOKUP ----------
app.get("/api/ip", async (req, res) => {
  const ip = (req.query.ip || "").trim();
  if (!ip || !isValidIp(ip)) {
    return res.status(400).json({ ok: false, error: "Provide a valid IPv4 or IPv6 address." });
  }
  try {
    const r = await withTimeout(
      fetch(
        `http://ip-api.com/json/${ip}?fields=status,message,continent,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query,reverse`
      )
    );
    const data = await safeJson(r);
    if (data.status === "fail") {
      return res.status(400).json({ ok: false, error: data.message || "Lookup failed." });
    }
    res.json({ ok: true, data });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ---------- DOMAIN / WHOIS (RDAP) ----------
app.get("/api/whois", async (req, res) => {
  const domain = (req.query.domain || "").trim().toLowerCase();
  if (!domain || !isValidDomain(domain)) {
    return res.status(400).json({ ok: false, error: "Provide a valid domain, e.g. example.com" });
  }
  try {
    const r = await withTimeout(fetch(`https://rdap.org/domain/${domain}`));
    if (!r.ok) {
      return res.status(404).json({ ok: false, error: `No RDAP record found (HTTP ${r.status}). The registry may not support RDAP.` });
    }
    const raw = await r.json();

    const events = {};
    (raw.events || []).forEach((e) => (events[e.eventAction] = e.eventDate));

    const nameservers = (raw.nameservers || []).map((n) => n.ldhName).filter(Boolean);

    let registrar = null;
    (raw.entities || []).forEach((e) => {
      if (e.roles?.includes("registrar")) {
        const vcard = e.vcardArray?.[1] || [];
        const fnEntry = vcard.find((v) => v[0] === "fn");
        registrar = fnEntry ? fnEntry[3] : e.handle || null;
      }
    });

    res.json({
      ok: true,
      data: {
        domain: raw.ldhName || domain,
        status: raw.status || [],
        registrar,
        nameservers,
        created: events.registration || null,
        updated: events.lastChanged || null,
        expires: events.expiration || null,
        raw,
      },
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ---------- DNS RECORDS ----------
app.get("/api/dns", async (req, res) => {
  const domain = (req.query.domain || "").trim().toLowerCase();
  if (!domain || !isValidDomain(domain)) {
    return res.status(400).json({ ok: false, error: "Provide a valid domain, e.g. example.com" });
  }

  const lookups = {
    A: () => dns.resolve4(domain),
    AAAA: () => dns.resolve6(domain),
    MX: () => dns.resolveMx(domain),
    NS: () => dns.resolveNs(domain),
    TXT: () => dns.resolveTxt(domain),
    CNAME: () => dns.resolveCname(domain),
    SOA: () => dns.resolveSoa(domain),
  };

  const results = {};
  await Promise.all(
    Object.entries(lookups).map(async ([type, fn]) => {
      try {
        results[type] = await withTimeout(fn(), 6000);
      } catch {
        results[type] = null;
      }
    })
  );

  res.json({ ok: true, data: results });
});

// ---------- URL SCANNER (headers, redirects, SSL, reputation) ----------
app.get("/api/url", async (req, res) => {
  let target = (req.query.url || "").trim();
  if (!target) return res.status(400).json({ ok: false, error: "Provide a URL." });
  if (!/^https?:\/\//i.test(target)) target = "https://" + target;

  let parsed;
  try {
    parsed = new URL(target);
  } catch {
    return res.status(400).json({ ok: false, error: "That URL doesn't look valid." });
  }

  const result = {
    finalUrl: null,
    statusCode: null,
    redirectChain: [],
    headers: {},
    securityHeaders: {},
    ssl: null,
    reputation: null,
  };

  try {
    let currentUrl = parsed.toString();
    let hops = 0;
    let response;
    while (hops < 8) {
      response = await withTimeout(
        fetch(currentUrl, { redirect: "manual", headers: { "User-Agent": "ReconX/1.0 (+scanner)" } }),
        6000
      );
      result.redirectChain.push({ url: currentUrl, status: response.status });
      if ([301, 302, 303, 307, 308].includes(response.status) && response.headers.get("location")) {
        currentUrl = new URL(response.headers.get("location"), currentUrl).toString();
        hops++;
      } else {
        break;
      }
    }
    result.finalUrl = currentUrl;
    result.statusCode = response.status;
    response.headers.forEach((v, k) => (result.headers[k] = v));

    const sec = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"];
    sec.forEach((h) => (result.securityHeaders[h] = result.headers[h] || null));
  } catch (err) {
    result.error = "Could not reach the site: " + err.message;
  }

  // SSL certificate + reputation: run in PARALLEL (was sequential — caused
  // slow scans to exceed serverless platform timeouts, e.g. Vercel's 10s cap)
  const finalParsed = new URL(result.finalUrl || parsed.toString());

  const sslPromise =
    finalParsed.protocol === "https:"
      ? withTimeout(
          new Promise((resolve, reject) => {
            const socket = tls.connect(
              { host: finalParsed.hostname, port: 443, servername: finalParsed.hostname, timeout: 5000 },
              () => {
                const cert = socket.getPeerCertificate();
                socket.end();
                if (!cert || Object.keys(cert).length === 0) return reject(new Error("No certificate returned"));
                resolve({
                  subject: cert.subject,
                  issuer: cert.issuer,
                  validFrom: cert.valid_from,
                  validTo: cert.valid_to,
                  protocol: socket.getProtocol ? socket.getProtocol() : null,
                });
              }
            );
            socket.on("error", reject);
            socket.on("timeout", () => {
              socket.destroy();
              reject(new Error("TLS handshake timed out"));
            });
          }),
          5000
        )
      : Promise.resolve(null);

  const reputationPromise = (async () => {
    const q = encodeURIComponent(`domain:${finalParsed.hostname}`);
    const r = await withTimeout(fetch(`https://urlscan.io/api/v1/search/?q=${q}&size=5`), 5000);
    if (!r.ok) throw new Error("reputation lookup unavailable");
    const j = await r.json();
    return {
      totalScans: j.total || 0,
      recent: (j.results || []).slice(0, 5).map((s) => ({
        date: s.task?.time,
        score: s.page?.status,
        malicious: s.verdicts?.overall?.malicious ?? null,
        screenshot: s.screenshot || null,
        reportUrl: s.result || null,
      })),
    };
  })();

  const [sslOutcome, reputationOutcome] = await Promise.allSettled([sslPromise, reputationPromise]);

  result.ssl = sslOutcome.status === "fulfilled" ? sslOutcome.value : { error: sslOutcome.reason?.message || "TLS check failed" };
  result.reputation = reputationOutcome.status === "fulfilled" ? reputationOutcome.value : { error: "reputation lookup unavailable" };

  res.json({ ok: true, data: result });
});

app.listen(PORT, () => {
  console.log(`ReconX running at http://localhost:${PORT}`);
});
