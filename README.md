# ReconX — OSINT Reconnaissance Console

A single Node.js/Express app (backend + frontend) for domain WHOIS, IP geolocation,
DNS records, and URL/SSL/security-header scanning — using only free, official public
data sources. No API keys required.

## Data sources (all free, no key needed)
- **Domain / WHOIS** — [RDAP](https://rdap.org) (the official successor to WHOIS, run by the regional internet registries)
- **IP lookup** — [ip-api.com](https://ip-api.com) (free tier, no key, 45 req/min)
- **DNS records** — Node's built-in `dns` module (live resolution, A/AAAA/MX/NS/TXT/CNAME/SOA)
- **URL scanner** — live HTTP headers, redirect chain and TLS certificate inspection (built-in `tls`/`fetch`), plus historical reputation via [urlscan.io](https://urlscan.io)'s public search API

## Run it

```bash
npm install
npm start
```

Then open **http://localhost:3000**.

## Project structure
```
reconx/
├── server.js          # Express API (whois, ip, dns, url, myip)
├── package.json
└── public/
    ├── index.html      # header/logo, tool tabs, search, footer
    ├── style.css       # dark "control room" theme, mobile-first
    └── script.js       # tab switching + fetch + result rendering
```

## Notes
- Deploy behind HTTPS in production (e.g. Render, Railway, Fly.io, a VPS + Nginx/Caddy).
- ip-api.com's free tier is HTTP-only and rate-limited to 45 requests/minute per IP — for heavier use, swap in a keyed provider (ipinfo.io, ipgeolocation.io) by editing the fetch URL in `server.js`.
- Only use this against domains, IPs and URLs you're authorized to inspect.
