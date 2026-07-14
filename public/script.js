document.getElementById("year").textContent = new Date().getFullYear();

const tabs = document.querySelectorAll(".tab");
const form = document.getElementById("searchForm");
const input = document.getElementById("searchInput");
const runBtn = document.getElementById("runBtn");
const output = document.getElementById("output");
const emptyState = document.getElementById("emptyState");
const myIpBtn = document.getElementById("myIpBtn");

const placeholders = {
  domain: "example.com",
  ip: "8.8.8.8",
  dns: "example.com",
  url: "https://example.com",
};

let activeTool = "domain";

tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    tabs.forEach((t) => { t.classList.remove("active"); t.setAttribute("aria-selected", "false"); });
    tab.classList.add("active");
    tab.setAttribute("aria-selected", "true");
    activeTool = tab.dataset.tool;
    input.placeholder = placeholders[activeTool];
    input.focus();
  });
});

document.querySelectorAll(".chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    if (chip.dataset.tool) {
      const tab = document.querySelector(`.tab[data-tool="${chip.dataset.tool}"]`);
      if (tab) tab.click();
    }
    input.value = chip.dataset.fill;
    form.requestSubmit();
  });
});

myIpBtn.addEventListener("click", async () => {
  document.querySelector('.tab[data-tool="ip"]').click();
  await runMyIp();
});

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const value = input.value.trim();
  if (!value) { input.focus(); return; }
  await runScan(activeTool, value);
});

function setLoading(isLoading) {
  runBtn.disabled = isLoading;
  runBtn.classList.toggle("loading", isLoading);
}

function showSkeleton() {
  emptyState.style.display = "none";
  output.innerHTML = `
    <div class="skeleton-card">
      <div class="skel-line" style="width:40%"></div>
      <div class="skel-line" style="width:70%"></div>
      <div class="skel-line" style="width:55%"></div>
      <div class="skel-line" style="width:30%"></div>
    </div>`;
}

function showError(msg) {
  output.innerHTML = `<div class="error-card">⚠ ${escapeHtml(msg)}</div>`;
}

function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function fetchJson(url) {
  const r = await fetch(url);
  const j = await r.json();
  if (!r.ok || j.ok === false) throw new Error(j.error || "Request failed.");
  return j;
}

async function runScan(tool, value) {
  setLoading(true);
  showSkeleton();
  try {
    if (tool === "domain") {
      const cleaned = value.replace(/^https?:\/\//i, "").split("/")[0];
      const j = await fetchJson(`/api/whois?domain=${encodeURIComponent(cleaned)}`);
      renderDomain(cleaned, j.data);
    } else if (tool === "ip") {
      const j = await fetchJson(`/api/ip?ip=${encodeURIComponent(value)}`);
      renderIp(j.data);
    } else if (tool === "dns") {
      const cleaned = value.replace(/^https?:\/\//i, "").split("/")[0];
      const j = await fetchJson(`/api/dns?domain=${encodeURIComponent(cleaned)}`);
      renderDns(cleaned, j.data);
    } else if (tool === "url") {
      const j = await fetchJson(`/api/url?url=${encodeURIComponent(value)}`);
      renderUrl(value, j.data);
    }
  } catch (err) {
    showError(err.message);
  } finally {
    setLoading(false);
  }
}

async function runMyIp() {
  setLoading(true);
  showSkeleton();
  try {
    const j = await fetchJson("/api/myip");
    input.value = j.ip;
    renderIp(j.geo);
  } catch (err) {
    showError(err.message);
  } finally {
    setLoading(false);
  }
}

function card(title, target, badgeHtml, bodyHtml) {
  return `
    <div class="card">
      <div class="card-head">
        <h3 class="card-title"><span class="dot"></span>${title}</h3>
        ${badgeHtml || ""}
      </div>
      ${target ? `<div class="card-target" style="margin-bottom:14px;">${escapeHtml(target)}</div>` : ""}
      ${bodyHtml}
    </div>`;
}

function kv(label, value) {
  return `<div class="kv"><div class="k">${escapeHtml(label)}</div><div class="v">${value ?? "<span class=\"empty-note\">not disclosed</span>"}</div></div>`;
}

/* ---------------- Domain / WHOIS ---------------- */
function renderDomain(domain, d) {
  const statusBadge = d.status?.length
    ? `<span class="badge ok">${escapeHtml(d.status[0])}</span>`
    : `<span class="badge neutral">status unknown</span>`;

  const body = `
    <div class="kv-grid">
      ${kv("Registrar", d.registrar ? escapeHtml(d.registrar) : null)}
      ${kv("Registered", d.created ? formatDate(d.created) : null)}
      ${kv("Last updated", d.updated ? formatDate(d.updated) : null)}
      ${kv("Expires", d.expires ? formatDate(d.expires) : null)}
    </div>
    <div class="section-label">Nameservers</div>
    <div class="record-list">
      ${
        d.nameservers?.length
          ? d.nameservers.map((ns) => `<div class="record-row"><span class="rtype">NS</span><span class="rval">${escapeHtml(ns)}</span></div>`).join("")
          : `<div class="empty-note">No nameservers returned by the registry.</div>`
      }
    </div>
    ${d.status?.length > 1 ? `
    <div class="section-label">All status codes</div>
    <div class="record-list">
      ${d.status.map((s) => `<div class="record-row"><span class="rtype">EPP</span><span class="rval">${escapeHtml(s)}</span></div>`).join("")}
    </div>` : ""}
  `;
  output.innerHTML = card(`Domain — ${escapeHtml(d.domain || domain)}`, null, statusBadge, body);
}

/* ---------------- IP ---------------- */
function renderIp(d) {
  const riskBits = [];
  if (d.proxy) riskBits.push(`<span class="badge warn">proxy/VPN</span>`);
  if (d.hosting) riskBits.push(`<span class="badge neutral">datacenter/hosting</span>`);
  if (d.mobile) riskBits.push(`<span class="badge neutral">mobile carrier</span>`);
  const badge = riskBits.length ? riskBits.join(" ") : `<span class="badge ok">residential-like</span>`;

  const body = `
    <div class="kv-grid">
      ${kv("Location", [d.city, d.regionName, d.country].filter(Boolean).map(escapeHtml).join(", ") || null)}
      ${kv("Timezone", d.timezone ? escapeHtml(d.timezone) : null)}
      ${kv("ISP", d.isp ? escapeHtml(d.isp) : null)}
      ${kv("Organization", d.org ? escapeHtml(d.org) : null)}
      ${kv("ASN", d.as ? escapeHtml(d.as) : null)}
      ${kv("Coordinates", d.lat ? `${d.lat}, ${d.lon}` : null)}
    </div>
  `;
  output.innerHTML = card(`IP — ${escapeHtml(d.query || "")}`, null, badge, body);
}

/* ---------------- DNS ---------------- */
function renderDns(domain, d) {
  const rows = [];
  const push = (type, arr, fmt) => {
    if (!arr) return;
    (Array.isArray(arr) ? arr : [arr]).forEach((item) => {
      rows.push(`<div class="record-row"><span class="rtype">${type}</span><span class="rval">${escapeHtml(fmt ? fmt(item) : item)}</span></div>`);
    });
  };
  push("A", d.A);
  push("AAAA", d.AAAA);
  push("CNAME", d.CNAME);
  push("MX", d.MX, (m) => `${m.exchange} (priority ${m.priority})`);
  push("NS", d.NS);
  push("TXT", d.TXT, (t) => (Array.isArray(t) ? t.join("") : t));
  if (d.SOA) rows.push(`<div class="record-row"><span class="rtype">SOA</span><span class="rval">primary ${escapeHtml(d.SOA.nsname)}, serial ${d.SOA.serial}</span></div>`);

  const count = rows.length;
  const badge = count ? `<span class="badge ok">${count} records</span>` : `<span class="badge bad">no records found</span>`;

  output.innerHTML = card(`DNS — ${escapeHtml(domain)}`, null, badge, `
    <div class="record-list">${rows.join("") || `<div class="empty-note">No resolvable DNS records for this name.</div>`}</div>
  `);
}

/* ---------------- URL ---------------- */
function renderUrl(input_, d) {
  if (d.error && !d.statusCode) {
    return showError(d.error);
  }

  const statusOk = d.statusCode >= 200 && d.statusCode < 400;
  const statusBadge = `<span class="badge ${statusOk ? "ok" : "bad"}">HTTP ${d.statusCode ?? "?"}</span>`;

  const chain = d.redirectChain?.length
    ? d.redirectChain.map((h, i) => `
      <div class="redirect-hop">
        <span class="status">${h.status}</span>
        <span class="url">${escapeHtml(h.url)}</span>
      </div>`).join("")
    : "";

  let sslBlock = "";
  if (d.ssl && !d.ssl.error) {
    const validTo = new Date(d.ssl.validTo);
    const daysLeft = Math.round((validTo - Date.now()) / 86400000);
    const sslBadge = daysLeft > 14 ? "ok" : daysLeft > 0 ? "warn" : "bad";
    sslBlock = `
      <div class="section-label">TLS certificate <span class="badge ${sslBadge}" style="margin-left:6px;">${daysLeft > 0 ? `expires in ${daysLeft}d` : "expired"}</span></div>
      <div class="kv-grid">
        ${kv("Issued to", d.ssl.subject?.CN ? escapeHtml(d.ssl.subject.CN) : null)}
        ${kv("Issuer", d.ssl.issuer?.O ? escapeHtml(d.ssl.issuer.O) : (d.ssl.issuer?.CN ? escapeHtml(d.ssl.issuer.CN) : null))}
        ${kv("Valid from", formatDate(d.ssl.validFrom))}
        ${kv("Valid to", formatDate(d.ssl.validTo))}
        ${kv("Protocol", d.ssl.protocol ? escapeHtml(d.ssl.protocol) : null)}
      </div>`;
  } else if (d.ssl?.error) {
    sslBlock = `<div class="section-label">TLS certificate</div><div class="empty-note">Could not inspect certificate: ${escapeHtml(d.ssl.error)}</div>`;
  }

  const secRows = Object.entries(d.securityHeaders || {}).map(([k, v]) => `
    <tr><td>${escapeHtml(k)}</td><td>${v ? escapeHtml(v) : `<span class="badge bad" style="font-size:0.65rem;">missing</span>`}</td></tr>
  `).join("");

  let repBlock = "";
  if (d.reputation && !d.reputation.error) {
    const mal = d.reputation.recent?.some((r) => r.malicious);
    repBlock = `
      <div class="section-label">Reputation history <span class="badge ${mal ? "bad" : "ok"}" style="margin-left:6px;">${d.reputation.totalScans} public scans</span></div>
      ${d.reputation.totalScans ? `<div class="empty-note" style="margin-bottom:8px;">Historical community scans via urlscan.io — most recent first.</div>` : `<div class="empty-note">No public scan history found for this host.</div>`}
    `;
  }

  const body = `
    ${chain ? `<div class="section-label">Redirect chain</div><div class="redirect-chain">${chain}</div>` : ""}
    <div class="section-label">Response headers</div>
    <table class="header-table"><tbody>
      <tr><td>server</td><td>${escapeHtml(d.headers?.server || "not disclosed")}</td></tr>
      <tr><td>content-type</td><td>${escapeHtml(d.headers?.["content-type"] || "—")}</td></tr>
    </tbody></table>
    <div class="section-label">Security headers</div>
    <table class="header-table"><tbody>${secRows}</tbody></table>
    ${sslBlock}
    ${repBlock}
  `;

  output.innerHTML = card("URL scan", d.finalUrl || input_, statusBadge, body);
}

function formatDate(iso) {
  try {
    const dt = new Date(iso);
    if (isNaN(dt)) return escapeHtml(iso);
    return dt.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  } catch {
    return escapeHtml(iso);
  }
}
