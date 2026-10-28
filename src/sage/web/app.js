"use strict";

// Dashboard di SAGE: legge /api/status e disegna la pagina scelta (#/panoramica, #/nodi...).
// Solo lettura, nessuna risorsa da fuori. I testi passano tutti da textContent e i grafici
// sono SVG costruiti nodo per nodo (niente HTML dai dati, CSP senza stili inline).

const PAGES = ["panoramica", "nodi", "cve", "giri", "salute", "log", "storico"];
const LEVEL = { critical: "critico", serious: "grave", warning: "attenzione", ok: "a posto", info: "in corso", unknown: "sconosciuto" };
const SYMBOL = { critical: "✕", serious: "◆", warning: "▲", ok: "✓", info: "●", unknown: "?" };
const ACTION = { update: "aggiorna", remove: "rimuovi", mitigate: "mitiga", not_affected: "non affetto", skip: "ignorato" };
const WAVE = { idle: "in attesa", running: "in corso", done: "fatto", failed: "fallito" };
const PENDING = new Set(["update", "remove", "mitigate"]);
const SVG = "http://www.w3.org/2000/svg";

let data = null;
let page = "panoramica";
let timer = null;
let lastOk = 0; // Date.now() dell'ultima lettura riuscita
let lastBody = ""; // risposta precedente: se non cambia non si ridisegna

// ------------------------------------------------------------------ elementi

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  return fill(node, attrs, children);
}

function svg(tag, attrs, ...children) {
  return fill(document.createElementNS(SVG, tag), attrs, children);
}

function fill(node, attrs, children) {
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.setAttribute("class", value);
    else if (key === "tip") node.dataset.tip = value;
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function replace(id, ...children) {
  document.getElementById(id).replaceChildren(...children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false));
}

function badge(level, text) {
  return el("span", { class: "badge b-" + level }, text || LEVEL[level] || level);
}

function when(iso) {
  if (!iso) return "mai";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  const minutes = Math.round((date.getTime() - Date.now()) / 60000);
  const rel = new Intl.RelativeTimeFormat("it", { numeric: "auto" });
  let relative;
  if (Math.abs(minutes) < 60) relative = rel.format(minutes, "minute");
  else if (Math.abs(minutes) < 48 * 60) relative = rel.format(Math.round(minutes / 60), "hour");
  else relative = rel.format(Math.round(minutes / 1440), "day");
  const absolute = date.toLocaleString("it-IT", { weekday: "short", day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
  return `${absolute} (${relative})`;
}

function duration(from, to) {
  const ms = new Date(to) - new Date(from);
  if (!Number.isFinite(ms) || ms < 0) return "?";
  const minutes = Math.round(ms / 60000);
  return minutes < 60 ? `${minutes} min` : `${Math.floor(minutes / 60)} h ${minutes % 60} min`;
}

// ------------------------------------------------------------------ grafici

function figure(id, title, note, ...body) {
  replace(id, el("figcaption", {}, title, note ? el("small", {}, note) : null), body);
}

function legend(items) {
  return el("ul", { class: "legend" }, items.map((it) => el(
    "li", {}, el("span", { class: "swatch bg-" + it.level, "aria-hidden": "true" }),
    `${SYMBOL[it.level] || ""} ${it.label}`, el("b", {}, it.value),
  )));
}

// Ciambella: parti di un intero, con il totale al centro e la legenda con i numeri.
function donut(items, centerLabel) {
  const total = items.reduce((sum, it) => sum + it.value, 0);
  const size = 180, r = 70, width = 26, c = 2 * Math.PI * r;
  const root = svg("svg", { viewBox: `0 0 ${size} ${size}`, width: size, height: size, role: "img", "aria-label": items.map((it) => `${it.label} ${it.value}`).join(", ") });
  const group = svg("g", { transform: `rotate(-90 ${size / 2} ${size / 2})` });
  if (!total) group.append(svg("circle", { cx: size / 2, cy: size / 2, r, class: "f-empty", fill: "none", "stroke-width": width }));
  let offset = 0;
  for (const it of items) {
    if (!it.value) continue;
    const length = (it.value / total) * c;
    const gap = items.filter((x) => x.value).length > 1 ? 2 : 0; // 2px di stacco tra le fette
    group.append(svg("circle", {
      cx: size / 2, cy: size / 2, r, fill: "none", "stroke-width": width,
      class: "mark ring-" + it.level, "stroke-dasharray": `${Math.max(length - gap, 0.5)} ${c}`,
      "stroke-dashoffset": -offset, tip: `${it.label}: ${it.value} su ${total} (${Math.round((it.value / total) * 100)}%)`,
    }));
    offset += length;
  }
  root.append(group,
    svg("text", { x: size / 2, y: size / 2 + 4, "text-anchor": "middle", class: "donut-total" }, total),
    svg("text", { x: size / 2, y: size / 2 + 22, "text-anchor": "middle", class: "donut-label" }, centerLabel));
  return el("div", { class: "chart" }, root, legend(items));
}

// Barre orizzontali impilate: una riga per categoria (gruppo, nodo), segmenti per stato.
function stackedRows(rows, keys) {
  const max = Math.max(1, ...rows.map((r) => keys.reduce((s, k) => s + (r.values[k.level] || 0), 0)));
  const labelW = 110, barW = 520, rowH = 26, height = rows.length * rowH + 4;
  const root = svg("svg", { viewBox: `0 0 ${labelW + barW + 40} ${height}`, width: labelW + barW + 40, height, role: "img", "aria-label": "barre" });
  rows.forEach((row, i) => {
    const y = i * rowH + 4;
    root.append(svg("text", { x: labelW - 8, y: y + 13, "text-anchor": "end", class: "tick" }, row.label));
    let x = labelW, sum = 0;
    for (const k of keys) {
      const v = row.values[k.level] || 0;
      if (!v) continue;
      const w = (v / max) * barW;
      root.append(svg("rect", { x, y, width: Math.max(w - 2, 1), height: rowH - 10, rx: 3, class: "mark f-" + k.level, tip: `${row.label} · ${k.label}: ${v}` }));
      x += w;
      sum += v;
    }
    root.append(svg("text", { x: x + 6, y: y + 13, class: "tick" }, sum));
  });
  return el("div", { class: "chart" }, root, legend(keys.map((k) => ({ ...k, value: rows.reduce((s, r) => s + (r.values[k.level] || 0), 0) }))));
}

// Colonne impilate nel tempo (giri): una colonna per giro, dal più vecchio al più recente.
function stackedColumns(cols, keys) {
  const max = Math.max(1, ...cols.map((c) => keys.reduce((s, k) => s + (c.values[k.level] || 0), 0)));
  const left = 28, plotH = 160, colW = Math.min(28, Math.max(8, 640 / Math.max(cols.length, 1))), width = left + cols.length * colW + 10;
  const root = svg("svg", { viewBox: `0 0 ${width} ${plotH + 24}`, width, height: plotH + 24, role: "img", "aria-label": "esiti dei giri" });
  for (const tick of [0, Math.round(max / 2), max]) {
    const y = plotH - (tick / max) * plotH + 4;
    root.append(svg("line", { x1: left, x2: width, y1: y, y2: y, class: "gridline" }),
      svg("text", { x: left - 6, y: y + 4, "text-anchor": "end", class: "tick" }, tick));
  }
  cols.forEach((col, i) => {
    let y = plotH + 4;
    const x = left + i * colW + 1;
    for (const k of keys) {
      const v = col.values[k.level] || 0;
      if (!v) continue;
      const h = (v / max) * plotH;
      root.append(svg("rect", { x, y: y - h, width: colW - 3, height: Math.max(h - 2, 1), rx: 2, class: "mark f-" + k.level, tip: `giro ${col.label} · ${k.label}: ${v}` }));
      y -= h;
    }
    if (cols.length <= 30 || i % 5 === 0) root.append(svg("text", { x: x + (colW - 3) / 2, y: plotH + 20, "text-anchor": "middle", class: "tick" }, col.label));
  });
  return el("div", { class: "chart" }, root, legend(keys.map((k) => ({ ...k, value: cols.reduce((s, c) => s + (c.values[k.level] || 0), 0) }))));
}

// Tooltip unico per tutti i grafici: segue il mouse sui segni con data-tip.
function setupTooltip() {
  const tip = document.getElementById("tooltip");
  document.addEventListener("pointermove", (ev) => {
    const mark = ev.target.closest && ev.target.closest("[data-tip]");
    if (!mark) { tip.hidden = true; return; }
    tip.textContent = mark.dataset.tip;
    tip.hidden = false;
    const x = Math.min(ev.clientX + 14, window.innerWidth - tip.offsetWidth - 8);
    tip.style.left = `${x}px`;
    tip.style.top = `${ev.clientY + 14}px`;
  });
}

// ------------------------------------------------------------------ stato dei nodi

// Stato del nodo per i grafici: cosa ne è stato in questo giro e se ha problemi.
function nodeBucket(row, quarantined) {
  if (quarantined.has(row.name)) return "serious";
  if (row.wave.status === "running") return "info";
  if (row.level === "critical") return "critical";
  if (row.plan.advisories || row.plan.remove.length || row.plan.mitigate.length || row.plan.reboot) return "warning";
  if (row.level === "unknown") return "unknown";
  return "ok";
}
const NODE_KEYS = [
  { level: "ok", label: "a posto" },
  { level: "info", label: "in aggiornamento" },
  { level: "warning", label: "da aggiornare" },
  { level: "serious", label: "in quarantena" },
  { level: "critical", label: "critici" },
  { level: "unknown", label: "senza dati" },
];

function waveBucket(row) {
  if (row.wave.status === "running") return "info";
  const outcome = row.wave.outcome || "";
  if (row.wave.status === "failed" || outcome.startsWith("fallit")) return "critical";
  if (outcome.startsWith("fatto") || outcome.startsWith("niente")) return "ok";
  if (outcome.startsWith("saltato")) return "warning";
  return "unknown";
}
const WAVE_KEYS = [
  { level: "ok", label: "fatti" },
  { level: "info", label: "in corso" },
  { level: "unknown", label: "da fare" },
  { level: "warning", label: "saltati" },
  { level: "critical", label: "falliti" },
];

// ------------------------------------------------------------------ pagine

function renderMeta(d) {
  const q = d.controller.quarantined.length;
  replace(
    "meta",
    d.dry_run ? badge("info", "SIMULAZIONE") : badge("warning", "VIVO: modifica i nodi"),
    q ? badge("serious", `QUARANTENA ${q}`) : null,
    el("span", {}, "controllore ", el("b", {}, d.controller.text)),
    d.controller.next_cycle ? el("span", {}, "prossimo giro ", el("b", {}, when(d.controller.next_cycle))) : null,
  );
}

function tile(label, value, note, progress) {
  const bar = progress === undefined ? null : el("div", { class: "bar-track" }, el("div", { class: "bar-fill" }));
  if (bar) bar.firstChild.style.width = `${Math.round(progress * 100)}%`; // CSSOM: la CSP vieta style inline
  return el("div", { class: "tile" }, el("div", { class: "label" }, label), el("div", { class: "value" }, value), note ? el("div", { class: "note" }, note) : null, bar);
}

function renderOverview(d) {
  const alarms = d.alarms.length ? d.alarms : [{ level: "ok", text: "nessun allarme: tutto sotto controllo" }];
  replace("alarms", alarms.map((a) => el("li", { class: a.level }, badge(a.level), el("span", {}, a.text))));

  const t = d.totals;
  const quarantined = new Set(d.controller.quarantined.map((q) => q.node));
  replace(
    "tiles",
    tile("Giro " + (d.controller.cycle || "-"), `${d.controller.done} / ${d.controller.queue}`, "nodi già passati in questo giro", d.controller.queue ? d.controller.done / d.controller.queue : 0),
    tile("Nodi a posto", `${t.nodes_clean} / ${t.nodes}`, `${t.advisories} advisory da applicare`, t.nodes ? t.nodes_clean / t.nodes : 0),
    tile("CVE gravi da sistemare", t.urgent, t.urgent ? `scadenza ${when(t.next_deadline)}` : `${t.kev} CVE sfruttate (KEV) aperte`),
    tile("In quarantena", quarantined.size, quarantined.size ? "si ritentano da soli" : "nessun nodo"),
  );

  const nodeCounts = Object.fromEntries(NODE_KEYS.map((k) => [k.level, 0]));
  for (const row of d.nodes) nodeCounts[nodeBucket(row, quarantined)] += 1;
  figure("chart-nodes", "Stato dei nodi", "cosa resta da fare su ogni nodo",
    donut(NODE_KEYS.map((k) => ({ ...k, value: nodeCounts[k.level] })), "nodi"));

  const open = d.cves.filter((c) => c.where.some((w) => PENDING.has(w.action)));
  const cveKeys = [
    { level: "critical", label: "sfruttate (KEV)", value: open.filter((c) => c.kev).length },
    { level: "serious", label: "priorità act", value: open.filter((c) => !c.kev && c.priority === "act").length },
    { level: "warning", label: "priorità attend", value: open.filter((c) => !c.kev && c.priority === "attend").length },
    { level: "unknown", label: "da seguire", value: open.filter((c) => !c.kev && !["act", "attend"].includes(c.priority)).length },
  ];
  figure("chart-cves", "CVE da sistemare", "per urgenza (SSVC, KEV)", donut(cveKeys, "CVE aperte"));

  const groups = d.groups.length ? d.groups.map((g) => g.name) : [...new Set(d.nodes.map((n) => n.group))];
  const rows = groups.map((name) => {
    const values = {};
    for (const row of d.nodes.filter((n) => n.group === name)) values[waveBucket(row)] = (values[waveBucket(row)] || 0) + 1;
    return { label: name || "senza gruppo", values };
  });
  figure("chart-groups", "Giro in corso per gruppo", "nell'ordine del giro, master per ultimi", stackedRows(rows, WAVE_KEYS));
}

function planText(plan) {
  const parts = [];
  if (plan.advisories) parts.push(`${plan.advisories} advisory (${plan.packages} pacchetti)`);
  if (plan.remove.length) parts.push("rimuovere " + plan.remove.join(", "));
  if (plan.mitigate.length) parts.push("bloccare " + plan.mitigate.join(", "));
  if (plan.reboot) parts.push("riavvio in sospeso");
  return parts.join("; ") || "niente da fare";
}

function renderNode(row, quarantine) {
  const failed = (row.wave.outcome || "").startsWith("fallit") ? `remediation ${row.wave.detail || row.wave.outcome}` : null;
  const kv = [
    ["Piano", planText(row.plan)],
    row.plan.deferred.length ? ["Rimandati", `${row.plan.deferred.length}: ${[...new Set(row.plan.deferred.map((x) => x.reason))].join("; ")}`] : null,
    row.deadline ? ["Scadenza CVE gravi", `${when(row.deadline)}: ${row.urgent.join(", ")}`] : null,
    ["Questo giro", row.wave.outcome || (WAVE[row.wave.status] || row.wave.status) + (row.wave.job ? ` (${row.wave.job})` : "")],
    quarantine ? ["Quarantena", `si ritenta dopo ${when(quarantine.until)} (${quarantine.failures} errori)`] : null,
    row.wave.last_success ? ["Ultima remediation", when(row.wave.last_success)] : null,
    row.kev.length ? ["KEV", row.kev.join(", ")] : null,
    row.profile ? ["Profilo", `${row.profile.units} servizi, ${row.profile.required} pacchetti necessari su ${row.profile.installed ?? "?"}`] : null,
  ].filter(Boolean);
  const pkgs = row.packages.map((p) => el(
    "li", {}, el("span", { class: "name" }, p.package), " ",
    badge(PENDING.has(p.action) ? (p.priority === "act" ? "critical" : p.priority === "attend" ? "warning" : "unknown") : "ok", ACTION[p.action] || p.action),
    p.kev ? badge("critical", "KEV") : null,
    p.priority ? el("span", { class: "hint" }, ` ${p.priority}, ${p.cves} CVE`) : null,
    p.evidence.length ? el("span", { class: "why" }, p.evidence.join("; ")) : null,
  ));
  return el(
    "article", { class: "node " + row.level, id: "nodo-" + row.name },
    el("div", { class: "title" }, el("h3", {}, row.name), badge(row.level)),
    el("div", { class: "tags" },
      row.group ? badge("plain", row.group) : badge("warning", "senza gruppo"),
      row.canary ? badge("info", "canary") : null,
      row.ready ? null : badge("critical", "non Ready"),
      row.cordoned ? badge("warning", "cordon") : null,
      quarantine ? badge("serious", "quarantena") : null),
    failed ? el("p", { class: "failed-msg" }, failed) : null,
    row.reasons.length ? el("ul", { class: "reasons" }, row.reasons.map((r) => el("li", {}, r))) : null,
    el("div", { class: "counts" },
      el("div", { class: "count" }, el("b", {}, row.actions.update), el("span", {}, "aggiorna")),
      el("div", { class: "count" }, el("b", {}, row.actions.remove + row.actions.mitigate), el("span", {}, "rimuovi/mitiga")),
      el("div", { class: "count" }, el("b", {}, row.actions.not_affected), el("span", {}, "non affetti")),
      el("div", { class: "count" }, el("b", {}, row.priorities.act), el("span", {}, "priorità act"))),
    el("dl", { class: "kv" }, kv.map(([k, v]) => [el("dt", {}, k), el("dd", {}, v)])),
    pkgs.length ? el("details", { "data-node": row.name, open: openDetails().has(row.name) }, el("summary", {}, `Pacchetti (${pkgs.length})`), el("ul", { class: "pkgs" }, pkgs)) : null,
  );
}

function openDetails() {
  // I dettagli aperti restano aperti quando la pagina si ridisegna.
  return new Set([...document.querySelectorAll("details[open][data-node]")].map((x) => x.dataset.node));
}

function setOptions(id, first, values) {
  const select = document.getElementById(id);
  const current = select.value;
  select.replaceChildren(el("option", { value: "" }, first), ...values.map((v) => el("option", { value: v }, v)));
  select.value = values.includes(current) ? current : "";
}

function renderNodes(d) {
  setOptions("node-group", "Tutti i gruppi", [...new Set(d.nodes.map((n) => n.group).filter(Boolean))]);
  const query = document.getElementById("node-search").value.trim().toLowerCase();
  const group = document.getElementById("node-group").value;
  const level = document.getElementById("node-level").value;
  const quarantine = new Map(d.controller.quarantined.map((q) => [q.node, q]));
  const rows = d.nodes.filter((n) => (!query || n.name.toLowerCase().includes(query)) && (!group || n.group === group) && (!level || n.level === level));
  replace("nodes", rows.length ? rows.map((r) => renderNode(r, quarantine.get(r.name))) : el("p", { class: "hint" }, "Nessun nodo con questi filtri."));
}

function renderCves(d) {
  setOptions("cve-node", "Tutti i nodi", d.nodes.map((n) => n.name));
  const perNode = d.nodes.map((n) => {
    const values = { critical: 0, warning: 0, unknown: 0 };
    for (const c of d.cves) {
      if (!c.where.some((w) => w.node === n.name && PENDING.has(w.action))) continue;
      values[c.kev || c.priority === "act" ? "critical" : c.priority === "attend" ? "warning" : "unknown"] += 1;
    }
    return { label: n.name, values };
  }).filter((r) => r.values.critical + r.values.warning + r.values.unknown);
  figure("chart-cve-nodes", "CVE aperte per nodo", "quante CVE restano da sistemare su ogni nodo",
    perNode.length ? stackedRows(perNode, [{ level: "critical", label: "gravi (KEV, act)" }, { level: "warning", label: "attend" }, { level: "unknown", label: "da seguire" }]) : el("p", { class: "hint" }, "Nessuna CVE aperta."));

  const query = document.getElementById("cve-search").value.trim().toLowerCase();
  const node = document.getElementById("cve-node").value;
  const openOnly = document.getElementById("cve-open").checked;
  const rows = [];
  for (const cve of d.cves) {
    let where = cve.where;
    if (node) where = where.filter((w) => w.node === node);
    if (openOnly) where = where.filter((w) => PENDING.has(w.action));
    if (!where.length) continue;
    if (query && !cve.id.toLowerCase().includes(query) && !where.some((w) => (w.package || "").toLowerCase().includes(query))) continue;
    rows.push(el(
      "tr", {},
      el("td", { class: "mono" }, cve.id, cve.kev ? [" ", badge("critical", "KEV")] : null),
      el("td", {}, cve.priority ? badge(cve.priority === "act" ? "critical" : cve.priority === "attend" ? "warning" : "unknown", cve.priority) : "-"),
      el("td", { class: "num" }, cve.epss === null ? "-" : (cve.epss * 100).toFixed(1) + "%"),
      el("td", {}, el("div", { class: "where" }, where.map((w) => el("span", { class: "chip", title: w.status || "" }, `${w.node} · ${w.package} · ${ACTION[w.action] || w.action}`)))),
    ));
    if (rows.length >= 150) break;
  }
  replace("cves", rows.length ? rows : el("tr", {}, el("td", { colspan: "4" }, "Nessuna CVE con questi filtri.")));
  document.getElementById("cve-count").textContent = `${rows.length} righe mostrate su ${d.cves.length} CVE nel report (le più urgenti per prime).`;
}

const CYCLE_KEYS = [
  { level: "ok", label: "fatti", match: "fatto" },
  { level: "unknown", label: "niente da fare", match: "niente da fare" },
  { level: "info", label: "simulati", match: "simulato" },
  { level: "warning", label: "saltati", match: "saltato" },
  { level: "critical", label: "falliti", match: "fallito" },
];

function cycleValues(c) {
  const values = {};
  for (const [outcome, n] of Object.entries(c.outcomes || {})) {
    const key = CYCLE_KEYS.find((k) => outcome.startsWith(k.match)) || CYCLE_KEYS[1];
    values[key.level] = (values[key.level] || 0) + n;
  }
  return values;
}

function renderCycles(d) {
  const cycles = d.cycles || [];
  const recent = cycles.slice(0, 60).reverse();
  figure("chart-cycles", "Esiti dei giri", "un giro per colonna, dal più vecchio al più recente",
    recent.length ? stackedColumns(recent.map((c) => ({ label: c.id, values: cycleValues(c) })), CYCLE_KEYS) : el("p", { class: "hint" }, "Nessun giro finito da quando c'è lo storico."));
  replace("cycles", cycles.map((c) => {
    const values = cycleValues(c);
    const failed = Object.entries(c.nodes || {}).filter(([, r]) => r.outcome.startsWith("fallit"));
    return el(
      "details", { class: "cycle", "data-node": "giro-" + c.id, open: openDetails().has("giro-" + c.id) },
      el("summary", {}, el("b", {}, `Giro ${c.id}`), el("span", { class: "hint" }, `${when(c.finished)} · durata ${duration(c.started, c.finished)} · ${c.why}`),
        CYCLE_KEYS.filter((k) => values[k.level]).map((k) => badge(k.level, `${values[k.level]} ${k.label}`))),
      c.error ? el("p", { class: "failed-msg" }, c.error) : null,
      failed.length ? el("p", { class: "failed-msg" }, failed.map(([n, r]) => `${n}: ${r.detail || r.outcome}`).join(" · ")) : null,
      el("ul", {}, Object.entries(c.nodes || {}).map(([n, r]) => el("li", {}, `${n}: ${r.outcome}${r.detail ? ` (${r.detail})` : ""}`))),
    );
  }));
}

function renderHealth(d) {
  const h = d.health || { components: [], servers: [] };
  replace("components", h.components.map((c) => el("li", {}, badge(c.level, c.name), el("span", { class: "detail" }, c.detail))));
  const quarantined = new Set(d.controller.quarantined.map((q) => q.node));
  replace("squares", h.servers.map((s) => {
    const level = quarantined.has(s.name) ? "serious" : !s.reached ? "critical" : s.level;
    const tip = `${s.name} · ${LEVEL[level]}${s.reached ? "" : " · non raggiunto all'ultimo controllo"}${s.outcome ? " · " + s.outcome : ""}`;
    return el("a", { class: "square bg-" + level, href: "#/nodi", tip }, el("span", { class: "sym", "aria-hidden": "true" }, SYMBOL[level]), s.name);
  }));
  replace("servers", h.servers.map((s) => el(
    "tr", {},
    el("td", {}, s.name, s.group ? el("span", { class: "hint" }, ` ${s.group}`) : null),
    el("td", {}, badge(quarantined.has(s.name) ? "serious" : s.level, quarantined.has(s.name) ? "quarantena" : null), s.ready ? null : badge("critical", "non Ready"), s.reboot ? badge("warning", "riavvio in sospeso") : null),
    el("td", {}, s.reached ? badge("ok", "sì") : badge("critical", "no")),
    el("td", { class: "mono" }, s.kernel || "-"),
    el("td", {}, s.os_image || "-"),
    el("td", {}, s.outcome || "-"),
  )));
}

function renderHistory(d) {
  replace("history", d.history.length ? d.history.map((h) => el(
    "li", {},
    el("span", { class: "when" }, [when(h.time), h.user ? `${h.user}${h.host ? `@${h.host}` : ""}` : null, h.kube_user ? `k8s ${h.kube_user}` : null].filter(Boolean).join(" · ")),
    el("span", {}, el("b", {}, h.action || "modifica"), h.changes ? ` · ${h.changes} modifiche` : "", h.note ? ` · ${h.note}` : ""),
  )) : el("li", {}, "Nessuna modifica registrata."));
}

// ------------------------------------------------------------------ log

async function loadPods() {
  const select = document.getElementById("log-pod");
  try {
    const pods = await (await fetch("/api/pods", { cache: "no-store" })).json();
    const current = select.value;
    select.replaceChildren(...pods.map((p) => el("option", { value: p.name }, `${p.role || "pod"} · ${p.name} · ${p.phase}`)));
    if (pods.some((p) => p.name === current)) select.value = current;
  } catch (exc) {
    document.getElementById("log-info").textContent = "elenco dei pod non disponibile: " + exc.message;
  }
}

async function loadLog() {
  const name = document.getElementById("log-pod").value;
  const box = document.getElementById("log");
  if (!name) { box.textContent = "Nessun pod di SAGE."; return; }
  try {
    const response = await fetch("/api/logs?pod=" + encodeURIComponent(name), { cache: "no-store" });
    const text = await response.text();
    const atBottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 20;
    box.textContent = response.ok ? text || "(log vuoto)" : "Log non disponibile: " + text;
    if (document.getElementById("log-follow").checked && atBottom) box.scrollTop = box.scrollHeight;
    document.getElementById("log-info").textContent = `ultime righe, lette ${new Date().toLocaleTimeString("it-IT")}`;
  } catch (exc) {
    box.textContent = "Log non disponibile: " + exc.message;
  }
}

// ------------------------------------------------------------------ giro di lettura

const RENDER = { panoramica: renderOverview, nodi: renderNodes, cve: renderCves, giri: renderCycles, salute: renderHealth, storico: renderHistory, log: () => {} };

function render() {
  if (!data) return;
  renderMeta(data);
  RENDER[page](data);
}

function route() {
  const name = location.hash.replace(/^#\//, "");
  page = PAGES.includes(name) ? name : "panoramica";
  for (const section of document.querySelectorAll(".page")) section.hidden = section.dataset.page !== page;
  for (const tab of document.querySelectorAll(".tabs a")) {
    if (tab.dataset.tab === page) tab.setAttribute("aria-current", "page");
    else tab.removeAttribute("aria-current");
  }
  render();
  if (page === "log") loadPods().then(loadLog);
}

function renderLive() {
  const live = document.getElementById("live");
  if (!data) return;
  const age = Math.round((Date.now() - lastOk) / 1000);
  const stale = age > 3 * data.refresh_seconds;
  live.className = "live" + (stale ? " stale" : "");
  live.replaceChildren(el("span", { class: "pulse", "aria-hidden": "true" }), stale ? `dati vecchi di ${age} s` : `in tempo reale · ${age} s fa`);
  document.getElementById("footer").textContent =
    `Dashboard ${data.dashboard_version} · SAGE dell'ultimo controllo ${data.sage_version || "?"} · si aggiorna ogni ${data.refresh_seconds} s`;
}

async function load() {
  const error = document.getElementById("error");
  clearTimeout(timer);
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (!response.ok) throw new Error(await response.text());
    const body = await response.text();
    data = JSON.parse(body);
    lastOk = Date.now();
    error.hidden = true;
    const key = body.replace(/"now":\s*"[^"]*"/, ""); // "now" cambia sempre
    if (key !== lastBody) {
      lastBody = key;
      render();
    }
    if (page === "log" && document.getElementById("log-follow").checked) loadLog();
  } catch (exc) {
    error.textContent = "Dati non disponibili: " + exc.message;
    error.hidden = false;
  }
  renderLive();
  // Con la scheda nascosta non si legge niente: si riparte quando torna visibile.
  if (!document.hidden) timer = setTimeout(load, ((data && data.refresh_seconds) || 5) * 1000);
}

document.addEventListener("DOMContentLoaded", () => {
  for (const id of ["node-search", "node-group", "node-level", "cve-search", "cve-node", "cve-open"]) {
    document.getElementById(id).addEventListener("input", render);
  }
  document.getElementById("log-pod").addEventListener("change", loadLog);
  window.addEventListener("hashchange", route);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) load(); });
  setInterval(() => data && render(), 60000); // tempi relativi ("3 minuti fa")
  setInterval(renderLive, 1000);
  setupTooltip();
  route();
  load();
});
