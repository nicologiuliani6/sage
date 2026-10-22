"use strict";

// Dashboard di SAGE: legge /api/status e disegna la pagina. Solo lettura, nessun
// dato da fuori. Tutti i testi passano da textContent (niente HTML dai dati).

const LEVEL = { critical: "critico", warning: "attenzione", ok: "a posto", unknown: "sconosciuto", info: "info" };
const ACTION = { update: "aggiorna", remove: "rimuovi", mitigate: "mitiga", not_affected: "non affetto", skip: "ignorato" };
const WAVE = { idle: "in attesa", running: "in corso", done: "fatto", failed: "fallito" };
const PENDING = new Set(["update", "remove", "mitigate"]);

let data = null;
let timer = null;

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
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

function replace(id, ...children) {
  const nodes = children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false);
  document.getElementById(id).replaceChildren(...nodes);
}

function renderMeta(d) {
  replace(
    "meta",
    d.dry_run ? badge("info", "SIMULAZIONE") : badge("warning", "VIVO: modifica i nodi"),
    d.suspended ? badge("warning", "giri sospesi") : null,
    d.halted ? badge("critical", "ondate ferme") : null,
    el("span", {}, "ultimo giro ", el("b", {}, when(d.report_at))),
    el("span", {}, "prossimo ", el("b", {}, d.suspended ? "nessuno (sospeso)" : when(d.next_scan))),
  );
}

function renderAlarms(d) {
  const items = d.alarms.length
    ? d.alarms.map((a) => el("li", { class: a.level }, badge(a.level), el("span", {}, a.text)))
    : [el("li", { class: "ok" }, badge("ok", "nessun allarme"), el("span", {}, "tutto sotto controllo"))];
  replace("alarms", items);
}

function tile(label, value, note, progress) {
  return el(
    "div", { class: "tile" },
    el("div", { class: "label" }, label),
    el("div", { class: "value" }, value),
    note ? el("div", { class: "note" }, note) : null,
    progress === undefined ? null : progressBar(progress),
  );
}

function progressBar(progress) {
  // Larghezza via CSSOM: la CSP non permette attributi style inline.
  const fill = el("div", { class: "bar-fill" });
  fill.style.width = `${Math.round(progress * 100)}%`;
  return el("div", { class: "bar-track" }, fill);
}

function renderTiles(d) {
  const t = d.totals;
  const levels = t.levels || {};
  replace(
    "tiles",
    tile("Nodi senza azioni in sospeso", `${t.nodes_clean} / ${t.nodes}`, "quanto manca alla fine delle ondate", t.nodes ? t.nodes_clean / t.nodes : 0),
    tile("Advisory da applicare", t.advisories, t.deferred ? `${t.deferred} ${t.deferred === 1 ? "pacchetto rimandato" : "pacchetti rimandati"} (finestra o kernel manuale)` : "nessun rimando"),
    tile("CVE sfruttate (KEV) aperte", t.kev, t.kev ? "da sistemare per prime" : "nessuna"),
    tile("Stato dei nodi", `${levels.critical || 0} · ${levels.warning || 0} · ${levels.ok || 0}`, "critici · attenzione · a posto"),
  );
}

function nodeDot(row) {
  return el("span", { class: "dot " + row.level, title: LEVEL[row.level] });
}

function renderWaves(d) {
  const byGroup = new Map();
  for (const row of d.nodes) {
    const key = row.group || "senza gruppo";
    if (!byGroup.has(key)) byGroup.set(key, []);
    byGroup.get(key).push(row);
  }
  const groups = d.groups.length ? d.groups : [...byGroup.keys()].map((name) => ({ name }));
  const cards = groups.map((g, index) => {
    const rows = byGroup.get(g.name) || [];
    return el(
      "div", { class: "wave" },
      el("div", { class: "head" }, el("b", {}, `${index + 1}. ${g.name}`), el("span", {}, g.window ? `finestra ${g.window}` : "senza finestra")),
      el("div", { class: "chips" }, rows.length ? rows.map((row) => el(
        "span", { class: "chip", title: row.reasons.join("; ") },
        nodeDot(row), row.name, row.canary ? badge("info", "canary") : null,
        badge(row.wave.status === "failed" ? "critical" : row.wave.status === "running" ? "info" : "unknown", WAVE[row.wave.status] || row.wave.status),
      )) : el("span", { class: "hint" }, "nessun nodo")),
    );
  });
  if (byGroup.has("senza gruppo") && d.groups.length) {
    cards.push(el("div", { class: "wave" }, el("div", { class: "head" }, el("b", {}, "senza gruppo"), el("span", {}, "non gestiti")),
      el("div", { class: "chips" }, byGroup.get("senza gruppo").map((row) => el("span", { class: "chip" }, nodeDot(row), row.name)))));
  }
  replace("waves", cards);
  replace("messages", d.messages.map((m) => el("li", {}, "› " + m)));
}

function count(value, label) {
  return el("div", { class: "count" }, el("b", {}, value), el("span", {}, label));
}

function planText(plan) {
  const parts = [];
  if (plan.advisories) parts.push(`${plan.advisories} advisory (${plan.packages} pacchetti)`);
  if (plan.remove.length) parts.push("rimuovere " + plan.remove.join(", "));
  if (plan.mitigate.length) parts.push("bloccare " + plan.mitigate.join(", "));
  return parts.join("; ") || "niente da fare";
}

function renderNode(row) {
  const kv = [
    ["Piano", planText(row.plan)],
    row.plan.deferred.length ? ["Rimandati", `${row.plan.deferred.length}: ${[...new Set(row.plan.deferred.map((x) => x.reason))].join("; ")}`] : null,
    row.next_window ? ["Prossima finestra", when(row.next_window)] : null,
    ["Ondata", (WAVE[row.wave.status] || row.wave.status) + (row.wave.job ? ` (${row.wave.job})` : "")],
    row.wave.last_success ? ["Ultima remediation", when(row.wave.last_success)] : null,
    row.wave.soak_until ? ["Osservazione fino a", when(row.wave.soak_until)] : null,
    row.kev.length ? ["KEV", row.kev.join(", ")] : null,
    row.profile ? ["Profilo", `${row.profile.units} servizi, ${row.profile.required} pacchetti necessari su ${row.profile.installed ?? "?"}`] : null,
    row.profile && row.profile.extra.length ? ["Aggiunti a mano", row.profile.extra.join(", ")] : null,
  ].filter(Boolean);

  const pkgs = row.packages.map((p) => el(
    "li", {},
    el("span", { class: "name" }, p.package), " ",
    badge(PENDING.has(p.action) ? (p.priority === "act" ? "critical" : p.priority === "attend" ? "warning" : "unknown") : "ok", ACTION[p.action] || p.action),
    p.kev ? badge("critical", "KEV") : null,
    p.priority ? el("span", { class: "hint" }, ` ${p.priority}, ${p.cves} CVE`) : null,
    p.evidence.length ? el("span", { class: "why" }, p.evidence.join("; ")) : null,
  ));

  return el(
    "article", { class: "node " + row.level },
    el("div", { class: "title" }, el("h3", {}, row.name), badge(row.level)),
    el("div", { class: "tags" },
      row.group ? badge("unknown", row.group) : badge("warning", "senza gruppo"),
      row.canary ? badge("info", "canary") : null,
      row.ready ? null : badge("critical", "non Ready"),
      row.cordoned ? badge("warning", "cordon") : null),
    row.reasons.length ? el("ul", { class: "reasons" }, row.reasons.map((r) => el("li", {}, r))) : null,
    el("div", { class: "counts" },
      count(row.actions.update, "aggiorna"),
      count(row.actions.remove + row.actions.mitigate, "rimuovi/mitiga"),
      count(row.actions.not_affected, "non affetti"),
      count(row.priorities.act, "priorità act")),
    el("dl", { class: "kv" }, kv.map(([k, v]) => [el("dt", {}, k), el("dd", {}, v)])),
    pkgs.length ? el("details", {}, el("summary", {}, `Pacchetti (${pkgs.length})`), el("ul", { class: "pkgs" }, pkgs)) : null,
  );
}

function renderNodes(d) {
  replace("nodes", d.nodes.length ? d.nodes.map(renderNode) : el("p", { class: "hint" }, "Nessun nodo gestito."));
  const select = document.getElementById("cve-node");
  const current = select.value;
  select.replaceChildren(el("option", { value: "" }, "Tutti i nodi"), ...d.nodes.map((n) => el("option", { value: n.name }, n.name)));
  select.value = d.nodes.some((n) => n.name === current) ? current : "";
}

function renderCves() {
  if (!data) return;
  const query = document.getElementById("cve-search").value.trim().toLowerCase();
  const node = document.getElementById("cve-node").value;
  const openOnly = document.getElementById("cve-open").checked;
  const rows = [];
  for (const cve of data.cves) {
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
      el("td", {}, el("div", { class: "where" }, where.map((w) => el(
        "span", { class: "chip", title: w.status || "" },
        `${w.node} · ${w.package} · ${ACTION[w.action] || w.action}`,
      )))),
    ));
    if (rows.length >= 150) break;
  }
  replace("cves", rows.length ? rows : el("tr", {}, el("td", { colspan: "4" }, "Nessuna CVE con questi filtri.")));
  document.getElementById("cve-count").textContent = `${rows.length} righe mostrate su ${data.cves.length} CVE nel report (le più urgenti per prime).`;
}

function renderHistory(d) {
  replace("history", d.history.length ? d.history.map((h) => el(
    "li", {},
    el("span", { class: "when" }, [
      when(h.time),
      h.user ? `${h.user}${h.sudo_user ? ` (sudo da ${h.sudo_user})` : ""}${h.host ? `@${h.host}` : ""}` : null,
      h.kube_user ? `k8s ${h.kube_user}` : null,
    ].filter(Boolean).join(" · ")),
    el("span", {}, el("b", {}, h.action || "modifica"), h.changes ? ` · ${h.changes} modifiche` : "", h.note ? ` · ${h.note}` : ""),
  )) : el("li", {}, "Nessuna modifica registrata."));
}

async function load() {
  const error = document.getElementById("error");
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (!response.ok) throw new Error(await response.text());
    data = await response.json();
    error.hidden = true;
    renderMeta(data);
    renderAlarms(data);
    renderTiles(data);
    renderWaves(data);
    renderNodes(data);
    renderCves();
    renderHistory(data);
    document.getElementById("footer").textContent =
      `Dashboard ${data.dashboard_version} · SAGE dell'ultimo giro ${data.sage_version || "?"} · aggiornata ${when(data.now)} · si aggiorna ogni ${data.refresh_seconds} s`;
  } catch (exc) {
    error.textContent = "Dati non disponibili: " + exc.message;
    error.hidden = false;
  }
  clearTimeout(timer);
  timer = setTimeout(load, ((data && data.refresh_seconds) || 60) * 1000);
}

document.addEventListener("DOMContentLoaded", () => {
  for (const id of ["cve-search", "cve-node", "cve-open"]) {
    document.getElementById(id).addEventListener("input", renderCves);
  }
  load();
});
