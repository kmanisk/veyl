"use strict";

const byId = id => document.getElementById(id);
const api = "/dashboard/api/";
const notice = byId("notice");
const remote = location.protocol === "https:";
const proofKey = "veyl-session-proof";
let csrf = remote ? sessionStorage.getItem(proofKey) : undefined;
let nextPage;
let currentJobCursor = "";
let jobRequest = 0;
let logRequest = 0;
const tabs = [...document.querySelectorAll('nav a[href^="#"]')];
let activeTab = "health";
let traceEnabled = false;
let traceExpiryTimer;
let liveInitialized = false;
function clearTracePreviews() {
  for (const cell of document.querySelectorAll("[data-trace-preview]")) {
    cell.textContent = cell.dataset.safeSummary || "";
    delete cell.dataset.tracePreview;
  }
  if (byId("detail-dialog").open && byId("detail-json").textContent.includes('"local_trace"')) {
    byId("detail-dialog").close();
  }
}
function commandPreview(record) {
  if (typeof record?.target_preview === "string") return record.target_preview;
  const args = record?.arguments;
  if (!args) return null;
  if (typeof args.command === "string") return args.command;
  if (Array.isArray(args.argv)) return JSON.stringify(args.argv);
  if (typeof args.profile === "string") return "Profile: " + args.profile;
  return null;
}
function updateTraceState(trace, requested) {
  clearTimeout(traceExpiryTimer);
  traceEnabled = trace.enabled === true && Number.isFinite(trace.remaining_ms) &&
    trace.remaining_ms > performance.now() - requested;
  if (!traceEnabled) clearTracePreviews();
  else traceExpiryTimer = setTimeout(() => {
    traceEnabled = false;
    clearTracePreviews();
    byId("trace-toggle").textContent = "Capture local command trace";
    byId("trace-state").textContent = "Trace expired";
  }, Math.max(0, trace.remaining_ms - (performance.now() - requested)));
}
byId("trace-controls").hidden = remote;
byId("diagnostics-nav").hidden = remote;
byId("diagnostics-form").addEventListener("submit",async event=>{
  event.preventDefault();
  const section=byId("diagnostics-section").value;
  const run=byId("diagnostics-run");
  run.disabled=true;
  byId("diagnostics-output").textContent="Inspecting "+section+"…";
  try {
    const data=await request("diagnostics?section="+encodeURIComponent(section));
    if (!byId("dashboard").hidden) byId("diagnostics-output").textContent=JSON.stringify(data,null,2);
  } catch(error) { byId("diagnostics-output").textContent=error.message; }
  finally { run.disabled=false; }
});
byId("trace-toggle").addEventListener("click", async () => {
  if (!traceEnabled && !window.confirm("Capture command arguments and responses for 10 minutes in this local session? They may contain secrets. No trace is written to disk.")) return;
  try {
    const state = await request("trace", {enabled: !traceEnabled, confirm:true});
    traceEnabled = state.enabled;
    await loadActivity();
  } catch(error) { notice.textContent=error.message; }
});
const themeModes = ["system", "dark", "light"];
let theme = "system";
try { const saved = localStorage.getItem("veyl-theme"); if (themeModes.includes(saved)) theme = saved; } catch {}
function applyTheme() {
  document.documentElement.dataset.theme = theme;
  byId("theme").textContent = "Theme: " + theme;
}
applyTheme();
byId("theme").addEventListener("click", () => {
  theme = themeModes[(themeModes.indexOf(theme) + 1) % themeModes.length];
  try { localStorage.setItem("veyl-theme", theme); } catch {}
  applyTheme();
});
function showDetails(value) {
  byId("detail-json").textContent = JSON.stringify(value, null, 2);
  if (!byId("detail-dialog").open) byId("detail-dialog").showModal();
}
byId("detail-close").addEventListener("click", () => byId("detail-dialog").close());
byId("detail-dialog").addEventListener("close", () => {
  if (!byId("detail-dialog").open) byId("detail-json").replaceChildren();
});
document.addEventListener("keydown", event => {
  if (event.key !== "/" || event.ctrlKey || event.altKey || event.metaKey || byId("dashboard").hidden || byId("detail-dialog").open || ["INPUT","TEXTAREA","SELECT"].includes(event.target.tagName)) return;
  const field = activeTab === "audit" ? "audit-filter" : activeTab === "jobs" ? "job-filter" : null;
  if (field) { event.preventDefault(); byId(field).focus(); }
});
function selectTab(id, focus = false) {
  const available = tabs.filter(tab => !tab.hidden);
  if (!available.some(tab => tab.hash === "#" + id)) id = "health";
  activeTab = id;
  for (const tab of tabs) {
    const key = tab.hash.slice(1);
    const selected = key === id;
    const page = byId(key).closest("section");
    tab.id = tab.id || "tab-" + key;
    tab.setAttribute("role", "tab");
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
    page.id = page.id || "page-" + key;
    tab.setAttribute("aria-controls", page.id);
    page.setAttribute("role", "tabpanel");
    page.setAttribute("aria-labelledby", tab.id);
    page.classList.toggle("inactive-tab", !selected);
    if (selected && focus) tab.focus();
  }
}
for (const tab of tabs) {
  tab.addEventListener("click", event => {
    event.preventDefault();
    history.replaceState(null, "", "/dashboard" + tab.hash);
    selectTab(tab.hash.slice(1));
  });
  tab.addEventListener("keydown", event => {
    const visible = tabs.filter(item => !item.hidden);
    const index = visible.indexOf(tab);
    const next = { ArrowRight: (index + 1) % visible.length, ArrowDown: (index + 1) % visible.length, ArrowLeft: (index + visible.length - 1) % visible.length, ArrowUp: (index + visible.length - 1) % visible.length, Home: 0, End: visible.length - 1 }[event.key];
    if (next === undefined) return;
    event.preventDefault();
    history.replaceState(null, "", "/dashboard" + visible[next].hash);
    selectTab(visible[next].hash.slice(1), true);
  });
}

async function request(path, body) {
  const response = await fetch(api + path, body === undefined ? {
    headers: csrf ? { "X-CSRF-Token": csrf } : {}
  } : {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf || "" },
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    if (response.status === 401 && path !== "pair") showPair();
    const message = response.headers.get("content-type")?.includes("application/json")
      ? (await response.json()).error : await response.text();
    throw Object.assign(new Error(message), { status: response.status });
  }
  return response.json();
}

function showPair() {
  byId("diagnostics-output").textContent="Select a subsystem and inspect.";
  if (byId("detail-dialog").open) byId("detail-dialog").close();
  activityRequest++;
  byId("audit-ledger").open = false;
  byId("audit-rows").replaceChildren();
  byId("live-refresh").checked = false;
  liveInitialized = false;
  clearTimeout(liveTimer);
  clearTimeout(traceExpiryTimer);
  traceEnabled = false;
  clearTracePreviews();
  csrf = undefined;
  if (remote) sessionStorage.removeItem(proofKey);
  byId("dashboard").hidden = true;
  byId("controls").hidden = true;
  byId("pair").hidden = false;
  byId("output").textContent = "";
}

function add(parent, tag, value) {
  const element = document.createElement(tag);
  element.textContent = value;
  parent.append(element);
  return element;
}

function table(id, rows) {
  const body = byId(id);
  body.replaceChildren();
  for (const row of rows) {
    const tr = add(body, "tr", "");
    for (const value of row) add(tr, "td", value);
  }
}

function filterRows(id, value) {
  const query = value.trim().toLowerCase();
  for (const row of byId(id).children) row.hidden = !(row.dataset.search || row.textContent).toLowerCase().includes(query);
}
byId("job-filter").addEventListener("input", event => filterRows("job-rows", event.target.value));
byId("audit-filter").addEventListener("input", event => filterRows("audit-rows", event.target.value));

function button(parent, label, action) {
  const element = add(parent, "button", label);
  element.type = "button";
  element.addEventListener("click", () => action().catch(error => notice.textContent = error.message));
}

// Catalog entries are metadata, never executable installation instructions.
let catalog = [];
let catalogLoaded = false;
let catalogPage = 0;
const catalogPageSize = 20;
let registeredIds = new Set();
const probedTools = new Map();
const catalogFields = {
  "catalog-category": entry => [entry.category],
  "catalog-type": entry => [entry.type],
  "catalog-maintainer": entry => [entry.maintainer],
  "catalog-platform": entry => entry.platforms || [],
};
function openTab(id) {
  history.replaceState(null, "", "/dashboard#" + id);
  selectTab(id, true);
}
function renderCatalog() {
  const query = byId("catalog-query").value.trim().toLowerCase();
  const status = byId("catalog-status").value;
  const matches = catalog.filter(entry => {
    if (query && ![entry.name, entry.id, entry.description, entry.maintainer, entry.category].join(" ").toLowerCase().includes(query)) return false;
    for (const [id, values] of Object.entries(catalogFields)) {
      const value = byId(id).value;
      if (value && !values(entry).includes(value)) return false;
    }
    return !status || (status === "registered") === registeredIds.has(entry.id);
  });
  const pages = Math.max(1, Math.ceil(matches.length / catalogPageSize));
  catalogPage = Math.min(catalogPage, pages - 1);
  const grid = byId("catalog-cards");
  grid.replaceChildren();
  byId("catalog-count").textContent = matches.length + " matching resources · " + catalog.length + " in bundled snapshot · metadata only";
  for (const entry of matches.slice(catalogPage * catalogPageSize, (catalogPage + 1) * catalogPageSize)) {
    const card = add(grid, "article", "");
    card.className = "catalog-card";
    card.dataset.entry = entry.id;
    const top = add(card, "div", "");
    top.className = "row";
    add(top, "span", entry.type).className = "catalog-kind";
    add(top, "span", registeredIds.has(entry.id) ? "Matching registered ID — verify identity" : "Not registered under this ID").className = "catalog-meta";
    add(card, "h3", entry.name);
    add(card, "p", entry.description || "");
    add(card, "p", [entry.category,entry.maintainer,entry.version].filter(Boolean).join(" · ")).className = "catalog-meta";
    const footer = add(card, "div", "");
    footer.className = "row catalog-footer";
    add(footer, "span", "Source checked " + (entry.verified_at || "Unknown")).className = "catalog-meta";
    button(footer, "Details", async () => showDetails(entry));
    if (entry.type === "mcp") button(footer, "Configure", async () => {
      const form = byId("server-add");
      form.reset();
      const id = entry.id.replace(/[^a-z0-9_-]/g,"").slice(0,24);
      form.elements.namedItem("id").value = id;
      byId("server-transport").value = "add-stdio";
      byId("server-transport").dispatchEvent(new Event("change"));
      byId("catalog-selection").textContent = entry.name + " · " + (entry.installation?.source || entry.source) + ". Enter a reviewed compatible executable/endpoint. " + (entry.id === "rea" ? "REA launcher: rea mcp. Existing Veyl stdio isolation does not mount Node package trees; compatibility must be verified." : "No installation or registration has occurred.");
      if (entry.id === "rea") form.elements.namedItem("argv").value = '["mcp"]';
      openTab("custom");
    });
    else if (entry.type === "skill") button(footer, "Import local skill", async () => openTab("skills"));
  }
  if (!matches.length) add(grid,"p","No matching resources.");
  byId("catalog-page").textContent = (catalogPage + 1) + " / " + pages;
  byId("catalog-prev").disabled = catalogPage === 0;
  byId("catalog-next").disabled = catalogPage + 1 >= pages;
}
async function loadCatalog(force = false) {
  if (catalogLoaded && !force) return;
  const data = await request("marketplace");
  if (data.version !== 1 || !Array.isArray(data.entries)) throw new Error("Invalid marketplace snapshot");
  catalog = data.entries;
  catalogLoaded = true;
  for (const [id, values] of Object.entries(catalogFields)) {
    const select = byId(id), previous = select.value;
    select.replaceChildren();
    add(select,"option","Any " + id.slice(8)).value = "";
    for (const value of [...new Set(catalog.flatMap(values).filter(Boolean))].sort()) add(select,"option",value).value = value;
    if ([...select.options].some(option => option.value === previous)) select.value = previous;
  }
  renderCatalog();
}
for (const id of ["catalog-query","catalog-status",...Object.keys(catalogFields)]) {
  byId(id).addEventListener(id === "catalog-query" ? "input" : "change", () => { catalogPage = 0; renderCatalog(); });
}
byId("catalog-prev").addEventListener("click", () => { catalogPage--; renderCatalog(); });
byId("catalog-next").addEventListener("click", () => { catalogPage++; renderCatalog(); });
byId("catalog-refresh").addEventListener("click", () => loadCatalog(true).catch(error => notice.textContent = error.message));
byId("open-custom").addEventListener("click", () => openTab("custom"));
byId("open-marketplace").addEventListener("click", () => openTab("marketplace"));
byId("custom-skills").addEventListener("click", () => {
  if (byId("skills-nav").hidden) notice.textContent = "Skills store is not configured.";
  else openTab("skills");
});
function updateProbedTools() {
  const list = byId("server-tool-options");
  list.replaceChildren();
  for (const name of probedTools.get(byId("server-grant-server").value) || []) add(list,"option",name).value = name;
}
byId("server-grant-server").addEventListener("change", updateProbedTools);

function summary(id, entries) {
  const list = byId(id);
  list.replaceChildren();
  for (const [label, value] of entries) {
    const box = add(list, "div", "");
    add(box, "dt", label);
    add(box, "dd", value);
  }
}

async function loadIntegrations() {
  summary("integrations-summary", [["Integrations", "Checking…"]]);
  try {
    const { service, tailscale } = await request("integrations");
    summary("integrations-summary", [
      ["Systemd", service.ActiveState || service.LoadState || "Unavailable"],
      ["Tailscale", tailscale.state || "Unconfigured"],
      ["MCP HTTPS", tailscale.mcp || "Unavailable"],
      ["Dashboard HTTPS", tailscale.dashboard || "Unavailable"],
    ]);
  } catch (error) {
    summary("integrations-summary", [["Integrations", "Unavailable"]]);
    throw error;
  }
}

async function refresh() {
  notice.textContent = "Loading gateway status…";
  const state = await request("status");
  csrf = state.csrf;
  byId("pair").hidden = true;
  byId("dashboard").hidden = false;
  if (location.pathname === "/dashboard/login") history.replaceState(null, "", "/dashboard");
  byId("controls").hidden = false;
  notice.textContent = "";
  summary("metrics", [
    ["MCP listener", state.listener], ["MCP sessions", state.sessions], ["TCP connections", state.connections], ["Active MCP calls", state.active_calls],
    ["Memory", state.rss_kib == null ? "Unavailable" : (state.rss_kib / 1024).toFixed(1) + " MiB"],
    ["CPU", state.cpu_percent == null ? "Refresh for sample" : state.cpu_percent.toFixed(2) + "%"],
    ["Audit", state.audit || "Unconfigured"]
  ]);
  const config = state.configuration;
  const paths = state.protected_paths;
  summary("configuration-summary", [
    ["Version", state.version],
    ["Authorization", config.authorization],
    ["Private state layout", config.broad_state_layout],
    ["Job profiles", config.configured_job_profiles ? "Configured" : "Unconfigured"],
    ["Skills store", config.configured_skills_store ? "Configured" : "Unconfigured"],
  ]);
  const homePaths = rules => rules.map(path => "~/" + path);
  const describe = rules => rules.length ? rules.join(", ") : "None";
  summary("protected-summary", [
    ["Masked state", paths.state_directory || "Broad YOLO inactive"],
    ["Masked skill store", paths.skills_directory || "Unconfigured"],
    ["Default masks", describe(homePaths(paths.default_masked))],
    ["Default read-only paths", describe(homePaths(paths.default_readonly))],
    ["Additional masks", describe(paths.extra_masked)],
    ["Additional read-only paths", describe(paths.extra_readonly)],
  ]);
  const modes = { standard: "Standard", scoped_yolo: "Scoped YOLO (legacy)", broad_yolo: "YOLO", yolo: "YOLO", full: "FULL", disabled: "Disabled" };
  const headerStatus = byId("header-status");
  if (headerStatus) {
    headerStatus.hidden = false;
    headerStatus.replaceChildren();
    add(add(headerStatus, "span", "Active calls: "), "strong", state.active_calls ?? 0).id = "header-active-count";
    add(headerStatus, "span", state.clients.map(c => `${c.id}: ${modes[c.mode] || c.mode}`).join(" · "));
  }
  const maskedBody = byId("protected-masked-rows");
  if (maskedBody && paths) {
    maskedBody.replaceChildren();
    const allMasked = [
      ...(paths.default_masked || []).map(p => ["~/" + p, "Masked (hidden)", "Default preset"]),
      ...(paths.extra_masked || []).map(p => [p, "Masked (hidden)", "Configured rule"])
    ];
    for (const [p, enf, scope] of allMasked) {
      const tr = add(maskedBody, "tr", "");
      add(tr, "td", p);
      add(tr, "td", enf);
      add(tr, "td", scope);
    }
  }
  const readonlyBody = byId("protected-readonly-rows");
  if (readonlyBody && paths) {
    readonlyBody.replaceChildren();
    const allReadonly = [
      ...(paths.default_readonly || []).map(p => ["~/" + p, "Read-Only", "Default preset"]),
      ...(paths.extra_readonly || []).map(p => [p, "Read-Only", "Configured rule"])
    ];
    for (const [p, enf, scope] of allReadonly) {
      const tr = add(readonlyBody, "tr", "");
      add(tr, "td", p);
      add(tr, "td", enf);
      add(tr, "td", scope);
    }
  }
  table("client-rows", state.clients.map(client => [
    client.id, (modes[client.mode] || client.mode) + (client.disabled ? " (disabled)" : "") + (client.expired ? " (expired)" : ""),
    client.connections, [
      client.grants.join(", "),
      client.skills.length ? "Skills: " + client.skills.join(", ") : "",
      client.upstreams.length ? "Upstream: " + client.upstreams.map(id => client.upstream_tools === null
        ? id + " (server-wide)" : id + " (" + (client.upstream_tools[id] || []).join(", ") + ")").join("; ") : ""
    ].filter(Boolean).join(" · ")
  ]));
  byId("client-empty").hidden = state.clients.length !== 0;
  const select = byId("job-client");
  const selected = select.value;
  select.replaceChildren();
  for (const client of state.clients) add(select, "option", client.id).value = client.id;
  if (state.clients.some(client => client.id === selected)) select.value = selected;
  const serverClient = byId("server-client");
  const previousServerClient = serverClient.value;
  serverClient.replaceChildren();
  for (const client of state.clients) add(serverClient, "option", client.id).value = client.id;
  if (state.clients.some(client => client.id === previousServerClient)) serverClient.value = previousServerClient;
  const tasks = [loadServers(), loadIntegrations(), loadCatalog()];
  byId("job-controls").hidden = !state.jobs_configured;
  if (state.jobs_configured) {
    tasks.push(loadJobs());
  } else {
    byId("job-rows").replaceChildren();
    add(byId("job-rows"), "li", "Job supervision is unavailable.");
    byId("logs").hidden = true;
  }
  tasks.push(loadActivity());
  byId("skill-panel").hidden = !state.skills_configured;
  byId("skills-nav").hidden = !state.skills_configured;
  selectTab(location.hash.slice(1) || activeTab);
  if (state.skills_configured) {
    const skillClient = byId("skill-client");
    const previous = skillClient.value;
    skillClient.replaceChildren();
    for (const client of state.clients) add(skillClient, "option", client.id).value = client.id;
    if (state.clients.some(client => client.id === previous)) skillClient.value = previous;
    tasks.push(loadSkills());
  }
  await Promise.allSettled(tasks).then(results => {
    for (const result of results) if (result.status === "rejected") notice.textContent = result.reason.message;
  });
  if (!liveInitialized && !byId("dashboard").hidden) {
    liveInitialized = true;
    byId("live-refresh").checked = true;
    byId("live-refresh").dispatchEvent(new Event("change"));
  }
}

async function loadJobs(cursor = "") {
  currentJobCursor = cursor;
  const generation = ++jobRequest;
  const client = byId("job-client").value;
  const list = byId("job-rows");
  list.replaceChildren();
  byId("more-jobs").hidden = true;
  byId("logs").hidden = true;
  if (!client) return;
  const { jobs, next_cursor: next } = await request("jobs?client=" + encodeURIComponent(client) + "&cursor=" + cursor);
  if (jobRequest !== generation) return;
  if (jobs.length === 0) add(list, "li", "No job records.");
  for (const job of jobs) {
    const row = add(list, "li", "");
    row.dataset.search = JSON.stringify(job);
    add(row, "code", job.job_id);
    const status = add(row, "span", job.state + (job.exit_code != null ? " · exit " + job.exit_code : ""));
    status.className = "job-state";
    status.dataset.state = job.state === "completed"
      ? (job.exit_code != null && job.exit_code !== 0 || job.signal != null && job.signal !== 0
        ? "failed" : job.exit_code === 0 ? "completed" : "uncertain")
      : job.state;
    const details = add(row, "span", [job.created_at ? new Date(job.created_at * 1000).toLocaleString() : "", job.client, job.cwd, job.executable || job.profile, job.execution_duration_ms != null ? "Job duration " + formatDuration(job.execution_duration_ms) : job.live_elapsed_ms != null ? "Live job elapsed " + formatDuration(job.live_elapsed_ms) : ""].filter(Boolean).join(" · "));
    details.className = "job-details";
    button(row, "Details", async () => showDetails(job));
    button(row, "Logs", async () => {
      const requestId = ++logRequest;
      const logs = await request("jobs/" + job.job_id + "/logs?client=" + encodeURIComponent(client));
      if (jobRequest !== generation || requestId !== logRequest) return;
      byId("output").textContent = "STDOUT\n" + (logs.stdout || "(empty)") + "\n\nSTDERR\n" + (logs.stderr || "(empty)") + (logs.stdout_truncated || logs.stderr_truncated ? "\n\n[Output truncated]" : "");
      byId("logs").hidden = false;
      byId("logs").open = true;
    });
    if (["starting", "running", "uncertain"].includes(job.state)) {
      button(row, "Cancel", async () => {
        if (!window.confirm("Cancel this job and its child processes?")) return;
        const result = await request("jobs/cancel", { client, job_id: job.job_id, confirm: true });
        await loadJobs();
        notice.textContent = "Job state: " + result.state;
      });
    }
  }
  nextPage = next;
  filterRows("job-rows", byId("job-filter").value);
  byId("more-jobs").hidden = !next;
}

async function editSkill(action, fields) {
  if (!window.confirm("Confirm skill action: " + action + "?")) return;
  await request("skills", { action, ...fields, confirm: true });
  await refresh();
}

async function loadSkills() {
  const { skills } = await request("skills");
  const list = byId("skill-rows");
  list.replaceChildren();
  byId("skill-document").hidden = true;
  if (!skills.length) add(list, "li", "No skills found.");
  for (const skill of skills) {
    const row = add(list, "li", "");
    row.dataset.search = JSON.stringify(skill);
    add(row, "strong", skill.name);
    add(row, "span", " · " + (skill.validation_error || skill.description) + " · " + (skill.enabled ? "Enabled" : "Disabled"));
    button(row,"Details",async () => showDetails(skill));
    if (skill.validation_error) continue;
    button(row, "Read", async () => {
      const skillText = await request("skills/read?name=" + encodeURIComponent(skill.name));
      byId("skill-document").textContent = skillText.document;
      byId("skill-document").hidden = false;
      showDetails({name:skill.name,document:skillText.document});
    });
    const toggle = skill.enabled ? "disable" : "enable";
    button(row, skill.enabled ? "Disable" : "Enable", () => editSkill(toggle, { name: skill.name }));
    if (byId("skill-client").options.length) {
      for (const action of ["grant", "revoke"]) {
        button(row, action === "grant" ? "Grant" : "Revoke", () =>
          editSkill(action, { name: skill.name, client: byId("skill-client").value }));
      }
    }
  }
  byId("skill-count").textContent = skills.length + " configured skills";
  filterRows("skill-rows",byId("skill-filter").value);
}
byId("skill-filter").addEventListener("input",event => filterRows("skill-rows",event.target.value));

byId("import-skill").addEventListener("submit", event => {
  event.preventDefault();
  editSkill("import", { source: byId("skill-source").value }).catch(error => notice.textContent = error.message);
});

async function editServer(action, fields) {
  if (!window.confirm("Confirm upstream action: " + action + " " + fields.id + "?")) return;
  const result = await request("servers", { action, ...fields, confirm: true });
  if (action === "probe") {
    const row = Array.from(byId("server-rows").children).find(row => row.dataset.server === fields.id);
    if (row) {
      const output = row.querySelector("output");
      output.dataset.health = result.health;
      output.textContent = result.health + (result.tools.length ? " · " + result.tools.length + " discovered tools" : "");
    }
    probedTools.set(fields.id, result.health === "ready" ? result.tools : []);
    updateProbedTools();
    showDetails(result);
    return;
  }
  await refresh();
}

async function loadServers() {
  const { servers } = await request("servers");
  const list = byId("server-rows");
  const select = byId("server-grant-server");
  list.replaceChildren();
  select.replaceChildren();
  probedTools.clear();
  registeredIds = new Set(servers.map(server => server.id));
  if (catalogLoaded) renderCatalog();
  if (!servers.length) add(list, "li", "No upstream servers configured.");
  for (const server of servers) {
    add(select, "option", server.id).value = server.id;
    const row = add(list, "li", "");
    row.dataset.server = server.id;
    add(row, "strong", server.id + " · " + server.transport);
    const health = add(row, "output", server.enabled ? "Registered · health unchecked" : "Disabled");
    health.className = "provider-health";
    health.dataset.health = server.enabled ? "unchecked" : "disabled";
    button(row, "Details", async () => showDetails({...server, probed_tools: probedTools.get(server.id) || null}));
    if (server.enabled) button(row, "Probe health and tools", () => editServer("probe", { id: server.id }));
    button(row, server.enabled ? "Disable" : "Enable", () => editServer(server.enabled ? "disable" : "enable", { id: server.id }));
    button(row, "Remove", () => editServer("remove", { id: server.id }));
  }
  updateProbedTools();
}

byId("server-transport").addEventListener("change", event => {
  const stdio = event.target.value === "add-stdio";
  byId("server-stdio-fields").hidden = !stdio;
  byId("server-http-fields").hidden = stdio;
});

byId("server-add").addEventListener("submit", async event => {
  event.preventDefault();
  const fields = Object.fromEntries(new FormData(event.currentTarget));
  const { action, id, url, connect_ip, command, argv } = fields;
  try {
    const data = action === "add-stdio" ? { id, command, arguments: JSON.parse(argv) } : { id, url, connect_ip };
    await editServer(action, data);
  } catch (error) { notice.textContent = error.message; }
});

byId("server-grant").addEventListener("submit", event => {
  event.preventDefault();
  const { action, client, id, tool } = Object.fromEntries(new FormData(event.currentTarget));
  editServer(action, { client, id, tool }).catch(error => notice.textContent = error.message);
});

function formatDuration(ms) {
  if (ms == null) return "—";
  if (ms === 0) return "<1 ms";
  if (ms < 1000) return ms + " ms";
  if (ms < 60000) return (ms / 1000).toFixed(3) + " s";
  return Math.floor(ms / 60000) + "m " + ((ms % 60000) / 1000).toFixed(3) + "s";
}

const activityClock = new Intl.DateTimeFormat("en-US", {
  hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: true
});

function formatLocalTime(unixSec) {
  return Number.isFinite(unixSec) ? activityClock.format(unixSec * 1000) : "—";
}

let activityRequest = 0;
async function loadActivity() {
  const generation = ++activityRequest;
  const funnel = byId("show-funnel-admission").checked;
  const data = await request(funnel ? "activity?funnel=1" : "activity");
  let previews = new Map();
  if (!remote) {
    try {
      const requested = performance.now();
      const trace = await request(traceEnabled ? "trace" : "trace?metadata=1");
      if (generation !== activityRequest) return;
      updateTraceState(trace, requested);
      if (traceEnabled) previews = new Map(trace.events.map(event => [event.call_id, commandPreview(event)]));
      byId("trace-toggle").textContent = traceEnabled ? "Stop and clear local trace" : "Capture local command trace";
      byId("trace-toggle").disabled = trace.busy;
      byId("trace-state").textContent = traceEnabled ? "Local trace active · up to 24 calls" : trace.busy ? "Another local session owns the trace" : "Trace off";
    } catch (error) {
      if (generation === activityRequest) {
        traceEnabled = false;
        clearTracePreviews();
        byId("trace-state").textContent = "Trace unavailable";
      }
    }
  }
  if (generation !== activityRequest) return;
  byId("activity-active").textContent = data.active_calls + " active calls";
  const headerCount = byId("header-active-count");
  if (headerCount) headerCount.textContent = data.active_calls;
  byId("audit-empty").hidden = data.events.length !== 0;
  const body = byId("audit-rows");
  body.replaceChildren();

  for (const event of data.events) {
    const tr = add(body, "tr", "");
    if (event.call_id) tr.dataset.callId = event.call_id;
    tr.dataset.search = JSON.stringify(event);
    const status = event.status === "failure" ? "failed" : event.status;
    add(tr, "td", formatLocalTime(event.time));
    add(tr, "td", event.tool);
    add(tr, "td", event.client || "—");

    const pill = add(add(tr, "td", ""), "span", status.toUpperCase());
    pill.className = "status-pill";
    pill.dataset.status = status;
    add(tr, "td", formatDuration(event.duration_ms));
    const preview = traceEnabled && previews.get(event.call_id);
    const summaryCell = add(tr, "td", preview || event.target_summary);
    if (preview) {
      summaryCell.dataset.tracePreview = "true";
      summaryCell.dataset.safeSummary = event.target_summary;
    }
    button(add(tr, "td", ""), "Details", async () => {
      let trace;
      if (!remote && traceEnabled && event.call_id) {
        const capture = await request("trace");
        trace = capture.events.find(record => record.call_id === event.call_id);
      }
      if (!byId("dashboard").hidden) showDetails(trace ? { ...event, local_trace: trace } : event);
    });
  }
  filterRows("audit-rows", byId("audit-filter").value);
}

byId("show-funnel-admission").addEventListener("change", () =>
  loadActivity().catch(error => notice.textContent = error.message));
byId("audit-ledger").addEventListener("toggle", async (event) => {
  const output = byId("audit-ledger-records");
  if (!event.target.open) {
    output.textContent = "";
    return;
  }
  try {
    const ledger = await request("audit");
    if (event.target.open) output.textContent = JSON.stringify(ledger.events, null, 2);
  } catch (error) { output.textContent = error.message; }
});

let liveBusy = false;
let liveTimer;
let lastSlowRefresh = 0;
byId("live-refresh").addEventListener("change", () => {
  clearInterval(liveTimer);
  if (!byId("live-refresh").checked) return;
  liveTimer = setInterval(async () => {
    if (!byId("live-refresh").checked) { clearInterval(liveTimer); return; }
    if (document.hidden || byId("dashboard").hidden || liveBusy) return;
    if (!["audit", "health", "jobs"].includes(activeTab)) return;
    if (activeTab === "jobs" && (!byId("logs").hidden || byId("job-controls").hidden)) return;
    if (activeTab !== "audit" && performance.now() - lastSlowRefresh < 3000) return;
    if (activeTab !== "audit") lastSlowRefresh = performance.now();
    liveBusy = true;
    try {
      if (activeTab === "audit") await loadActivity();
      else if (activeTab === "jobs") await loadJobs(currentJobCursor);
      else {
        const state = await request("status");
        const headerCount = byId("header-active-count");
        if (headerCount) headerCount.textContent = state.active_calls ?? 0;
        summary("metrics", [
          ["MCP listener", state.listener], ["MCP sessions", state.sessions], ["TCP connections", state.connections], ["Active MCP calls", state.active_calls],
          ["Memory", state.rss_kib == null ? "Unavailable" : (state.rss_kib / 1024).toFixed(1) + " MiB"],
          ["CPU", state.cpu_percent == null ? "Refresh for sample" : state.cpu_percent.toFixed(2) + "%"],
          ["Audit", state.audit || "Unconfigured"]
        ]);
      }
    } catch (error) { notice.textContent = error.message; }
    finally { liveBusy = false; }
  }, 1000);
});

async function pairBrowser(token) {
  try {
    const pairing = await request("pair", { pairing_token: token });
    csrf = pairing.csrf;
    if (remote) sessionStorage.setItem(proofKey, csrf);
    byId("pairing-code").value = "";
    history.replaceState(null, "", "/dashboard");
    await refresh();
  } catch (error) {
    showPair();
    notice.textContent = error.message;
  }
}
byId("pair").addEventListener("submit", event => {
  event.preventDefault();
  pairBrowser(byId("pairing-code").value.trim());
});
byId("refresh").addEventListener("click", () => refresh().catch(error => notice.textContent = error.message));
byId("job-client").addEventListener("change", () => loadJobs().catch(error => notice.textContent = error.message));
byId("more-jobs").addEventListener("click", () => loadJobs(nextPage).catch(error => notice.textContent = error.message));
byId("logout").addEventListener("click", async () => {
  try {
    await request("logout", {});
    showPair();
    notice.textContent = "Signed out.";
  } catch (error) { notice.textContent = error.message; }
});
const automaticPair = location.hash.match(/^#pair=([a-f0-9]{48})$/);
if (automaticPair) {
  // Remove the fragment before any request or session navigation.
  history.replaceState(null, "", "/dashboard/login");
  pairBrowser(automaticPair[1]);
} else {
  refresh().catch(error => notice.textContent = error.status === 401 ? "" : error.message);
}
