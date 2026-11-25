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
let diagnosticsRequest = 0;
let diagnosticsBusy = false;
let diagnosticsSample = 0;
let liveBusy = false;
let liveTimer;
let lastSlowRefresh = 0;
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
  if (typeof args.job_id === "string") return "Job " + args.job_id;
  if (Array.isArray(args.sections)) return args.sections.join(", ");
  return null;
}
function renderTraceControl(message="",busy=false) {
  const control=byId("trace-toggle");
  const label=message|| (traceEnabled?"Clear local trace":"Enable local trace");
  control.title=label;
  control.setAttribute("aria-label",label);
  control.setAttribute("aria-pressed",String(traceEnabled));
  control.disabled=busy;
  byId("trace-state").textContent=message;
}
function updateTraceState(trace, requested) {
  clearTimeout(traceExpiryTimer);
  traceEnabled = trace.enabled === true && Number.isFinite(trace.remaining_ms) &&
    trace.remaining_ms > performance.now() - requested;
  if (!traceEnabled) clearTracePreviews();
  else traceExpiryTimer = setTimeout(() => {
    traceEnabled = false;
    clearTracePreviews();
    renderTraceControl("Trace expired");
  }, Math.max(0, trace.remaining_ms - (performance.now() - requested)));
}
byId("trace-controls").hidden = remote;
byId("diagnostics-nav").hidden = remote;
const diagnosticNames = {resources:"Resources",gpu:"Graphics",storage:"Storage",network:"Network",audio:"Audio",bluetooth:"Bluetooth",desktop:"Display connectors",sway:"Sway",services:"Services"};
const fieldNames = {cpu:"CPU",io:"I/O",mtu:"MTU",pci_address:"PCI address",vendor_id:"Vendor ID",device_id:"Device ID",rx_bytes:"Received (total)",tx_bytes:"Sent (total)",busy_percent:"GPU busy",capacity_percent:"Capacity",temperature_millicelsius:"Temperature",memory_available_kib:"Available RAM",memory_total_kib:"Total RAM",swap_free_kib:"Free swap",swap_total_kib:"Total swap",MainPID:"PID",MemoryCurrent:"Memory",TasksCurrent:"Tasks",NRestarts:"Restarts",UnitFileState:"Startup",ActiveState:"State",SubState:"Service state",LoadState:"Load state"};
function diagLabel(key) { return fieldNames[key] || key.replace(/([a-z])([A-Z])/g,"$1 $2").replaceAll("_"," ").replace(/^./,c=>c.toUpperCase()); }
function diagBytes(n) {
  if (!Number.isFinite(n) || n < 0) return "Unavailable";
  const units=["B","KiB","MiB","GiB","TiB"];
  let i=0; while(n>=1024 && i<units.length-1){n/=1024;i++;}
  return n.toFixed(i===0?0:2)+" "+units[i];
}
function diagDuration(n) {
  if (!Number.isFinite(n) || n<0) return "Unavailable";
  n=Math.floor(n);
  return [Math.floor(n/86400)?Math.floor(n/86400)+"d":"",Math.floor(n%86400/3600)+"h",Math.floor(n%3600/60)+"m"].filter(Boolean).join(" ");
}
function diagValue(key,value) {
  if(value===null || value===undefined || value==="") return "Unavailable";
  if(typeof value==="boolean") return value?"Yes":"No";
  if(key==="online" && (value===0||value===1)) return value?"Online":"Offline";
  if(key==="temperature_millicelsius" && Number.isFinite(value)) return (value/1000).toFixed(1)+" °C";
  if(key.endsWith("_kib") && Number.isFinite(value)) return diagBytes(value*1024);
  if((key.endsWith("_bytes") || key==="MemoryCurrent") && value!=="" && Number.isFinite(Number(value))) return diagBytes(Number(value));
  if(key.endsWith("_percent") && Number.isFinite(value)) return value+"%";
  if(key==="uptime_seconds") return diagDuration(value);
  if(key==="load_average" && Array.isArray(value)) return value.join(" / ");
  if(key==="current_mode" && value && typeof value==="object" && Number.isFinite(value.width) && Number.isFinite(value.height)) return value.width+" × "+value.height+(Number.isFinite(value.refresh)?" · "+(value.refresh/1000).toFixed(2)+" Hz":"");
  return String(value);
}
function diagCard(grid,title,tag) {
  const card=add(grid,"article","");card.className="diag-card";
  const header=add(card,"div","");header.className="diag-card-heading";
  add(header,"h3",title);
  if(tag) add(header,"span",tag).className="diag-tag";
  return card;
}
function diagFields(card,record,exclude=[]) {
  const list=add(card,"dl","");list.className="diag-fields";
  function field(key,value,label,depth) {
    if(value && typeof value==="object" && !Array.isArray(value) && key!=="current_mode" && depth<5) {
      for(const [k,v] of Object.entries(value)) field(k,v,label+" / "+diagLabel(k),depth+1);
      return;
    }
    const row=add(list,"div","");add(row,"dt",label);
    const display=Array.isArray(value)?(value.length?value.map(x=>typeof x==="object"?JSON.stringify(x):String(x)).join(", "):"None"):diagValue(key,value);
    add(row,"dd",display);
  }
  for(const [key,value] of Object.entries(record||{})) {
    if(["source","items","truncated","available","reason",...exclude].includes(key)) continue;
    field(key,value,diagLabel(key),0);
  }
  if(!list.children.length) list.remove();
}
function diagMeter(card,label,used,total,format=diagBytes) {
  if(!Number.isFinite(used)||!Number.isFinite(total)||total<=0||used<0||used>total) return;
  const top=add(card,"div","");top.className="diag-meter-label";
  add(top,"span",label);add(top,"strong",Math.round(used/total*100)+"%");
  const meter=add(card,"progress","");meter.max=total;meter.value=used;meter.setAttribute("aria-label",label);
  add(card,"p",format(used)+" / "+format(total)).className="diag-caption";
}
function diagInventory(grid,title,inventory,identify,decorate) {
  if(!inventory || inventory.available===false) {
    const card=diagCard(grid,title);add(card,"p",inventory?.reason||"Unavailable").className="diag-caption";return;
  }
  const items=Array.isArray(inventory.items)?inventory.items:[];
  const group=add(grid,"section","");group.className="diag-group";
  const heading=add(group,"h3",title+" · "+items.length+(inventory.truncated?"+":""));
  heading.className="diag-group-title";
  const inner=add(group,"div","");inner.className="diagnostic-grid";
  if(!items.length){add(inner,"p","None detected").className="diag-caption";return;}
  for(const item of items) {
    const [name,tag,exclude]=identify(item);
    const card=diagCard(inner,name,tag);
    if(decorate) decorate(card,item);
    diagFields(card,item,exclude);
  }
}
function renderDiagnostics(section,v) {
  const grid=byId("diagnostics-summary");grid.replaceChildren();
  if(!v||v.available===false){add(diagCard(grid,diagnosticNames[section]),"p",v?.reason||"Unavailable");return;}
  const identity=(key,tag)=>item=>[String(item[key]??"Unknown"),item[tag]===undefined||item[tag]===null?"":diagValue(tag,item[tag]),[key,tag]];
  const inventory=(title,data,key,tag,decorate)=>diagInventory(grid,title,data,identity(key,tag),decorate);
  const simple=(title,data)=>{const card=diagCard(grid,title);if(data&&typeof data==="object")diagFields(card,data);else add(card,"p",data??"Unavailable");return card;};
  if(section==="resources"){
    const cpu=diagCard(grid,"Processor");add(cpu,"strong",v.cpu_model??"Unavailable").className="diag-value";
    diagFields(cpu,{logical_cpus:v.logical_cpus,load_average:v.load_average,architecture:v.architecture});
    const memory=diagCard(grid,"Memory");add(memory,"strong",diagValue("memory_total_kib",v.memory_total_kib)).className="diag-value";
    if(Number.isFinite(v.memory_total_kib)&&Number.isFinite(v.memory_available_kib)) diagMeter(memory,"Used",(v.memory_total_kib-v.memory_available_kib)*1024,v.memory_total_kib*1024);
    diagFields(memory,{memory_available_kib:v.memory_available_kib});
    const swap=diagCard(grid,"Swap");add(swap,"strong",diagValue("swap_total_kib",v.swap_total_kib)).className="diag-value";
    if(Number.isFinite(v.swap_total_kib)&&Number.isFinite(v.swap_free_kib)) diagMeter(swap,"Used",(v.swap_total_kib-v.swap_free_kib)*1024,v.swap_total_kib*1024);
    diagFields(swap,{swap_free_kib:v.swap_free_kib});
    simple("System",{platform:v.platform,uptime_seconds:v.uptime_seconds});
    if(v.pressure){
      const card=diagCard(grid,"Resource pressure","10s average");card.classList.add("diag-wide");
      for(const [key,raw] of Object.entries(v.pressure)){
        const match=typeof raw==="string"?raw.match(/(?:^|\n)some\s+avg10=([\d.]+)/):null;
        const full=typeof raw==="string"?raw.match(/(?:^|\n)full\s+avg10=([\d.]+)/):null;
        const row=add(card,"div","");row.className="pressure-row";
        add(row,"span",diagLabel(key));add(row,"strong",match?match[1]+"% stalled":"Unavailable");
        if(full)add(row,"small","Full: "+full[1]+"%");
      }
      add(card,"p","Linux PSI: time stalled, not utilization. Full averages in Raw JSON.").className="diag-caption";
    }
    if(v.workspace_filesystem) simple("Workspace filesystem",v.workspace_filesystem);
    inventory("Thermal sensors",v.thermal,"type","id");
    inventory("Power supplies",v.power,"name","type",(c,x)=>{if(Number.isFinite(x.capacity_percent))diagMeter(c,"Charge",x.capacity_percent,100,n=>n+"%");});
  }else if(section==="gpu"){
    inventory("Graphics devices",v,"pci_address","runtime_status",(c,x)=>{if(Number.isFinite(x.busy_percent))diagMeter(c,"GPU busy",x.busy_percent,100,n=>n+"%");diagMeter(c,"VRAM",x.vram_used_bytes,x.vram_total_bytes);});
  }else if(section==="storage"){
    if(v.workspace_filesystem) {
      const card=simple("Workspace filesystem",v.workspace_filesystem);
      const {total_bytes,available_bytes}=v.workspace_filesystem;
      if(Number.isFinite(total_bytes)&&Number.isFinite(available_bytes)) diagMeter(card,"Used",total_bytes-available_bytes,total_bytes);
    }
    inventory("Block devices",v.devices,"name","model");
  }else if(section==="network"){
    inventory("Network interfaces",v,"interface","state");
  }else if(section==="audio"){
    inventory("Sound cards",v,"card","id");
    if(v.session?.available===false) simple("Audio session",v.session.reason||"Unavailable");
    else {
      inventory("Output devices",v.session?.sinks,"description","state");
      inventory("Input devices",v.session?.sources,"description","state");
    }
  }else if(section==="bluetooth"){
    inventory("Adapters",v,"adapter","driver");
    const connected=diagCard(grid,"Connected devices");
    if(v.session?.available===true){
      const names=v.session.connected_names||[];
      if(!names.length)add(connected,"p","No connected devices");
      else for(const name of names)add(connected,"p",name).className="diag-device";
    }else add(connected,"p",v.session?.reason||"Unavailable");
  }else if(section==="desktop"){
    inventory("Display connectors",v,"connector","status");
  }else if(section==="sway"){
    inventory("Outputs",v.outputs,"name","active");
    inventory("Workspaces",v.workspaces,"name","focused");
  }else if(section==="services"){
    simple("Veyl gateway",v.veyl);
    inventory("Failed user units",v.user_failed,"unit","sub");
    inventory("Failed system units",v.system_failed,"unit","sub");
  }
  if(!grid.children.length)add(diagCard(grid,diagnosticNames[section]||section),"p","No data available");
}
async function loadDiagnostics() {
  if (remote || activeTab !== "diagnostics" || byId("dashboard").hidden || document.hidden) return;
  const section = byId("diagnostics-section").value;
  const generation = ++diagnosticsRequest;
  diagnosticsBusy = true;
  byId("diagnostics-state").textContent = "Updating…";
  try {
    const data = await request("diagnostics?section=" + encodeURIComponent(section));
    if (generation !== diagnosticsRequest || activeTab !== "diagnostics" || byId("dashboard").hidden) return;
    byId("diagnostics-output").textContent = JSON.stringify(data, null, 2);
    renderDiagnostics(section, data.sections?.[section]);
    byId("diagnostics-state").textContent = "Updated " + new Date().toLocaleTimeString();
    diagnosticsSample = performance.now();
  } catch (error) {
    if (generation === diagnosticsRequest && activeTab === "diagnostics") byId("diagnostics-state").textContent = error.message;
  } finally {
    if (generation === diagnosticsRequest) diagnosticsBusy = false;
  }
}
byId("diagnostics-form").addEventListener("submit", event => event.preventDefault());
byId("diagnostics-section").addEventListener("change", () => {
  byId("diagnostics-summary").replaceChildren();
  byId("diagnostics-output").textContent = "Loading…";
  loadDiagnostics();
});
byId("trace-toggle").addEventListener("click", async () => {
  const enable = !traceEnabled;
  if (enable && !window.confirm("Capture command arguments and responses for 10 minutes in this local session? They may contain secrets. No trace is written to disk.")) return;
  traceRequest++;
  if (!enable) {
    traceEnabled = false;
    clearTimeout(traceExpiryTimer);
    clearTracePreviews();
  }
  try {
    const state = await request("trace", {enabled: enable, confirm:true});
    traceEnabled = state.enabled;
    renderTraceControl();
    if (activeTab === "jobs") await loadJobs(currentJobCursor, true);
    else await loadActivity();
  } catch(error) { notice.textContent=error.message; }
});
const themeModes = ["system", "dark", "light"];
let theme = "system";
try { const saved = localStorage.getItem("veyl-theme"); if (themeModes.includes(saved)) theme = saved; } catch {}
function applyTheme() {
  document.documentElement.dataset.theme = theme;
  const dark=theme==="dark" || (theme==="system" && matchMedia("(prefers-color-scheme: dark)").matches);
  byId("theme-glyph").setAttribute("d",dark?"M12 4V2 M12 22v-2 M4 12H2 M22 12h-2 M6.3 6.3 4.9 4.9 M19.1 19.1l-1.4-1.4 M6.3 17.7l-1.4 1.4 M19.1 4.9l-1.4 1.4 M17 12a5 5 0 1 1-10 0 5 5 0 0 1 10 0":"M20 15a9 9 0 0 1-11-11 9 9 0 1 0 11 11z");
  const label="Switch to "+(dark?"light":"dark")+" theme";
  byId("theme").title=label;
  byId("theme").setAttribute("aria-label",label);
}
applyTheme();
matchMedia("(prefers-color-scheme: dark)").addEventListener("change",()=>{if(theme==="system")applyTheme();});
byId("theme").addEventListener("click", () => {
  const dark = theme === "dark" || (theme === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
  theme = dark ? "light" : "dark";
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
  const changed = activeTab !== id;
  activeTab = id;
  if (changed) { diagnosticsRequest++; diagnosticsBusy = false; }
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
  if (id === "diagnostics") loadDiagnostics();
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
  diagnosticsRequest++;
  diagnosticsBusy = false;
  byId("diagnostics-summary").replaceChildren();
  byId("diagnostics-output").textContent="Loading diagnostics…";
  if (byId("detail-dialog").open) byId("detail-dialog").close();
  activityRequest++;
  jobRequest++;
  logRequest++;
  traceRequest++;
  byId("job-rows").replaceChildren();
  byId("logs").hidden = true;
  byId("audit-ledger").open = false;
  byId("audit-rows").replaceChildren();
  liveInitialized = false;
  clearInterval(liveTimer);
  clearTimeout(traceExpiryTimer);
  traceEnabled = false;
  renderTraceControl();
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
// Bundled decorative category icons; never load third-party image URLs.
function catalogIcon(entry) {
  const ns = "http://www.w3.org/2000/svg";
  const key = [entry.category, entry.name, entry.id].join(" ").toLowerCase();
  const shape = entry.type === "skill" ? "M4 4h7a3 3 0 0 1 3 3v13a4 4 0 0 0-4-2H4z M14 7a3 3 0 0 1 3-3h3v14h-2a4 4 0 0 0-4 2" :
    /reverse|debug/.test(key) ? "M4 7h16 M7 4v6 M17 4v6 M6 14l3 3-3 3 M18 14l-3 3 3 3 M10 17h4" :
    /browser|web|playwright/.test(key) ? "M3 5h18v14H3z M3 9h18 M6 7h1 M9 7h1 M12 7h1" :
    /filesystem|file|storage/.test(key) ? "M3 7h7l2 2h9v11H3z M3 7V5h7l2 2h7" :
    /database|memory|vector/.test(key) ? "M4 6c0-4 16-4 16 0s-16 4-16 0v12c0 4 16 4 16 0V6 M4 12c0 4 16 4 16 0" :
    /git|github|version control/.test(key) ? "M7 3a2 2 0 1 0 0 4 2 2 0 0 0 0-4 M7 7v10 M7 17a2 2 0 1 0 0 4 2 2 0 0 0 0-4 M17 3a2 2 0 1 0 0 4 2 2 0 0 0 0-4 M17 7v3c0 4-3 5-10 5" :
    /search|research/.test(key) ? "M15 10a5 5 0 1 1-10 0 5 5 0 0 1 10 0 M14 14l6 6" :
    /terminal|code|developer|programming/.test(key) ? "M3 5h18v14H3z M7 9l3 3-3 3 M13 15h4" :
    "M9 3v5 M15 3v5 M7 8h10v3a5 5 0 0 1-10 0z M12 16v5";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  svg.setAttribute("class", "catalog-icon");
  const path = document.createElementNS(ns, "path");
  path.setAttribute("d", shape);
  svg.append(path);
  return svg;
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
    top.className = "catalog-heading";
    const mark = add(top, "div", "");
    mark.className = "catalog-mark";
    mark.append(catalogIcon(entry));
    const heading = add(top, "div", "");
    heading.className = "catalog-title";
    add(heading, "span", entry.type).className = "catalog-kind";
    add(heading, "h3", entry.name);
    add(card, "span", registeredIds.has(entry.id) ? "Matching registered ID — verify identity" : "Not registered").className = "catalog-meta";
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

function renderStatus(state) {
  summary("metrics", [
    ["MCP listener", state.listener], ["MCP sessions", state.sessions], ["TCP connections", state.connections], ["Active MCP calls", state.active_calls],
    ["Memory", state.rss_kib == null ? "Unavailable" : (state.rss_kib / 1024).toFixed(1) + " MiB"],
    ["CPU", state.cpu_percent == null ? "Waiting for sample" : state.cpu_percent.toFixed(2) + "%"],
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
  summary("protected-summary", [
    ["Masked state", paths.state_directory || "Broad YOLO inactive"],
    ["Masked skill store", paths.skills_directory || "Unconfigured"],
    ["Masked paths", ((paths.default_masked || []).length + (paths.extra_masked || []).length) + " rules"],
    ["Read-only paths", ((paths.default_readonly || []).length + (paths.extra_readonly || []).length) + " rules"],
  ]);
  const modes = modeLabels;
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
  renderStatus(state);
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
    lastSlowRefresh = performance.now();
    liveInitialized = true;
    startLive();
  }
}

async function loadJobs(cursor = "", preserveLogs = false) {
  currentJobCursor = cursor;
  const generation = ++jobRequest;
  const client = byId("job-client").value;
  const list = byId("job-rows");
  if (!preserveLogs) byId("logs").hidden = true;
  if (!client) { list.replaceChildren(); byId("more-jobs").hidden = true; return; }
  const { jobs, next_cursor: next } = await request("jobs?client=" + encodeURIComponent(client) + "&cursor=" + cursor);
  const trace = await localTrace();
  if (jobRequest !== generation || byId("dashboard").hidden) return;
  list.replaceChildren();
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
    const preview = traceEnabled && commandPreview(jobTrace(trace, job));
    if (preview) {
      const command = add(row, "code", preview);
      command.className = "job-command";
      command.dataset.tracePreview = "true";
      command.dataset.safeSummary = "Command preview expired";
    }
    button(row, "Details", async () => {
      const capture = await localTrace();
      const record = traceEnabled && jobTrace(capture, job);
      if (!byId("dashboard").hidden) showDetails(record ? {...job, local_trace:record} : {...job, trace_note:"No captured launch arguments; enable local trace before starting a new job."});
    });
    button(row, "Logs", async () => {
      const requestId = ++logRequest;
      const logs = await request("jobs/" + job.job_id + "/logs?client=" + encodeURIComponent(client));
      if (requestId !== logRequest || byId("job-client").value !== client || activeTab !== "jobs" || byId("dashboard").hidden) return;
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
  const trace = await localTrace();
  const previews = new Map(trace.map(event => [event.call_id, commandPreview(event)]));
  if (generation !== activityRequest || byId("dashboard").hidden) return;
  byId("activity-active").textContent = data.active_calls + " active calls";
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
        const capture = await localTrace();
        trace = traceEnabled && capture.find(record => record.call_id === event.call_id);
      }
      if (!byId("dashboard").hidden) showDetails(trace ? { ...event, local_trace: trace } : {...event, trace_note:"Metadata only; enable local trace to capture future calls."});
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

const modeLabels = { standard: "Standard", scoped_yolo: "Scoped YOLO (legacy)", broad_yolo: "YOLO", yolo: "YOLO", full: "FULL", disabled: "Disabled" };
function modeSummary(clients) {
  const groups = new Map();
  for (const c of clients) {
    const mode = c.disabled ? "Disabled" : c.expired ? "Expired" : modeLabels[c.mode] || c.mode;
    if (!groups.has(mode)) groups.set(mode, []);
    groups.get(mode).push(c.id);
  }
  return Array.from(groups, ([mode, ids]) => mode + ": " + ids.join(", ")).join(" · ") || "No clients";
}
let traceRequest = 0;
async function localTrace() {
  if (remote || byId("dashboard").hidden) return [];
  const generation = ++traceRequest;
  try {
    const requested = performance.now();
    const trace = await request(traceEnabled ? "trace" : "trace?metadata=1");
    if (generation !== traceRequest || byId("dashboard").hidden) return [];
    updateTraceState(trace, requested);
    renderTraceControl(trace.busy?"Trace in another session":traceEnabled?"Clear local trace":"Enable local trace",trace.busy);
    byId("job-trace-state").textContent = traceEnabled ? "Command previews from this local trace; historical jobs may not have captured arguments." : "Enable local trace to capture future job command arguments.";
    return traceEnabled ? trace.events : [];
  } catch (error) {
    if (generation === traceRequest) {
      traceEnabled = false;
      clearTracePreviews();
      renderTraceControl("Trace unavailable");
    }
    return [];
  }
}
function jobTrace(events, job) {
  return events.find(event => event.job_id === job.job_id && event.client === job.client);
}
function startLive() {
  clearInterval(liveTimer);
  liveTimer = setInterval(async () => {
    if (document.hidden || byId("dashboard").hidden || liveBusy) return;
    const now = performance.now();
    const tab = activeTab;
    const statusDue = now - lastSlowRefresh >= 5000;
    const diagnosticsDue = tab === "diagnostics" && !diagnosticsBusy && now - diagnosticsSample >= 10000;
    if (!statusDue && !diagnosticsDue && tab !== "audit" && tab !== "jobs") return;
    liveBusy = true;
    try {
      if (statusDue) {
        lastSlowRefresh = now;
        const state = await request("status");
        if (byId("dashboard").hidden) return;
        renderStatus(state);
      }
      if (tab === activeTab) {
        if (tab === "audit") await loadActivity();
        else if (tab === "jobs" && !byId("job-controls").hidden) await loadJobs(currentJobCursor, true);
        else if (diagnosticsDue) await loadDiagnostics();
      }
    } catch (error) { notice.textContent = error.message; }
    finally { liveBusy = false; }
  }, 1000);
}

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
