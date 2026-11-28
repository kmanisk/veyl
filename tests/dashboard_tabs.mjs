// Disposable Chromium DevTools test. No browser automation dependency.
// URL (including the one-use pairing fragment) arrives only over stdin.
import {spawn} from "node:child_process";
import {mkdtemp, readFile, rm, writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import assert from "node:assert/strict";
const browser = process.argv[2];
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const url = Buffer.concat(chunks).toString().trim();
assert.match(url,/^http:\/\/127\.0\.0\.1:\d+\/dashboard\/login#pair=[a-f0-9]{48}$/);
const profile = await mkdtemp(join(tmpdir(),"veyl-tabs-"));
const child = spawn(browser,["--headless","--incognito","--ozone-platform=headless",
  "--disable-gpu","--disable-background-networking","--disable-component-update",
  "--disable-extensions","--no-proxy-server","--password-store=basic","--no-first-run","--no-default-browser-check",
  "--remote-debugging-port=0","--user-data-dir="+profile,"about:blank"],{stdio:"ignore"});
const delay = ms => new Promise(r=>setTimeout(r,ms));
async function until(fn, timeout=8000) {
  const end = Date.now()+timeout;
  while(Date.now()<end) {
    try {const v=await fn();if(v)return v;}catch{}
    await delay(100);
  }
  throw Error("Browser test condition timed out");
}
let ws;
try {
  const port = await until(async()=>Number((await readFile(join(profile,"DevToolsActivePort"),"utf8")).split("\n")[0]));
  const page = await until(async()=> (await (await fetch("http://127.0.0.1:"+port+"/json/list")).json()).find(p=>p.type==="page"));
  ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=reject;});
  let serial=0;
  const pending=new Map();
  ws.onmessage=event=>{
    const result=JSON.parse(event.data);
    if(result.id && pending.has(result.id)){
      const {resolve,reject,timer}=pending.get(result.id);
      pending.delete(result.id);clearTimeout(timer);
      if(result.error)reject(Error("CDP command failed"));else resolve(result.result);
    }
  };
  function send(method,params={}) {
    return new Promise((resolve,reject)=>{
      const id=++serial;
      const timer=setTimeout(()=>{pending.delete(id);reject(Error("CDP timeout"));},4000);
      pending.set(id,{resolve,reject,timer});ws.send(JSON.stringify({id,method,params}));
    });
  }
  async function evaluate(expression){
    const response=await send("Runtime.evaluate",{expression,returnByValue:true});
    if(response.exceptionDetails)throw Error("Page script evaluation failed");
    return response.result.value;
  }
  const screenshotDir = process.env.VEYL_SCREENSHOTS;
  const openTab = id => evaluate(`document.querySelector('nav a[href="#${id}"]').click()`);
  async function capture(id, width, height) {
    if (!screenshotDir) return;
    await send("Emulation.setDeviceMetricsOverride", {width,height,deviceScaleFactor:1,mobile:width < 600});
    await openTab(id);
    await until(() => evaluate(`!document.querySelector("#page-${id}").classList.contains("inactive-tab")`));
    await evaluate("scrollTo(0,0)");
    const {data} = await send("Page.captureScreenshot", {format:"png"});
    await writeFile(join(screenshotDir, id + "-" + width + ".png"), Buffer.from(data,"base64"));
  }
  await send("Emulation.setTimezoneOverride", {timezoneId:"America/New_York"});
  await send("Page.navigate",{url});
  await until(()=>evaluate("!document.querySelector('#dashboard')?.hidden && document.querySelector('[role=tab][aria-selected=true]')?.hash === '#health'"));
  assert.equal(await evaluate("location.hash"),"");
  const pairingCode = url.split("#pair=")[1];
  assert.ok(!(await evaluate("document.documentElement.innerHTML.includes(" + JSON.stringify(pairingCode) + ")")));
  const visible = "Array.from(document.querySelectorAll('[role=tabpanel]')).filter(p=>getComputedStyle(p).display!=='none').map(p=>p.querySelector('h1,h2').id)";
  assert.deepEqual(await evaluate(visible),["health"]);
  for(const id of ["jobs","clients","audit","skills","servers","marketplace","custom","configuration","protection","health"]){
    await evaluate("document.querySelector('nav a[href=\"#"+id+"\"]').click()");
    assert.deepEqual(await evaluate(visible),[id]);
    assert.equal(await evaluate("document.querySelector('[role=tab][aria-selected=true]').hash"),"#"+id);
  }
  await evaluate("document.querySelector('nav a[href=\"#health\"]').dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowDown',bubbles:true}))");
  assert.deepEqual(await evaluate(visible),["audit"]);
  await evaluate("document.dispatchEvent(new KeyboardEvent('keydown',{key:'/',bubbles:true}))");
  assert.equal(await evaluate("document.activeElement.id"),"audit-filter");
  await until(()=>evaluate("document.querySelectorAll('#audit-rows tr[data-call-id]').length === 3"));
  assert.equal(await evaluate("new Set(Array.from(document.querySelectorAll('#audit-rows tr'), row => row.dataset.callId)).size"), 3);
  assert.equal(await evaluate("document.querySelector('#activity-active').textContent"), "0 active calls");
  assert.equal(await evaluate("document.querySelectorAll('#audit-rows [data-status=failed]').length"), 1);
  assert.ok(!(await evaluate("document.querySelector('#audit-rows').innerHTML")).includes("BROWSER_SYNTHETIC_CREDENTIAL"));
  assert.match(await evaluate("document.querySelector('#audit-rows td').textContent"), /[AP]M$/);
  assert.equal(await evaluate("document.querySelector('#live-refresh') === null"), true);
  assert.equal(await evaluate("document.querySelector('#live-state') === null && document.querySelector('#header-status') === null"),true);
  assert.equal(await evaluate("document.querySelector('#trace-toggle svg') !== null && document.querySelector('#trace-toggle').getAttribute('aria-pressed') === 'false'"),true);
  assert.equal(await evaluate("formatDuration(42)"), "42 ms");
  assert.equal(await evaluate("formatDuration(1234)"), "1.234 s");
  assert.equal(await evaluate("formatDuration(62345)"), "1m 2.345s");
  assert.equal(await evaluate("commandPreview({arguments:{command:'printf synthetic'}})"), "printf synthetic");
  assert.equal(await evaluate("commandPreview({arguments:{argv:['echo','synthetic']}})"), '["echo","synthetic"]');
  await evaluate("document.querySelector('#show-funnel-admission').click()");
  await until(()=>evaluate("document.querySelectorAll('#audit-rows tr[data-call-id]').length === 3"));
  await evaluate("document.querySelector('#audit-ledger summary').click()");
  await until(()=>evaluate("document.querySelector('#audit-ledger-records').textContent.includes('sequence')"));
  assert.ok(!(await evaluate("document.querySelector('#audit-ledger-records').textContent")).includes('duration_ms'));
  await evaluate("document.querySelector('#audit-ledger summary').click()");
  await evaluate("document.querySelector('#audit-rows button').click()");
  assert.equal(await evaluate("document.querySelector('#detail-dialog').open"),true);
  const details = JSON.parse(await evaluate("document.querySelector('#detail-json').textContent"));
  assert.equal(details.tool, "system_info");
  assert.match(details.call_id, /^call-/);
  assert.ok(Number.isInteger(details.duration_ms));
  await evaluate("document.querySelector('#detail-close').click()");
  assert.equal(await evaluate("document.querySelector('#detail-dialog').open"),false);
  await evaluate("theme='light';applyTheme();document.querySelector('#theme').click()");
  assert.equal(await evaluate("document.documentElement.dataset.theme"),"dark");
  assert.equal(await evaluate("document.querySelector('#theme svg') !== null"),true);
  await evaluate("document.querySelector('#theme').click()");
  assert.equal(await evaluate("document.documentElement.dataset.theme"),"light");
  assert.equal(await evaluate("document.querySelector('link[rel=icon]').getAttribute('href')"),"/dashboard/icon.svg");
  await evaluate("document.querySelector('nav a[href=\"#diagnostics\"]').click()");
  assert.deepEqual(await evaluate(visible),["diagnostics"]);
  await until(()=>evaluate("document.querySelector('#diagnostics-output').textContent.includes('memory_total_kib')"));
  assert.match(await evaluate("document.querySelector('#diagnostics-summary').textContent"), /GiB/);
  await evaluate("document.querySelector('#diagnostics-section').value='storage';document.querySelector('#diagnostics-section').dispatchEvent(new Event('change'))");
  await until(()=>evaluate("!!JSON.parse(document.querySelector('#diagnostics-output').textContent).sections.storage"));
  assert.equal(await evaluate("document.querySelector('#diagnostics-run') === null"), true);
  for (const section of ["resources","gpu","storage","network","audio","bluetooth","desktop","sway","services"]) {
    await evaluate("document.querySelector('#diagnostics-section').value="+JSON.stringify(section)+";document.querySelector('#diagnostics-section').dispatchEvent(new Event('change'))");
    await until(()=>evaluate("(()=>{try{return !!JSON.parse(document.querySelector('#diagnostics-output').textContent).sections["+JSON.stringify(section)+"] && document.querySelectorAll('#diagnostics-summary .diag-card').length>0}catch{return false}})()"));
    assert.equal(await evaluate("document.querySelector('#diagnostics-summary').textContent.includes('entries · see Raw JSON')"),false);
  }
  await evaluate("renderDiagnostics('network',{available:true,items:[{interface:'test0',state:'up',mtu:1500,carrier:true,rx_bytes:1048576,tx_bytes:2048}]})");
  assert.match(await evaluate("document.querySelector('#diagnostics-summary').textContent"),/test0.*1.00 MiB.*2.00 KiB/);
  await evaluate("renderDiagnostics('gpu',{available:true,items:[{pci_address:'test',runtime_status:'suspended',busy_percent:null,vram_total_bytes:null}]})");
  assert.equal(await evaluate("document.querySelectorAll('#diagnostics-summary progress').length"),0);
  await evaluate("renderDiagnostics('sway',{available:false,reason:'No compositor'})");
  assert.match(await evaluate("document.querySelector('#diagnostics-summary').textContent"),/No compositor/);
  assert.match(await evaluate("modeSummary([{id:'chatgpt',mode:'yolo'},{id:'codex',mode:'standard'},{id:'agy',mode:'standard'}])"), /YOLO: chatgpt · Standard: codex, agy/);
  assert.equal(await evaluate("commandPreview(jobTrace([{job_id:'a',client:'x',arguments:{command:'echo test'}}],{job_id:'a',client:'x'}))"), "echo test");
  assert.equal(await evaluate("jobTrace([{job_id:'a',client:'x'}],{job_id:'a',client:'y'}) === undefined"), true);
  await evaluate("document.querySelector('nav a[href=\"#marketplace\"]').click()");
  await until(()=>evaluate("document.querySelectorAll('#catalog-cards article').length === 20"));
  assert.match(await evaluate("document.querySelector('#catalog-count').textContent"), /106 matching resources/);
  assert.equal(await evaluate("document.querySelectorAll('#catalog-cards article svg.catalog-icon[aria-hidden=true]').length"),20);
  assert.ok(await evaluate("new Set(Array.from(document.querySelectorAll('#catalog-cards svg path'),p=>p.getAttribute('d'))).size > 3"));
  assert.equal(await evaluate("document.querySelectorAll('#catalog-cards img, #catalog-cards svg image').length"),0);
  const first = await evaluate("document.querySelector('#catalog-cards article').dataset.entry");
  await evaluate("document.querySelector('#catalog-next').click()");
  assert.notEqual(await evaluate("document.querySelector('#catalog-cards article').dataset.entry"), first);
  await evaluate("document.querySelector('#catalog-query').value='Reverse Engineer Anything';document.querySelector('#catalog-query').dispatchEvent(new Event('input'))");
  assert.equal(await evaluate("document.querySelectorAll('#catalog-cards article[data-entry=rea]').length"),1);
  await evaluate("document.querySelector('article[data-entry=rea] button').click()");
  assert.match(await evaluate("document.querySelector('#detail-json').textContent"), /search_guidance/);
  await evaluate("document.querySelector('#detail-close').click()");
  await evaluate("Array.from(document.querySelectorAll('article[data-entry=rea] button')).find(b=>b.textContent==='Configure').click()");
  assert.deepEqual(await evaluate(visible),["custom"]);
  assert.equal(await evaluate("document.querySelector('#server-add').elements.namedItem('id').value"),"rea");
  assert.equal(await evaluate("document.querySelector('#server-add').elements.namedItem('argv').value"),'["mcp"]');
  assert.equal(await evaluate("document.querySelector('#server-add').elements.namedItem('command').value"),"");
  assert.ok(await evaluate("Array.from(document.querySelector('#server-transport').options).some(o=>o.value==='add-bundle')"));
  await evaluate("document.querySelector('#custom-workspaces').click()");
  assert.deepEqual(await evaluate(visible),["servers"]);
  assert.equal(await evaluate("document.activeElement.id"),"workspace-client");
  assert.equal(await evaluate("document.querySelector('#workspace-path').required"),true);
  assert.deepEqual(await evaluate("Array.from(document.querySelector('#workspace-scope').options,o=>o.value)"),["workspace","workspace-folder"]);
  assert.equal(await evaluate("document.querySelector('#workspace-form button[type=submit]').disabled"),true);
  assert.match(await evaluate("document.querySelector('#workspace-current').textContent"),/No workspace folder/);
  await evaluate("document.querySelector('nav a[href=\"#marketplace\"]').click()");
  await evaluate("document.querySelector('#catalog-query').value='no-such-entry';document.querySelector('#catalog-query').dispatchEvent(new Event('input'))");
  assert.equal(await evaluate("document.querySelectorAll('#catalog-cards article').length"),0);
  await evaluate("document.querySelector('#goals-nav').click()");
  await until(()=>evaluate("document.querySelector('#goals-list button')?.textContent === 'Browser roadmap fixture'"));
  assert.deepEqual(await evaluate(visible),["goals"]);
  await evaluate("document.querySelector('#goals-list button').click()");
  await until(()=>evaluate("document.querySelector('#goal-detail').textContent.includes('Review goal')"));
  assert.match(await evaluate("document.querySelector('#goal-detail').textContent"),/Observe persisted goal/);
  const goalButton = label => "Array.from(document.querySelectorAll('#goal-detail button')).find(button=>button.textContent===" + JSON.stringify(label) + ")";
  await evaluate(goalButton("Pause")+".click()");
  await until(()=>evaluate("Boolean("+goalButton("Resume")+")"));
  await evaluate(goalButton("Resume")+".click()");
  await until(()=>evaluate("document.querySelector('#goal-detail').textContent.includes('running')"));
  if (screenshotDir) {
    await evaluate("theme='dark';applyTheme()");
    for (const page of ["health", "clients", "goals", "jobs"]) {
      await capture(page, 1280, 900);
      await capture(page, 390, 844);
    }
  }
  if (await evaluate("!!document.querySelector('#grant-search')")) {
    await openTab("clients");
    await until(() => evaluate("!!document.querySelector('#client-rows button')"));
    assert.ok(await evaluate("document.documentElement.scrollWidth <= innerWidth"));
    assert.equal(await evaluate("document.querySelector('#client-rows td[data-label=Auth]').textContent"), "Bearer");
    const click = label => evaluate(`Array.from(document.querySelectorAll('#client-rows button')).find(b=>b.textContent===${JSON.stringify(label)}).click()`);
    assert.equal(await evaluate("document.querySelector('#client-default').hidden"), false);
    await evaluate("window.confirm=()=>true;document.querySelector('#client-default-mode').value='yolo';document.querySelector('#client-default-save').click()");
    await until(() => evaluate("lastStatus.default_mode === 'yolo'"));
    assert.equal(await evaluate("lastStatus.clients[0].mode"),"standard");
    await evaluate("document.querySelector('#client-default-mode').value='standard';document.querySelector('#client-default-save').click()");
    await until(() => evaluate("lastStatus.default_mode === 'standard'"));
    await click("Grants");
    await evaluate("document.querySelector('#grant-search').value='goal_create';document.querySelector('#grant-search').dispatchEvent(new Event('input'))");
    assert.equal(await evaluate("Array.from(document.querySelectorAll('#native-grant-grid label')).filter(e=>!e.hidden).length"),1);
    assert.equal(await evaluate("document.querySelector('#native-grant-grid details[open]:not([hidden]) summary').textContent"),"Goals");
    await evaluate("window.confirm=()=>true");
    await click("YOLO");
    await until(() => evaluate("document.querySelector('#client-rows td[data-label=Mode]').textContent === 'YOLO'"));
    await click("Standard");
    await until(() => evaluate("document.querySelector('#client-rows td[data-label=Mode]').textContent === 'Standard'"));
    await click("Revoke");
    await until(() => evaluate("document.querySelector('#client-rows td[data-label=Connection]').textContent === 'Revoked'"));
    console.log("RESPONSIVE_CLIENT_GRANTS_AND_PERMISSIONS_PASS");
  }
  await evaluate("document.querySelector('nav a[href=\"#audit\"]').click()");
  await send("Emulation.setDeviceMetricsOverride",{width:390,height:844,deviceScaleFactor:1,mobile:true});
  assert.deepEqual(await evaluate(visible),["audit"]);
  console.log("DASHBOARD_TABS_AND_KEYBOARD_PASS");
} finally {
  if(ws)ws.close();
  child.kill("SIGTERM");
  await Promise.race([new Promise(r=>child.once("exit",r)),delay(3000)]);
  await rm(profile,{recursive:true,force:true,maxRetries:3});
}
