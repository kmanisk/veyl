// Disposable Chromium DevTools test. No browser automation dependency.
// URL (including the one-use pairing fragment) arrives only over stdin.
import {spawn} from "node:child_process";
import {mkdtemp, readFile, rm} from "node:fs/promises";
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
  "--disable-extensions","--password-store=basic","--no-first-run","--no-default-browser-check",
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
  await send("Page.navigate",{url});
  await until(()=>evaluate("!document.querySelector('#dashboard')?.hidden && document.querySelector('[role=tab][aria-selected=true]')?.hash === '#health'"));
  assert.equal(await evaluate("location.hash"),"");
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
  await until(()=>evaluate("document.querySelector('#audit-rows button') !== null"));
  await evaluate("document.querySelector('#audit-rows button').click()");
  assert.equal(await evaluate("document.querySelector('#detail-dialog').open"),true);
  assert.ok((await evaluate("document.querySelector('#detail-json').textContent")).includes('"tool"'));
  await evaluate("document.querySelector('#detail-close').click()");
  assert.equal(await evaluate("document.querySelector('#detail-dialog').open"),false);
  await evaluate("document.querySelector('#theme').click()");
  assert.equal(await evaluate("document.documentElement.dataset.theme"),"dark");
  assert.equal(await evaluate("document.querySelector('link[rel=icon]').getAttribute('href')"),"/dashboard/icon.svg");
  await evaluate("document.querySelector('nav a[href=\"#diagnostics\"]').click()");
  assert.deepEqual(await evaluate(visible),["diagnostics"]);
  await evaluate("document.querySelector('#diagnostics-run').click()");
  await until(()=>evaluate("document.querySelector('#diagnostics-output').textContent.includes('memory_total_kib')"));
  await evaluate("document.querySelector('nav a[href=\"#marketplace\"]').click()");
  await until(()=>evaluate("document.querySelectorAll('#catalog-cards article').length === 20"));
  assert.match(await evaluate("document.querySelector('#catalog-count').textContent"), /106 matching resources/);
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
  await evaluate("document.querySelector('nav a[href=\"#marketplace\"]').click()");
  await evaluate("document.querySelector('#catalog-query').value='no-such-entry';document.querySelector('#catalog-query').dispatchEvent(new Event('input'))");
  assert.equal(await evaluate("document.querySelectorAll('#catalog-cards article').length"),0);
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
