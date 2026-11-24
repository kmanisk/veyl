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
  for(const id of ["jobs","clients","audit","skills","servers","configuration","protection","health"]){
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
  await send("Emulation.setDeviceMetricsOverride",{width:390,height:844,deviceScaleFactor:1,mobile:true});
  assert.deepEqual(await evaluate(visible),["audit"]);
  console.log("DASHBOARD_TABS_AND_KEYBOARD_PASS");
} finally {
  if(ws)ws.close();
  child.kill("SIGTERM");
  await Promise.race([new Promise(r=>child.once("exit",r)),delay(3000)]);
  await rm(profile,{recursive:true,force:true,maxRetries:3});
}
