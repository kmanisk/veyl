// Real dashboard consent through disposable Chromium CDP, no external requests.
// Synthetic pairing URL and request handles are passed over stdin, never argv.
import {spawn} from "node:child_process";
import {mkdtemp,readFile,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import assert from "node:assert/strict";
const chunks=[];
for await(const chunk of process.stdin) chunks.push(chunk);
const fixture=JSON.parse(Buffer.concat(chunks).toString());
assert.match(fixture.url,/^http:\/\/127\.0\.0\.1:\d+\/dashboard\/login#pair=[a-f0-9]{48}$/);
for(const key of ["approve","deny","approve_id","deny_id","revoke_id"]) assert.match(fixture[key],/^[a-f0-9]{64}$/);
const profile=await mkdtemp(join(tmpdir(),"veyl-oauth-browser-"));
const child=spawn(process.argv[2],["--headless","--incognito","--ozone-platform=headless",
  "--disable-gpu","--disable-background-networking","--disable-component-update","--disable-extensions",
  "--no-proxy-server","--password-store=basic","--no-first-run","--no-default-browser-check",
  "--remote-debugging-port=0","--user-data-dir="+profile,"about:blank"],{stdio:"ignore"});
const delay=ms=>new Promise(r=>setTimeout(r,ms));
async function until(fn,timeout=10000) {
  const end=Date.now()+timeout;
  while(Date.now()<end) {
    try {const result=await fn();if(result)return result;}catch{}
    await delay(75);
  }
  throw Error("Browser condition timed out");
}
let ws;
try {
  const port=await until(async()=>Number((await readFile(join(profile,"DevToolsActivePort"),"utf8")).split("\n")[0]));
  const page=await until(async()=>(await (await fetch("http://127.0.0.1:"+port+"/json/list")).json()).find(p=>p.type==="page"));
  ws=new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=reject;});
  let serial=0;
  const pending=new Map();
  const dialogs=[];
  let expected;
  function send(method,params={}) {
    return new Promise((resolve,reject)=>{
      const id=++serial;
      const timer=setTimeout(()=>{pending.delete(id);reject(Error("CDP timeout"));},5000);
      pending.set(id,{resolve,reject,timer});ws.send(JSON.stringify({id,method,params}));
    });
  }
  ws.onmessage=event=>{
    const message=JSON.parse(event.data);
    if(message.id&&pending.has(message.id)){
      const {resolve,reject,timer}=pending.get(message.id);
      pending.delete(message.id);clearTimeout(timer);
      if(message.error) reject(Error("CDP command failed"));else resolve(message.result);
    } else if(message.method==="Page.javascriptDialogOpening") {
      const text=message.params.message;
      const match=expected&&message.params.type==="confirm"&&expected.parts.every(part=>text.includes(part));
      dialogs.push({match:Boolean(match),accepted:Boolean(match&&expected.accept)});
      send("Page.handleJavaScriptDialog",{accept:Boolean(match&&expected.accept)}).catch(()=>{});
      expected=undefined;
    }
  };
  async function evaluate(expression){
    const result=await send("Runtime.evaluate",{expression,returnByValue:true,awaitPromise:true});
    if(result.exceptionDetails)throw Error("Page script failed");
    return result.result.value;
  }
  await send("Page.enable");
  await send("Page.navigate",{url:fixture.url});
  await until(()=>evaluate("document.querySelector('#dashboard')?.hidden===false && document.querySelector('#oauth-nav')?.hidden===false"));
  assert.equal(await evaluate("location.hash"),"");
  await evaluate("document.querySelector('#oauth-nav').click()");
  await until(()=>evaluate("document.querySelectorAll('#oauth-registrations .section-card').length===3"));
  assert.equal(await evaluate("document.querySelector('#oauth-registrations img')===null"),true);
  async function inspect(handle,id) {
    await evaluate("document.querySelector('#oauth-handle').value="+JSON.stringify(handle)+";document.querySelector('#oauth-inspect').requestSubmit()");
    await until(()=>evaluate("document.querySelectorAll('#oauth-review button').length===2"));
    const text=await evaluate("document.querySelector('#oauth-review').textContent");
    assert.ok(text.includes(id)&&text.includes(fixture.callback)&&text.includes(fixture.resource)&&text.includes("Standard read-only"));
    assert.equal(await evaluate("document.querySelector('#oauth-review img')===null"),true);
  }
  async function clickConsent(action,id,accept) {
    expected={parts:[action.toUpperCase(),id,fixture.callback,fixture.resource,fixture.local],accept};
    const count=dialogs.length;
    const label=action==="approve"?"Approve exact binding":"Deny request";
    await evaluate("setTimeout(()=>Array.from(document.querySelectorAll('#oauth-review button')).find(b=>b.textContent==="+JSON.stringify(label)+").click(),0);true");
    await until(()=>dialogs.length===count+1);
    assert.deepEqual(dialogs.at(-1),{match:true,accepted:accept});
    if(accept) await until(()=>evaluate("document.querySelector('#oauth-review').children.length===0"));
  }
  await inspect(fixture.approve,fixture.approve_id);
  await clickConsent("approve",fixture.approve_id,false);
  assert.equal(await evaluate("document.querySelectorAll('#oauth-review button').length"),2);
  await clickConsent("approve",fixture.approve_id,true);
  await inspect(fixture.deny,fixture.deny_id);
  await clickConsent("deny",fixture.deny_id,true);
  expected={parts:["Revoke OAuth client",fixture.revoke_id],accept:true};
  const count=dialogs.length;
  await evaluate("setTimeout(()=>Array.from(document.querySelectorAll('#oauth-registrations .section-card')).find(c=>c.textContent.includes("+JSON.stringify(fixture.revoke_id)+")).querySelector('button').click(),0);true");
  await until(()=>dialogs.length===count+1);
  assert.deepEqual(dialogs.at(-1),{match:true,accepted:true});
  await until(()=>evaluate("document.querySelectorAll('#oauth-registrations .section-card').length===2"));
  await evaluate("document.querySelector('#logout').click()");
  await until(()=>evaluate("document.querySelector('#dashboard').hidden && !document.querySelector('#pair').hidden"));
  assert.equal(await evaluate("document.querySelector('#oauth-review').children.length===0 && document.querySelector('#oauth-registrations').children.length===0"),true);
  console.log("OAUTH_DASHBOARD_BROWSER_PASS");
} finally {
  if(ws)ws.close();
  child.kill("SIGTERM");
  await Promise.race([new Promise(r=>child.once("exit",r)),delay(3000)]);
  await rm(profile,{recursive:true,force:true,maxRetries:3});
}
