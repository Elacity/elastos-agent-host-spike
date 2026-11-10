import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync, mkdirSync } from "node:fs";
import http from "node:http";
import test from "node:test";
import {makeSystemSummary,makeAppearanceRecord,inertSystemApiResponse} from "./system-uiux-fixture.mjs";
const require = createRequire(new URL("../elastos/tools/browser-playwright-engine/package.json", import.meta.url));
const { chromium } = require("playwright");
const root = new URL("../", import.meta.url);
const consentText = "Browser opens websites through this computer's internet connection, or through an Exit you approved. Websites can see that connection's address. Turn this off any time in System, Security.";
const hostScript = `window.messages=[];window.approvals=[];window.passkeyAllowed=true;window.holdPasskey=false;
window.showFixtureApp=(target,query={})=>{
  for(const frame of document.querySelectorAll('iframe')) frame.hidden=true;
  let frame=document.querySelector('iframe[data-app="'+target+'"]');
  if(!frame){frame=document.createElement('iframe');frame.dataset.app=target;
    frame.src='/apps/'+target+'/?'+new URLSearchParams({home_origin:location.origin,...query})+'#home_token=fixture';document.body.append(frame);}
  frame.hidden=false;
};
addEventListener('message',e=>{
  messages.push(e.data);
  if(e.data?.type==='home:open-target' && new URLSearchParams(location.search).has('flow')) {
    showFixtureApp(e.data.target,e.data.query);return;
  }
  if(e.data?.type!=="elastos.home.passkey-step-up.request/v1")return;
  approvals.push(e.data.operation);
  window.completeFixturePasskey=()=>e.source.postMessage({type:"elastos.home.passkey-step-up.result/v1",requestId:e.data.requestId,
    ...(passkeyAllowed?{stepUpToken:"fixture-step-up"}:{error:"Passkey cancelled."})},"*");
  if(!holdPasskey)completeFixturePasskey();
});`;

async function screen(page, name) {
  if (!process.env.BROWSER_INTERNET_SCREENSHOTS || page.viewportSize().width !== 1280) return;
  mkdirSync(process.env.BROWSER_INTERNET_SCREENSHOTS,{recursive:true});
  for (const frame of page.frames().slice(1)) await frame.evaluate(() => window.elastosTheme?.set("light"));
  await page.waitForTimeout(250);
  await page.screenshot({path:`${process.env.BROWSER_INTERNET_SCREENSHOTS}/${name}.png`});
}
async function fixture() {
  const state = {consent:"off", expired:false, grantedRequestId:"fixture", requests:0, reads:0, opens:[], actions:[]};
  const server=http.createServer(async (req,res) => {
    const url=new URL(req.url,"http://localhost");
    res.setHeader("access-control-allow-origin","*");
    res.setHeader("access-control-allow-headers","content-type,x-elastos-home-token");
    res.setHeader("access-control-allow-methods","GET,POST,OPTIONS");
    if(req.method==="OPTIONS") {res.writeHead(204).end();return;}
    const json=value=>{res.setHeader("content-type","application/json");res.end(JSON.stringify(value));};
    let input;
    if (req.method === "POST") {let body="";for await (const chunk of req) body+=chunk;input=JSON.parse(body);}
    if(url.pathname === "/gui") {
      res.setHeader("content-type","text/html");
      res.end(`<iframe src="/apps/browser/?browser_restore=1&home_origin=http://127.0.0.1:${server.address().port}#home_token=fixture"></iframe>`);return;
    }
    if (url.pathname === "/") {
      if(url.searchParams.has("nested")) {
        res.setHeader("content-type","text/html");
        res.end(`<script>${hostScript}</script><iframe id="gui" sandbox="allow-scripts allow-forms" src="/gui"></iframe>`);return;
      }
      const app=url.searchParams.get("app") || "browser";
      res.setHeader("content-type","text/html");
      res.end(`<style>html,body{margin:0;height:100%}iframe{border:0;width:100%;height:100%}</style><script>${hostScript}</script><iframe data-app="${app}" src="/apps/${app}/?browser_restore=${url.searchParams.get("restore") || "0"}&notification_id=browser-internet:permission&url=https%3A%2F%2Fexample.com%2Frequested&home_origin=http://127.0.0.1:${server.address().port}#home_token=fixture"></iframe>`);return;
    }
    if (url.pathname === "/api/apps/browser/internet") {
      state.reads++;
      if(input?.action === "revoke") {assert.equal(input.step_up_token,"fixture-step-up");state.consent="revoked";}
      if (input?.action === "end") {json({status:"ended"});return;}
      if (input?.action === "request") {state.requests++;state.consent="requested";state.expired=false;await state.requestBarrier;}
      json({status:state.consent,request_id:state.consent==="granted"?state.grantedRequestId:undefined,request:state.expired?null:{resource:"elastos://browser/internet",grant_id:"fixture-grant",request_id:"fixture",text:consentText,expires_at:Math.floor(Date.now()/1000)+3600}});return;
    }
    if (url.pathname === "/api/apps/inbox/summary") {
      const pending=state.consent === "requested";
      const body=pending?consentText:state.consent === "granted"?"Browser can use the internet. Allowed with your passkey.":state.consent === "refused"?"Not allowed.":"Turned off.";
      json({notifications:{unread_count:pending?1:0,attention_count:pending?1:0,entries:[{
        id:"browser-internet:permission",source_app:"browser",kind:pending?"browser_internet_request":"browser_internet_decision",
        title:pending?"Allow Browser to use the internet?":"Browser internet access",body,severity:pending?"attention":"info",read:!pending,created_at:1794312000,
        action_ref:pending?{app:"inbox",action_id:"browser-internet-allow:fixture"}:null,
      }]}});return;
    }
    if (url.pathname === "/api/apps/inbox/actions") {
      state.actions.push(input);
      if(input.action_id === "browser-internet-allow:fixture") {
        assert.equal(input.step_up_token,"fixture-step-up");state.consent="granted";
      } else if(input.action_id === "browser-internet-deny:fixture") state.consent="refused";
      json({ok:true});return;
    }
    if (url.pathname === "/api/apps/browser/summary") {
      json({net:{exit_provider:{remote_carrier_exits:[{id:"sasha-exit",display_name:"A shared Exit",contact_name:"Sasha",allowed_for_principal:true},{id:"legacy-exit",display_name:"A service label",allowed_for_principal:true}]}},engine_adapter:{adapters:[]},sessions:{schema:"elastos.browser.session-capacity/v1",status:"configured",fresh_start_allowed:true,recoverable_page:null}});return;
    }
    if (url.pathname === "/api/apps/browser/open") {
      state.opens.push(input);json({schema:"elastos.browser.open-accepted/v1",status_url:"/api/apps/browser/open/fixture"});return;
    }
    if (url.pathname === "/api/apps/browser/open/fixture") {json({schema:"elastos.browser.open-status/v1",status:"pending"});return;}
    if(url.pathname === "/api/apps/system/summary") {json(makeSystemSummary(makeAppearanceRecord({theme:"light"})));return;}
    if(url.pathname.startsWith("/api/")) {
      const response=inertSystemApiResponse(url.pathname);if(response) {json(response);return;}
    }
    const match=url.pathname.match(/^\/apps\/(browser|inbox|home|system)\/(.*)$/);
    if (!match || match[2].includes("..")) {res.writeHead(404).end();return;}
    const name=match[2] || "index.html";
    try {const bytes=readFileSync(new URL(`capsules/${match[1]}/browser/${name}`,root));res.setHeader("content-type",(name.endsWith(".js") || name.endsWith(".mjs"))?"text/javascript":name.endsWith(".css")?"text/css":"text/html");res.end(bytes);} catch {res.writeHead(404).end();}
  });
  await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
  return {state,url:`http://127.0.0.1:${server.address().port}/`,close:()=>new Promise(resolve=>server.close(resolve))};
}
async function settingsMessage(page) {
  await page.waitForFunction(()=>messages.some(m=>m.type==="home:open-target" && m.target==="system" && m.query.settings==="security"));
}

test("Browser asks once, polls every two seconds and opens the requested page without a click", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    for (const width of [1280,390]) {
      f.state.consent="off";f.state.opens=[];f.state.requests=0;
      const page=await browser.newPage({viewport:{width,height:844},colorScheme:"light"});
      await page.goto(f.url);const frame=page.frameLocator("iframe");
      await frame.getByText("Waiting for your answer in Inbox.",{exact:true}).waitFor({timeout:4000});
      assert.equal(await frame.locator("#browser-status").isVisible(),false);

      assert.equal(await frame.getByRole("button",{name:"Ask in Inbox",exact:true}).count(),0);
      await page.waitForFunction(()=>messages.some(m=>m.type==="home:open-target" && m.target==="inbox" && m.query.notification_id==="browser-internet:permission"));
      assert.equal(f.state.requests,1);
      await frame.getByRole("button",{name:"Show Request",exact:true}).click();
      assert.equal(f.state.requests,1,"Show Request reuses the current request");assert.equal(f.state.opens.length,0);
      await frame.getByText("Waiting for your answer in Inbox.",{exact:true}).waitFor();
      await screen(page,"browser-waiting");
      await frame.getByRole("button",{name:"Browser settings",exact:true}).click();
      assert.equal(await frame.locator("#browser-internet").count(),0);
      await frame.getByText("Internet access: Off",{exact:true}).waitFor();
      await frame.getByText("Websites see this Mac's internet address.",{exact:true}).waitFor();
      await frame.locator("#browser-exit").selectOption("sasha-exit");
      await frame.getByText("Websites see Sasha's internet address.",{exact:true}).waitFor();
      await frame.locator("#browser-exit").selectOption("legacy-exit");
      await frame.getByText("Websites see the address of the shared connection.",{exact:true}).waitFor();
      await frame.locator("#browser-exit").selectOption("");
      await frame.getByRole("button",{name:"Change in Settings",exact:true}).click();await settingsMessage(page);
      await frame.getByRole("button",{name:"Close Browser settings"}).click();
      f.state.consent="granted";
      await page.waitForResponse(r=>r.url().endsWith("/api/apps/browser/open"),{timeout:5000});
      assert.equal(f.state.opens.length,1);assert.equal(f.state.opens[0].url,"https://example.com/requested");
      assert.equal(await frame.locator("#browser-internet-request").isVisible(),false);
      await screen(page,"browser-allowed");
      await Promise.all([
        page.waitForResponse(r=>r.url().endsWith("/api/apps/browser/internet") && r.request().method()==="GET"),
        frame.getByRole("button",{name:"Browser settings",exact:true}).click(),
      ]);
      await frame.getByText("Internet access: Allowed",{exact:true}).waitFor();
      await frame.getByText("Pages go out through",{exact:true}).waitFor();await frame.getByText("Websites see this Mac's internet address.",{exact:true}).waitFor();
      await screen(page,"browser-settings");
      const reads=f.state.reads;await page.waitForTimeout(2200);assert.equal(f.state.reads,reads,"permission poll stops after grant");
      f.state.consent="revoked";
      await frame.getByRole("button",{name:"Close Browser settings"}).click();
      await frame.getByRole("button",{name:"Browser settings",exact:true}).click();
      await frame.getByText("Internet access: Off",{exact:true}).waitFor({timeout:2000});
      await page.close();
    }
    for (const consent of ["refused","revoked"]) {
      f.state.consent=consent;
      const page=await browser.newPage({viewport:{width:1280,height:844},colorScheme:"light"});await page.goto(f.url);const frame=page.frameLocator("iframe");
      await frame.getByText("Internet access is off for Browser.",{exact:true}).waitFor();
      await screen(page,"browser-off");
      await frame.getByRole("button",{name:"Open Settings",exact:true}).click();await settingsMessage(page);
      const reads=f.state.reads;await page.goto("about:blank");await page.waitForTimeout(2200);
      assert.equal(f.state.reads,reads,"permission polling stops on leave");await page.close();
    }
  } finally {await browser.close();await f.close();}
});

test("only an explicit Browser action continues once; restore, close, denial and expiry cancel it", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    const restored=await browser.newPage({viewport:{width:1280,height:844},colorScheme:"light"});await restored.goto(f.url+"?restore=1");
    await restored.frameLocator("iframe").locator("#browser-internet-request").waitFor();
    await screen(restored,"browser-blocked");
    assert.equal(f.state.requests,0);assert.equal(await restored.evaluate(()=>messages.some(m=>m.target==="inbox")),false);
    const asking=await browser.newPage();await asking.goto(f.url+"?restore=1");const frame=asking.frameLocator("iframe");
    await frame.locator("#browser-internet-request").waitFor();
    await frame.getByRole("textbox",{name:"Web address"}).fill("https://example.com/go");
    await frame.getByRole("textbox",{name:"Web address"}).press("Enter");
    await asking.waitForFunction(()=>messages.some(m=>m.target==="inbox" && m.query.notification_id==="browser-internet:permission"));
    assert.equal(f.state.requests,1);
    f.state.consent="granted";await asking.waitForResponse(r=>r.url().endsWith("/api/apps/browser/open"));
    await asking.waitForTimeout(4300);
    assert.equal(f.state.opens.length,1);assert.equal(f.state.opens[0].url,"https://example.com/go");
    await asking.close();await restored.close();
    for(const ending of ["closed","refused","expired"]) {
      f.state.consent="off";f.state.expired=false;f.state.opens=[];
      const page=await browser.newPage();await page.goto(f.url);
      await page.waitForFunction(()=>messages.some(m=>m.target==="inbox"),{timeout:4000});
      if(ending === "closed") await page.close();
      else {
        if(ending === "expired") f.state.expired=true;else f.state.consent="refused";
        await page.frameLocator("iframe").getByText("Internet access is off for Browser.",{exact:true}).waitFor({timeout:5000});
      }
      f.state.expired=false;f.state.consent="granted";
      await new Promise(resolve=>setTimeout(resolve,2300));assert.equal(f.state.opens.length,0,ending+" cancels continuation");
      if(!page.isClosed()) await page.close();
    }
  } finally {await browser.close();await f.close();}
});

test("an explicit Home open in a restored Browser uses the same permission request path", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    const page=await browser.newPage();await page.goto(f.url+"?nested=1");
    const gui=page.frameLocator("#gui");const frame=gui.frameLocator("iframe");
    await frame.locator("#browser-internet-request").waitFor();assert.equal(f.state.requests,0);
    await gui.locator("body").evaluate(()=>document.querySelector("iframe").contentWindow.postMessage({
      type:"elastos.browser.navigate/v1",homeToken:"fixture",url:"https://example.com/from-home",
    },"*"));
    await page.waitForFunction(()=>messages.some(m=>m.target==="inbox" && m.query.notification_id==="browser-internet:permission"),null,{timeout:4000});
    assert.equal(f.state.requests,1);assert.equal(f.state.opens.length,0);
    f.state.consent="granted";await page.waitForResponse(r=>r.url().endsWith("/api/apps/browser/open"));
    assert.equal(f.state.opens.length,1);assert.equal(f.state.opens[0].url,"https://example.com/from-home");
    await page.close();
  } finally {await browser.close();await f.close();}
});

test("a grant for a replacement request cannot resume an earlier denied request", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    const page=await browser.newPage();await page.goto(f.url);
    await page.waitForFunction(()=>messages.some(m=>m.target==="inbox"));
    // Refusal and a new grant can both happen between two summary polls.
    f.state.grantedRequestId="replacement";f.state.consent="granted";
    await page.waitForTimeout(2300);assert.equal(f.state.opens.length,0);
    await page.close();
  } finally {await browser.close();await f.close();}
});

test("restoring after approval never creates a fresh page, and reload never repeats a request", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    f.state.consent="granted";
    const page=await browser.newPage();await page.goto(f.url+"?restore=1");
    await page.waitForTimeout(2300);assert.equal(f.state.opens.length,0);
    f.state.consent="off";await page.goto(f.url);
    await page.waitForFunction(()=>messages.some(m=>m.target==="inbox"));
    const requests=f.state.requests;
    await page.frameLocator("iframe").locator("body").evaluate(()=>location.reload());
    await page.waitForTimeout(2300);assert.equal(f.state.requests,requests);
    f.state.consent="granted";await page.waitForTimeout(2300);assert.equal(f.state.opens.length,0);
    await page.close();
  } finally {await browser.close();await f.close();}
});

test("Inbox keeps Allow, Don't Allow and Turn Off as read history with one Settings link", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    for (const answer of ["Allow","Don't Allow","Turn Off"]) {
      f.state.consent=answer === "Turn Off"?"revoked":"requested";
      const page=await browser.newPage({viewport:{width:1280,height:844},colorScheme:"light"});
      await page.goto(f.url+"?app=inbox");const frame=page.frameLocator("iframe");
      if (answer !== "Turn Off") {
        await frame.locator("#entry-detail").getByText(consentText,{exact:true}).waitFor();await screen(page,"inbox-request");
        await page.waitForLoadState("networkidle");
        assert.equal(await frame.locator(".entry-row-unread").count(),1,"an open permission request stays unread until answered");
        assert.deepEqual(await frame.locator("#entry-detail button").allTextContents(),["Don't Allow","Allow"]);
        await frame.locator("#entry-detail").getByRole("button",{name:answer,exact:true}).click();
      }
      const body=answer === "Allow"?/Browser can use the internet\. Allowed with your passkey on/:answer === "Don't Allow"?/Not allowed on/:/Turned off on/;
      await frame.locator("#entry-detail .entry-body").filter({hasText:body}).waitFor();
      assert.equal(await frame.locator("#pending-count").innerText(),"0");assert.equal(await frame.locator("#review-count").innerText(),"0");
      assert.deepEqual(await frame.locator("#entry-detail button").allTextContents(),["Manage in Settings"]);
      await frame.locator("#entry-detail").getByRole("button",{name:"Manage in Settings"}).click();await settingsMessage(page);
      assert.deepEqual(await page.evaluate(()=>approvals),answer === "Allow"?["browser.internet.grant"]:[]);
      if(answer === "Allow") await screen(page,"inbox-decided-allowed");
      await page.reload();
      await frame.locator("#entry-detail .entry-body").filter({hasText:body}).waitFor();
      assert.equal(await frame.locator("#pending-count").innerText(),"0");
      if(answer === "Allow") {
        const requests=f.state.requests;f.state.consent="revoked";await page.reload();
        await frame.locator("#entry-detail .entry-body").filter({hasText:/Turned off on/}).waitFor();
        assert.equal(f.state.requests,requests,"turning off updates the same history without a new request");
      }
      await page.close();
    }
  } finally {await browser.close();await f.close();}
});

test("first-run Go, Inbox Allow, passkey, automatic page; Manage reaches the real Security switch", async () => {
  const f=await fixture();const browser=await chromium.launch({headless:true});
  try {
    const page=await browser.newPage({viewport:{width:1280,height:844},colorScheme:"light"});
    let releaseRequest;
    f.state.requestBarrier=new Promise(resolve=>{releaseRequest=resolve;});
    await page.goto(f.url+"?flow=1");
    const browserFrame=page.frameLocator('iframe[data-app="browser"]');
    await browserFrame.locator("#browser-internet-request").waitFor();
    await browserFrame.getByRole("textbox",{name:"Web address"}).fill("https://example.com/first-run");
    await screen(page,"flow-1");
    assert.equal(f.state.requests,1);
    await browserFrame.getByRole("textbox",{name:"Web address"}).press("Enter");
    releaseRequest();
    const inbox=page.frameLocator('iframe[data-app="inbox"]');
    await inbox.getByRole("button",{name:"Allow",exact:true}).waitFor();
    await screen(page,"flow-2");
    assert.equal(f.state.requests,1);assert.equal(f.state.opens.length,0);assert.deepEqual(await page.evaluate(()=>approvals),[]);
    await page.evaluate(()=>holdPasskey=true);
    await inbox.getByRole("button",{name:"Allow",exact:true}).click();
    await page.waitForFunction(()=>approvals.length===1);
    assert.equal(f.state.consent,"requested");assert.equal(f.state.opens.length,0);
    // The real Inbox is awaiting Home's passkey result. The fixture pauses the
    // authentication boundary; it does not draw a counterfeit OS passkey sheet.
    await screen(page,"flow-3");
    await page.evaluate(()=>completeFixturePasskey());
    await page.waitForResponse(r=>r.url().endsWith("/api/apps/browser/open"));
    assert.deepEqual(await page.evaluate(()=>approvals),["browser.internet.grant"]);
    assert.equal(f.state.opens.length,1);assert.equal(f.state.opens[0].url,"https://example.com/first-run");
    await page.evaluate(()=>showFixtureApp("browser"));await screen(page,"flow-4");
    await page.evaluate(()=>showFixtureApp("inbox"));
    await inbox.getByRole("button",{name:"Manage in Settings",exact:true}).click();
    const system=page.frameLocator('iframe[data-app="system"]');
    await system.locator("#browser-internet-switch:checked:not(:disabled)").waitFor();
    assert.equal(await system.getByRole("heading",{name:"Permissions",exact:true}).count(),1);
    await page.evaluate(()=>holdPasskey=false);
    await system.locator("label:has(#browser-internet-switch)").click();
    await system.getByRole("button",{name:"Turn Off",exact:true}).click();
    await system.locator("#browser-internet-switch:not(:checked):not(:disabled)").waitFor();
    assert.equal(f.state.consent,"revoked");assert.equal(f.state.requests,1);
    await page.evaluate(()=>showFixtureApp("inbox"));
    await inbox.locator("body").evaluate(()=>location.reload());
    await inbox.locator("#entry-detail .entry-body").filter({hasText:/Turned off on/}).waitFor();
    assert.equal(await inbox.locator("#pending-count").innerText(),"0");
    assert.equal(f.state.requests,1,"System revoke updates history without requesting access");
    await page.close();
    for(const link of ["Open Settings","Change in Settings"]) {
      const settingsPage=await browser.newPage();await settingsPage.goto(f.url+"?flow=1");
      const offBrowser=settingsPage.frameLocator('iframe[data-app="browser"]');
      await offBrowser.getByText("Internet access is off for Browser.",{exact:true}).waitFor();
      if(link==="Change in Settings") await offBrowser.getByRole("button",{name:"Browser settings",exact:true}).click();
      await offBrowser.getByRole("button",{name:link,exact:true}).click();
      const settings=settingsPage.frameLocator('iframe[data-app="system"]');
      await settings.locator("#browser-internet-switch:not(:checked):not(:disabled)").waitFor();
      assert.equal(await settings.getByRole("heading",{name:"Permissions",exact:true}).count(),1);
      assert.equal(f.state.requests,1);await settingsPage.close();
    }
  } finally {await browser.close();await f.close();}
});

test("System switch confirms Off before passkey, preserves access on cancel, requests On, and retries stop", async () => {
  const {startSystemFixtureServer,makeSystemSummary,makeAppearanceRecord,jsonResponse} = await import("./system-uiux-fixture.mjs");
  let consent="granted",pending=false,writes=[];
  const server=await startSystemFixtureServer({title:"Browser permission",hostScript,
    async onApiRequest({request,response,url}) {
      if(url.pathname==="/api/apps/system/summary") {jsonResponse(response,makeSystemSummary(makeAppearanceRecord({theme:"light"})));return true;}
      if(url.pathname!=="/api/apps/browser/internet")return false;
      if(request.method==="POST") {
        let body="";for await(const part of request)body+=part;const input=JSON.parse(body);writes.push(input);
        if(input.action === "request") {assert.equal(pending,false);consent="requested";jsonResponse(response,{status:consent});}
        else {
          assert.equal(input.action,"revoke");assert.equal(input.step_up_token,pending?undefined:"fixture-step-up");
          consent="revoked";
          if(!pending){pending=true;jsonResponse(response,{status:"stop_incomplete"},409);}
          else {pending=false;jsonResponse(response,{status:"revoked",revoke_list:"persisted"});}
        }
      } else jsonResponse(response,{status:consent,stop_pending:pending,request:{resource:"elastos://browser/internet",grant_id:"fixture"}});
      return true;
    }});
  const browser=await chromium.launch({headless:true});
  try {
    const consoleErrors=[];
    const page=await browser.newPage({viewport:{width:1280,height:844},colorScheme:"light"});
    page.on("console", message=>{if(message.type()==="error" && !/status of 409 \(Conflict\)/.test(message.text()))consoleErrors.push(message.text());});
    await page.goto(`${server.baseUrl}/fixture?settings=security`);
    let frame=page.frameLocator("#system-frame");const toggle=()=>frame.getByRole("switch",{name:"Browser can use the internet",exact:true});
    const clickSwitch=async()=>{
      await frame.locator("#browser-internet-switch:not(:disabled)").waitFor();
      await frame.locator("label:has(#browser-internet-switch)").click();
    };
    await page.waitForFunction(()=>messages.length>0);await frame.locator("#browser-internet-switch:checked:not(:disabled)").waitFor({timeout:4000});
    await screen(page,"system-switch-on");
    await clickSwitch();const confirm=()=>frame.getByRole("dialog");await confirm().waitFor();
    assert.match(await confirm().innerText(),/Turn off internet access for Browser\? Open Browser windows stop loading pages\./);
    assert.equal(await confirm().getByRole("button",{name:"Cancel",exact:true}).evaluate(n=>n===n.ownerDocument.activeElement),true);
    assert.deepEqual(await page.evaluate(()=>approvals),[]);assert.equal(writes.length,0);await screen(page,"system-confirm");
    await confirm().getByRole("button",{name:"Cancel",exact:true}).click();assert.equal(await toggle().isChecked(),true);
    await page.evaluate(()=>passkeyAllowed=false);await clickSwitch();await confirm().getByRole("button",{name:"Turn Off",exact:true}).click();
    await frame.locator("#browser-internet-error").filter({hasText:/passkey/i}).waitFor();assert.equal(writes.length,0);assert.equal(await toggle().isChecked(),true);
    await clickSwitch();await confirm().waitFor();await frame.locator('#browser-internet-confirm [value="cancel"]').press("Escape");
    await confirm().waitFor({state:"hidden"});
    await frame.locator("#browser-internet-switch:not(:disabled)").waitFor();
    assert.deepEqual(await page.evaluate(()=>approvals),["browser.internet.revoke"],"Escape cancels even after a previous Turn Off answer");
    await page.evaluate(()=>passkeyAllowed=true);await clickSwitch();await confirm().getByRole("button",{name:"Turn Off",exact:true}).click();
    await frame.locator("#browser-internet-error").filter({hasText:/try again/i}).waitFor();assert.equal(writes.length,1);
    assert.deepEqual(await page.evaluate(()=>approvals),["browser.internet.revoke","browser.internet.revoke"]);
    await page.reload();frame=page.frameLocator("#system-frame");await Promise.all([page.waitForResponse(r=>r.url().endsWith("/api/apps/browser/internet") && r.request().method()==="POST"),clickSwitch()]);
    assert.equal(pending,false);assert.equal(writes.length,2);assert.deepEqual(await page.evaluate(()=>approvals),[]);
    assert.equal(await toggle().isChecked(),false);
    await clickSwitch();await page.waitForFunction(()=>messages.some(m=>m.type==="home:open-target" && m.target==="inbox"));
    assert.equal(writes[2].action,"request");assert.equal(await toggle().isChecked(),false);
    assert.deepEqual(server.requestFailures,[]);
    assert.deepEqual(consoleErrors,[],"System permission controls produce no sandbox console errors");
  } finally {await browser.close();await server.close();}
});

test("internet grant refusal points to the permission request", async () => {
  const {friendlyOpenError} = await import("../capsules/browser/browser/browser-status.js");
  assert.equal(friendlyOpenError({status:403,payload:{code:"browser_internet_grant_required"}}),"Internet access is off for Browser. Open Settings to change it.");
});
