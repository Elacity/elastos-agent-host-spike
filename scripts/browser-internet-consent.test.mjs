import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync, mkdirSync } from "node:fs";
import http from "node:http";
import test from "node:test";
const require = createRequire(new URL("../elastos/tools/browser-playwright-engine/package.json", import.meta.url));
const { chromium } = require("playwright");
const root = new URL("../", import.meta.url);
const consentText = "Browser opens websites through this computer's internet connection, or through an Exit you approved. Websites can see that connection's address. Turn this off any time in System, Security.";
const hostScript = `window.messages=[];window.approvals=[];window.passkeyAllowed=true;addEventListener('message',e=>{
  messages.push(e.data);if(e.data?.type!=="elastos.home.passkey-step-up.request/v1")return;
  approvals.push(e.data.operation);e.source.postMessage({type:"elastos.home.passkey-step-up.result/v1",requestId:e.data.requestId,
    ...(passkeyAllowed?{stepUpToken:"fixture-step-up"}:{error:"Passkey cancelled."})},"*");
});`;
async function screen(page, name) {
  if (!process.env.BROWSER_INTERNET_SCREENSHOTS || page.viewportSize().width !== 1280) return;
  mkdirSync(process.env.BROWSER_INTERNET_SCREENSHOTS,{recursive:true});
  for (const frame of page.frames().slice(1)) await frame.evaluate(() => window.elastosTheme?.set("light"));
  await page.waitForTimeout(250);
  await page.screenshot({path:`${process.env.BROWSER_INTERNET_SCREENSHOTS}/${name}.png`});
}
async function fixture() {
  const state = {consent:"requested", requests:0, reads:0, opens:[], actions:[]};
  const server=http.createServer(async (req,res) => {
    const url=new URL(req.url,"http://localhost");
    const json=value=>{res.setHeader("content-type","application/json");res.end(JSON.stringify(value));};
    let input;
    if (req.method === "POST") {let body="";for await (const chunk of req) body+=chunk;input=JSON.parse(body);}
    if (url.pathname === "/") {
      const app=url.searchParams.get("app") || "browser";
      res.setHeader("content-type","text/html");
      res.end(`<style>html,body{margin:0;height:100%}iframe{border:0;width:100%;height:100%}</style><script>${hostScript}</script><iframe src="/apps/${app}/?notification_id=browser-internet:fixture&url=https%3A%2F%2Fexample.com%2Frequested&home_origin=http://127.0.0.1:${server.address().port}#home_token=fixture"></iframe>`);return;
    }
    if (url.pathname === "/api/apps/browser/internet") {
      state.reads++;
      if (input?.action === "end") {json({status:"ended"});return;}
      if (input?.action === "request") {state.requests++;state.consent="requested";}
      json({status:state.consent,request:{request_id:"fixture",text:consentText}});return;
    }
    if (url.pathname === "/api/apps/inbox/summary") {
      const pending=state.consent === "requested";
      const body=pending?consentText:state.consent === "granted"?"Browser can use the internet. Allowed with your passkey.":state.consent === "refused"?"Not allowed.":"Turned off.";
      json({notifications:{unread_count:pending?1:0,attention_count:pending?1:0,entries:[{
        id:"browser-internet:fixture",source_app:"browser",kind:pending?"browser_internet_request":"browser_internet_decision",
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
      json({engine_adapter:{adapters:[]},sessions:{schema:"elastos.browser.session-capacity/v1",status:"configured",fresh_start_allowed:true,recoverable_page:null}});return;
    }
    if (url.pathname === "/api/apps/browser/open") {
      state.opens.push(input);json({schema:"elastos.browser.open-accepted/v1",status_url:"/api/apps/browser/open/fixture"});return;
    }
    if (url.pathname === "/api/apps/browser/open/fixture") {json({schema:"elastos.browser.open-status/v1",status:"pending"});return;}
    const match=url.pathname.match(/^\/apps\/(browser|inbox|home)\/(.*)$/);
    if (!match || match[2].includes("..")) {res.writeHead(404).end();return;}
    const name=match[2] || "index.html";
    try {const bytes=readFileSync(new URL(`capsules/${match[1]}/browser/${name}`,root));res.setHeader("content-type",name.endsWith(".js")?"text/javascript":name.endsWith(".css")?"text/css":"text/html");res.end(bytes);} catch {res.writeHead(404).end();}
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
      f.state.consent="requested";f.state.opens=[];f.state.requests=0;
      const page=await browser.newPage({viewport:{width,height:844},colorScheme:"light"});
      await page.goto(f.url);const frame=page.frameLocator("iframe");
      await frame.getByRole("heading",{name:"Browser can't open websites yet"}).waitFor({timeout:4000});
      assert.equal(await frame.locator("#browser-status").isVisible(),false);
      await screen(page,"browser-blocked");
      await frame.getByRole("button",{name:"Ask in Inbox",exact:true}).click();
      await page.waitForFunction(()=>messages.some(m=>m.type==="home:open-target" && m.target==="inbox"));
      assert.equal(f.state.requests,1);assert.equal(f.state.opens.length,0);
      await frame.getByText("Waiting for your answer in Inbox.",{exact:true}).waitFor();
      await screen(page,"browser-waiting");
      await frame.getByRole("button",{name:"Browser settings",exact:true}).click();
      assert.equal(await frame.locator("#browser-internet").count(),0);
      await frame.getByText("Internet access: Off",{exact:true}).waitFor();
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
      await frame.getByText("Pages go out through",{exact:true}).waitFor();await screen(page,"browser-settings");
      const reads=f.state.reads;await page.waitForTimeout(2200);assert.equal(f.state.reads,reads,"permission poll stops after grant");
      f.state.consent="revoked";
      await frame.getByRole("button",{name:"Close Browser settings"}).click();
      await frame.getByRole("button",{name:"Browser settings",exact:true}).click();
      await frame.getByText("Internet access: Off",{exact:true}).waitFor({timeout:2000});
      await page.close();
    }
    for (const consent of ["refused","revoked"]) {
      f.state.consent=consent;
      const page=await browser.newPage();await page.goto(f.url);const frame=page.frameLocator("iframe");
      await frame.getByText("Internet access is off for Browser.",{exact:true}).waitFor();
      await frame.getByRole("button",{name:"Open Settings",exact:true}).click();await settingsMessage(page);
      const reads=f.state.reads;await page.goto("about:blank");await page.waitForTimeout(2200);
      assert.equal(f.state.reads,reads,"permission polling stops on leave");await page.close();
    }
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
      assert.deepEqual(await frame.locator("#entry-detail button").allTextContents(),["Change in Settings"]);
      await frame.locator("#entry-detail").getByRole("button",{name:"Change in Settings"}).click();await settingsMessage(page);
      assert.deepEqual(await page.evaluate(()=>approvals),answer === "Allow"?["browser.internet.grant"]:[]);
      if(answer === "Allow") await screen(page,"inbox-decided-allowed");await page.close();
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
  assert.equal(friendlyOpenError({status:403,payload:{code:"browser_internet_grant_required"}}),"Browser can't open websites yet. Allow internet access in Inbox.");
});
