import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync, mkdirSync } from "node:fs";
import http from "node:http";
import test from "node:test";
const require = createRequire(new URL("../elastos/tools/browser-playwright-engine/package.json", import.meta.url));
const { chromium } = require("playwright");
const root = new URL("../", import.meta.url);

test("updated Home shows one Browser permission request before any engine open, with Inbox and Off controls", async () => {
  let consent="off", requests=0, opens=0;
  const server=http.createServer(async (req,res) => {
    const url=new URL(req.url,"http://localhost");
    const json=value=>{res.setHeader("content-type","application/json");res.end(JSON.stringify(value));};
    if (url.pathname === "/") {
      res.setHeader("content-type","text/html");
      res.end(`<script>window.messages=[];addEventListener('message',e=>messages.push(e.data))</script><iframe style="border:0;width:100%;height:95vh" src="/apps/browser/?home_origin=http://127.0.0.1:${server.address().port}#home_token=fixture"></iframe>`);return;
    }
    if (url.pathname === "/api/apps/browser/internet") {
      if (req.method === "POST") {
        let body="";for await (const chunk of req) body+=chunk;
        const input=JSON.parse(body);
        if (!input || typeof input !== "object" || !["request","end"].includes(input.action)) {res.statusCode=422;json({message:"Expected an action object"});return;}
        const action=input.action;
        if (action === "end") {json({status:"ended"});return;}
      }
      if (consent === "off") {consent="requested";requests++;}
      json({status:consent});return;
    }
    if (url.pathname === "/api/apps/browser/summary") {
      json({engine_adapter:{adapters:[]},sessions:{schema:"elastos.browser.session-capacity/v1",status:"configured",fresh_start_allowed:true,recoverable_page:null}});return;
    }
    if (url.pathname === "/api/apps/browser/open") {
      opens++;res.statusCode=503;
      json({schema:"elastos.browser.open-error/v1",code:"provider_error",message:"Fixture Engine is unavailable.",outcome:{schema:"elastos.browser.open-outcome/v1",state:"terminal_pre_effect_failure",effects:{page_acquired:false,vm_acquired:false,stream_acquired:false}}});return;
    }
    const match=url.pathname.match(/^\/apps\/(browser|home)\/(.*)$/);
    if (!match || match[2].includes("..")) {res.writeHead(404).end();return;}
    const name=match[2] || "index.html";
    try {const bytes=readFileSync(new URL(`capsules/${match[1]}/browser/${name}`,root));res.setHeader("content-type",name.endsWith(".js")?"text/javascript":name.endsWith(".css")?"text/css":"text/html");res.end(bytes);} catch {res.writeHead(404).end();}
  });
  await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
  const browser=await chromium.launch({headless:true});
  try {
    for (const width of [1280,390]) {
      const page=await browser.newPage({viewport:{width,height:844}});
      await page.goto(`http://127.0.0.1:${server.address().port}/`);
      const frame=page.frameLocator("iframe");
      await frame.locator("#browser-internet-request").waitFor({state:"visible"});
      await frame.locator("#browser-settings").click();
      await frame.locator("#browser-settings-close").click({timeout:3000});
      assert.match(await frame.locator("#browser-internet-request").innerText(),/this computer's internet connection.*turn it off in Browser Settings/s);
      assert.equal(await frame.locator("#browser-url").isDisabled(),true,"address stays disabled until permission is active");
      assert.equal(opens,0);
      assert.equal(requests,1);
      await frame.locator("#browser-internet-review").click();
      await page.waitForFunction(()=>messages.some(m=>m.type==="home:open-target" && m.target==="inbox"), null, {timeout:3000});
      assert.equal(requests,1);
      if (process.env.BROWSER_INTERNET_SCREENSHOTS) {
        mkdirSync(process.env.BROWSER_INTERNET_SCREENSHOTS,{recursive:true});
        await page.screenshot({path:`${process.env.BROWSER_INTERNET_SCREENSHOTS}/browser-internet-${width}.png`});
      }
      await page.close();
    }
    const page=await browser.newPage();
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    const frame=page.frameLocator("iframe");
    await frame.locator("#browser-internet-request").waitFor({state:"visible"});
    consent="granted";
    await Promise.all([
      page.waitForResponse(response=>response.url().endsWith("/api/apps/browser/open")),
      frame.locator("#browser-internet-retry").click(),
    ]);
    await frame.locator("#browser-url").waitFor();
    await page.waitForFunction(()=>document.querySelector("iframe").contentDocument.querySelector("#browser-url").disabled === false);
    assert.equal(opens,1);
    assert.equal(await frame.locator("#browser-internet-request").isVisible(),false);
    await frame.locator("#browser-settings").click();
    await frame.locator("#browser-internet").selectOption("off");
    await page.waitForFunction(()=>messages.some(m=>m.type==="home:open-target" && m.target==="system" && m.query.settings==="security"));
  } finally {await browser.close();await new Promise(resolve=>server.close(resolve));}
});


test("System retries an incomplete Stop after refresh without a second approval", async () => {
  const {startSystemFixtureServer,makeSystemSummary,makeAppearanceRecord,jsonResponse} = await import("./system-uiux-fixture.mjs");
  let stopped=false, pending=false, writes=0;
  const server=await startSystemFixtureServer({title:"Browser permission Stop",hostScript:`window.approvals=0;addEventListener('message',e=>{if(e.data?.type!=="elastos.home.passkey-step-up.request/v1")return;approvals++;e.source.postMessage({type:"elastos.home.passkey-step-up.result/v1",requestId:e.data.requestId,stepUpToken:"fixture-step-up"},"*")})`,
    async onApiRequest({request,response,url}) {
      if(url.pathname==="/api/apps/system/summary") {const summary=makeSystemSummary(makeAppearanceRecord());summary.access.role="admin";jsonResponse(response,summary);return true;}
      if(url.pathname!=="/api/apps/browser/internet")return false;
      if(request.method==="POST") {
        let body="";for await(const part of request)body+=part;
        const input=JSON.parse(body);writes++;assert.equal(input.action,"revoke");
        if(writes===1){assert.equal(input.step_up_token,"fixture-step-up");stopped=true;pending=true;jsonResponse(response,{status:"stop_incomplete"},409);}
        else {assert.equal(input.step_up_token,undefined);pending=false;jsonResponse(response,{status:"revoked",revoke_list:"persisted"});}
      } else jsonResponse(response,{status:stopped?"revoked":"granted",stop_pending:pending,request:{resource:"elastos://browser/internet",grant_id:"fixture"}});
      return true;
    }});
  const browser=await chromium.launch({headless:true});
  try {
    const page=await browser.newPage();await page.goto(`${server.baseUrl}/fixture?settings=security`);
    let frame=page.frameLocator("#system-frame");
    await frame.locator("#browser-internet-stop").click();
    await frame.locator("#browser-internet-status").filter({hasText:"Stop was not confirmed"}).waitFor();
    await page.reload();frame=page.frameLocator("#system-frame");
    await frame.locator("#browser-internet-stop").click({timeout:3000});
    await frame.locator("#browser-internet-status").filter({hasText:"Browser internet access is off."}).waitFor();
    assert.equal(writes,2);assert.equal(await page.evaluate(()=>approvals),0,"retry after reload uses existing revoked decision");
    assert.equal(await frame.locator("#browser-internet-stop").isDisabled(),true);
    assert.deepEqual(server.requestFailures,[]);
  } finally {await browser.close();await server.close();}
});


test("internet grant refusal explains the permission request", async () => {
  const {friendlyOpenError} = await import("../capsules/browser/browser/browser-status.js");
  for (const state of [undefined, "terminal_pre_effect_failure"]) {
    const message = friendlyOpenError({status:403,payload:{code:"browser_internet_grant_required",outcome:state ? {state,effects:{page_acquired:false,vm_acquired:false,stream_acquired:false}} : undefined}});
    assert.equal(message,"Browser needs the Home owner's permission. Review the request in Inbox, then open Browser after approval.");
  }
});
