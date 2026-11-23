import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import test from "node:test";

import { chatSummaryRequest, readChatSummary, readLaunchToken, redactLaunchTokens } from "./chat-summary-smoke-client.mjs";

const origin = "http://localhost:8090";
const launchRoute = "/apps/chat-room/?home_origin=http%3A%2F%2Flocalhost%3A8090#home_token=chat%2Blaunch";

test("Chat summary reads the fragment token and sends the opaque Origin", async () => {
  const { url, options } = chatSummaryRequest(launchRoute, origin);
  assert.equal(url.href, `${origin}/api/apps/chat-room/summary`);
  assert.deepEqual(options, {
    method: "GET",
    headers: { origin: "null", "x-elastos-home-token": "chat+launch" },
  });

  let called = false;
  const summary = await readChatSummary(launchRoute, origin, (requestedUrl, requestedOptions, callback) => {
    called = true;
    assert.equal(requestedUrl.href, url.href);
    assert.deepEqual(requestedOptions, options);
    const req = new EventEmitter();
    req.setTimeout = () => req;
    req.end = () => {
      const response = Readable.from([Buffer.from(JSON.stringify({ room_slug: "chat-room" }))]);
      response.statusCode = 200;
      callback(response);
    };
    return req;
  });
  assert.equal(called, true);
  assert.deepEqual(summary, { room_slug: "chat-room" });
});

test("Chat summary rejects a query-only token or another launch route", () => {
  assert.throws(() => chatSummaryRequest("/apps/chat-room/?home_token=query-only", origin), /did not return a home token/);
  assert.throws(() => chatSummaryRequest("/apps/inbox/#home_token=other-actor", origin), /unexpected route/);
});

test("launch token reader accepts each actor's fragment and checks the route", () => {
  for (const actor of ["chat-room", "inbox", "system", "documents", "home-cli", "library"]) {
    assert.equal(readLaunchToken(`/apps/${actor}/?view=read#home_token=${actor}%2Bgrant`, origin, actor), `${actor}+grant`);
    assert.throws(() => readLaunchToken(`/apps/${actor}/?home_token=query-only`, origin, actor), /did not return a home token/);
    assert.throws(() => readLaunchToken(`/apps/other/#home_token=wrong-actor`, origin, actor), /unexpected route/);
  }
  assert.equal(readLaunchToken("/apps/inbox/?home_token=stale-query#home_token=fragment-grant", origin, "inbox"), "fragment-grant");
  assert.throws(() => readLaunchToken(`https://other.example/apps/inbox/#home_token=wrong-origin`, origin, "inbox"), /unexpected route/);
  assert.throws(() => readLaunchToken("/apps/inbox/#home_token=", origin, "inbox"), /did not return a home token/);
});

test("launch token reader also runs inside a frame evaluation", () => {
  const win = { location: { href: `${origin}/apps/system/#home_token=frame%2Bgrant`, origin } };
  const browserRead = new Function("win", `return (${readLaunchToken.toString()})(win.location.href, win.location.origin, "system")`);
  assert.equal(browserRead(win), "frame+grant");
});

test("failure output redacts fragment tokens", () => {
  const detail = JSON.stringify({ route: "/apps/inbox/#home_token=secret%2Bgrant&view=all" });
  const redacted = redactLaunchTokens(detail);
  assert.equal(redacted, '{"route":"/apps/inbox/#home_token=[REDACTED]&view=all"}');
  assert.equal(redactLaunchTokens("Error at /apps/chat-room/#home_token=another-secret"), "Error at /apps/chat-room/#home_token=[REDACTED]");
});
