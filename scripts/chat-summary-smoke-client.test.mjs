import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import test from "node:test";

import { chatSummaryRequest, readChatSummary } from "./chat-summary-smoke-client.mjs";

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
