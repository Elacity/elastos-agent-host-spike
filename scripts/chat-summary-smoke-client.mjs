import http from "node:http";
import https from "node:https";

export function readLaunchToken(launchRoute, homeOrigin, actor) {
  const launch = new URL(launchRoute, homeOrigin);
  if (launch.origin !== homeOrigin || launch.pathname !== `/apps/${actor}/`) {
    throw new Error(`${actor} launch returned an unexpected route`);
  }
  const token = new URLSearchParams(launch.hash.slice(1)).get("home_token");
  if (!token) {
    throw new Error(`${actor} launch did not return a home token`);
  }
  return token;
}

export function redactLaunchTokens(value) {
  return String(value).replace(/(#home_token=)[^&\s"'\\<>]*/g, "$1[REDACTED]");
}

export function chatSummaryRequest(launchRoute, homeOrigin) {
  const token = readLaunchToken(launchRoute, homeOrigin, "chat-room");
  return {
    url: new URL("/api/apps/chat-room/summary", homeOrigin),
    options: {
      method: "GET",
      headers: { origin: "null", "x-elastos-home-token": token },
    },
  };
}

export function readChatSummary(launchRoute, homeOrigin, requestImpl) {
  const { url, options } = chatSummaryRequest(launchRoute, homeOrigin);
  const request = requestImpl || (url.protocol === "https:" ? https.request : http.request);
  return new Promise((resolve, reject) => {
    const req = request(url, options, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("error", reject);
      response.on("end", () => {
        if (response.statusCode !== 200) {
          reject(new Error(`Chat summary failed: ${response.statusCode}`));
          return;
        }
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
        } catch (error) {
          reject(error);
        }
      });
    });
    req.on("error", reject);
    req.setTimeout(30_000, () => req.destroy(new Error("Chat summary timed out")));
    req.end();
  });
}
