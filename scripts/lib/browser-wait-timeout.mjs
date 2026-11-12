// Timeout for a browser check's wait on a DOM condition.
//
// The waits in the product-ui-browser smokes carry a short explicit timeout so
// a wrong page fails quickly. On a shared CI runner the page can be slow to
// paint without being wrong, so the same predicate gets more time there. The
// predicate never changes: only the time it is allowed.
//
// ELASTOS_BROWSER_TIMEOUT_MS names the time directly, CI (set by the runner)
// allows 15 s, and a local run keeps 5 s. A CI of "false" or "0" counts as off,
// as it does for tools that read the variable as a switch.

export const LOCAL_WAIT_TIMEOUT_MS = 5000;
export const CI_WAIT_TIMEOUT_MS = 15000;

function ciEnabled(value) {
  if (value === undefined || value === null) {
    return false;
  }
  const text = String(value).trim().toLowerCase();
  return text !== "" && text !== "0" && text !== "false";
}

export function browserWaitTimeoutMs(env = process.env) {
  const named = env.ELASTOS_BROWSER_TIMEOUT_MS;
  if (named !== undefined && named.trim() !== "") {
    const parsed = Number(named);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      throw new Error(`ELASTOS_BROWSER_TIMEOUT_MS must be a positive number of milliseconds. Got ${JSON.stringify(named)}`);
    }
    return Math.round(parsed);
  }
  return ciEnabled(env.CI) ? CI_WAIT_TIMEOUT_MS : LOCAL_WAIT_TIMEOUT_MS;
}
