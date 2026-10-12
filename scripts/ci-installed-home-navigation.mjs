import assert from "node:assert/strict";
import { join } from "node:path";

export async function returnInstalledHome(page, assistant, evidence, timeout = 10000) {
  // Assistant owns the visible Home control while Home's dock is hidden.
  await assistant.locator("#agent-shelf-flip-back").click({ timeout });
  const shell = page.frameLocator("#active-shell-frame");
  await shell.locator("#assistant-space").waitFor({ state: "hidden", timeout });
  await shell.locator("#desktop").waitFor({ state: "visible", timeout });
  assert.equal(await page.getAttribute("body", "data-home-status"), "ready");
  await page.screenshot({ path: join(evidence, "finite-home-recovery.png"), fullPage: true });
}
