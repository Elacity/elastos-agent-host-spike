// Pure checks for the installed U3 journey. The runner applies them.
// This file does not start a Home.

import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const PAGE_FOLDERS = ["home", "system", "inbox", "home-gui"];

function sha1Git(type, data) {
  const header = Buffer.from(`${type} ${data.length}\0`);
  return crypto.createHash("sha1").update(header).update(data).digest("hex");
}

// Git's tree id for a directory. A directory name sorts as if it ended in "/".
export function gitTreeHash(dir) {
  const rows = fs.readdirSync(dir, { withFileTypes: true }).map((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isSymbolicLink()) {
      return {
        name: entry.name,
        mode: "120000",
        hash: sha1Git("blob", Buffer.from(fs.readlinkSync(full))),
      };
    }
    if (entry.isDirectory()) {
      return { name: entry.name, mode: "40000", hash: gitTreeHash(full) };
    }
    if (!entry.isFile()) throw new Error(`unsupported installed file: ${entry.name}`);
    const stat = fs.lstatSync(full);
    const mode = (stat.mode & 0o111) !== 0 ? "100755" : "100644";
    return { name: entry.name, mode, hash: sha1Git("blob", fs.readFileSync(full)) };
  });
  rows.sort((left, right) => {
    const leftKey = Buffer.from(left.mode === "40000" ? `${left.name}/` : left.name);
    const rightKey = Buffer.from(right.mode === "40000" ? `${right.name}/` : right.name);
    return Buffer.compare(leftKey, rightKey);
  });
  const body = Buffer.concat(rows.map((row) => Buffer.concat([
    Buffer.from(`${row.mode} ${row.name}\0`),
    Buffer.from(row.hash, "hex"),
  ])));
  return sha1Git("tree", body);
}

export function committedTree(repoRoot, folder) {
  const listed = spawnSync("git", ["rev-parse", `HEAD:capsules/${folder}`], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  if (listed.status !== 0) return "";
  return listed.stdout.trim();
}

// One hash per copied page folder. It is the hash of the installed bytes.
export function pageFolderProof(repoRoot, dataDir) {
  const pages = {};
  let ok = true;
  for (const folder of PAGE_FOLDERS) {
    let installed = "";
    try {
      installed = gitTreeHash(path.join(dataDir, "capsules", folder));
    } catch {
      installed = "";
    }
    const tree = committedTree(repoRoot, folder);
    const equal = installed.length > 0 && installed === tree;
    if (!equal) ok = false;
    pages[folder] = { installed, committed: tree, equal };
  }
  return { ok, pages };
}

export function gitPorcelain(repoRoot) {
  const listed = spawnSync("git", ["status", "--porcelain"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  if (listed.status !== 0) {
    return { ok: false, text: String(listed.stderr || "git status failed").slice(0, 500) };
  }
  return { ok: listed.stdout.length === 0, text: listed.stdout };
}

export function playwrightPin(text) {
  const versions = [
    ...String(text).matchAll(/installed[^\n]*\splaywright\s+(\d+\.\d+\.\d+)/g),
    ...String(text).matchAll(/playwright@(\d+\.\d+\.\d+)/g),
  ].map((match) => match[1]);
  if (versions.length === 0 || versions.some((version) => version !== versions[0])) {
    return { ok: false, version: "" };
  }
  return { ok: true, version: versions[0] };
}

function behaviourInputsFromHome(home) {
  return home ? path.join(home, ".cache", "elastos-runtime", "behaviour") : "";
}

function behaviourInputsReady(dir) {
  return Boolean(dir) && fs.existsSync(path.join(dir, "browser", "node_modules", "playwright", "package.json"));
}

// The same inputs path as scripts/test-behaviour.sh. An account home is
// checked when HOME does not already hold those inputs. No user path is built in.
export function behaviourInputsDir(env) {
  if (env.BEHAVIOUR_INPUTS) return env.BEHAVIOUR_INPUTS;
  if (env.RUNNER_TEMP && behaviourInputsReady(path.join(env.RUNNER_TEMP, "behaviour"))) {
    return path.join(env.RUNNER_TEMP, "behaviour");
  }
  const homes = [];
  if (env.HOME) homes.push(env.HOME);
  try {
    const passwd = os.userInfo().homedir;
    if (passwd && !homes.includes(passwd)) homes.push(passwd);
  } catch { /* no passwd entry */ }
  for (const home of homes) {
    const inputs = behaviourInputsFromHome(home);
    if (behaviourInputsReady(inputs)) return inputs;
  }
  if (env.RUNNER_TEMP) return path.join(env.RUNNER_TEMP, "behaviour");
  return behaviourInputsFromHome(env.HOME);
}

// Mac only. Playwright's own browser cache lives under Library/Caches.
export function macPlaywrightBrowserCache(env = process.env) {
  if (process.platform !== "darwin") return "";
  const homes = [];
  try {
    const passwd = os.userInfo().homedir;
    if (passwd) homes.push(passwd);
  } catch { /* no passwd entry */ }
  if (env.HOME && !homes.includes(env.HOME)) homes.push(env.HOME);
  for (const home of homes) {
    const cache = path.join(home, "Library", "Caches", "ms-playwright");
    if (fs.existsSync(cache)) return cache;
  }
  return "";
}

export function headlessShellRevision(playwrightDir) {
  const candidates = [
    path.join(playwrightDir, "node_modules", "playwright-core", "browsers.json"),
    path.join(playwrightDir, "..", "playwright-core", "browsers.json"),
  ];
  for (const file of candidates) {
    if (!fs.existsSync(file)) continue;
    const body = JSON.parse(fs.readFileSync(file, "utf8"));
    const row = (body.browsers || []).find((item) => item.name === "chromium-headless-shell");
    if (row?.revision) return String(row.revision);
  }
  return "";
}

export function packageVersion(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8")).version || "";
  } catch {
    return "";
  }
}

// Inherited ELASTOS_* stays out. The quiet flag is set here, not copied.
export function homeProcessEnv(homeDir, inherited = process.env) {
  const env = {};
  for (const key of ["PATH", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "USER", "LOGNAME"]) {
    const value = inherited[key];
    if (typeof value === "string" && value.length > 0) env[key] = value;
  }
  env.HOME = homeDir;
  env.ELASTOS_QUIET_RUNTIME_NOTICES = "1";
  return env;
}

export function redactDidAndAddress(text) {
  return String(text)
    .replace(/did:key:z[1-9A-HJ-NP-Za-km-z]+/g, "did:key:redacted")
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b/g, "[address]")
    .replace(/\[[0-9a-fA-F:.]+\](?::\d{1,5})?/g, "[address]");
}

export function redactInstall(install) {
  const copy = install && typeof install === "object" ? structuredClone(install) : {};
  if (Object.prototype.hasOwnProperty.call(copy, "signer_did")) copy.signer_did = "redacted";
  return JSON.parse(redactDidAndAddress(JSON.stringify(copy)));
}

export function localUdpPort(name) {
  const local = String(name || "").split("->")[0].trim();
  const match = local.match(/:(\d+)$/);
  return match ? Number(match[1]) : null;
}

export function bindsPort(names, port) {
  return (names || []).some((name) => localUdpPort(name) === port);
}

export const CARRIER_BIND = "127.0.0.1:0";
export const CARRIER_MODE = "ephemeral-loopback";

// Carrier is not disabled. This line asks it for a free loopback port.
export function carrierConfigOk(text) {
  return String(text || "").trim() === `carrier_bind_addr = "${CARRIER_BIND}"`;
}

export function listedAgentsMatch(body, expected) {
  const agents = body?.agents;
  const wanted = Array.isArray(expected) ? expected : [];
  if (!Array.isArray(agents) || wanted.length === 0) {
    return { ok: false, reason: "agents list missing" };
  }
  if (agents.length !== wanted.length) return { ok: false, reason: "list length" };
  const seen = new Set();
  for (const want of wanted) {
    if (!want?.id || seen.has(want.id)) return { ok: false, reason: "id" };
    const row = agents.find((item) => item?.agent_id === want.id);
    if (!row) return { ok: false, reason: "id" };
    seen.add(want.id);
    if (row.display_name !== want.name) return { ok: false, reason: "name" };
    if (row.active !== want.active) return { ok: false, reason: "active" };
  }
  if (seen.size !== agents.length) return { ok: false, reason: "extra" };
  return { ok: true, reason: "" };
}

// Stricter than either observation on its own: strays must be empty, and a
// running serve must have a listed capsule set with no guest.
export function noGuestProof(input) {
  const stray = Array.isArray(input?.stray) ? input.stray : null;
  if (!stray || input?.serveKnown !== true) {
    return { ok: false, reason: "process list is missing" };
  }
  if (input.serveRunning === true && input.capsulesListed !== true) {
    return { ok: false, reason: "serve is running and its capsules cannot be listed" };
  }
  if (stray.length > 0) return { ok: false, reason: "stray processes remain" };
  if (input.serveRunning === true && input.guestCapsules !== 0) {
    return { ok: false, reason: "a listed capsule is a guest" };
  }
  return { ok: true, reason: "" };
}

export function guestCapsuleCount(rows, agentIds) {
  const ids = (agentIds || []).filter((id) => typeof id === "string" && id.length > 0);
  return (rows || []).filter((row) => {
    const live = row?.status === "starting" || row?.status === "running";
    if (!live) return false;
    const blob = JSON.stringify(row);
    if (blob.includes("agent-host")) return true;
    return ids.some((id) => blob.includes(id));
  }).length;
}

export function judgeCreatingOwner(input) {
  if (input?.checkRan !== true) return { ok: false, reason: "owner check skipped" };
  const stored = input.storedOwner;
  const product = input.productOwner;
  const fileOwner = input.fileOwner;
  if (typeof stored !== "string" || !stored.startsWith("person:local:") || stored !== product) {
    return { ok: false, reason: "stored owner is not the product caller" };
  }
  if (stored !== fileOwner || product !== fileOwner) {
    return { ok: false, reason: "stored owner is not the auth file admin" };
  }
  return { ok: true, reason: "" };
}

// The launch route is the agents-in-gateway change when the gateway starts
// the guest through the in-process agent plane. The home runtime must call
// the plane's live coordinates and define a launch function with a body.
// The gateway source must dispatch the approved plan.
export function agentsInGatewayChange(gatewaySource, launchSource, homeRuntimeSource) {
  const route = "/api/apps/system/agents/launch";
  const gateway = String(gatewaySource || "");
  const registered = gateway.includes(`"${route}"`);
  const dispatch = gateway.includes("dispatch_approved_agent_plan");
  const text = String(launchSource || "");
  const asksPlane = text.includes("launch_runtime_agent") && text.includes("agent_plane::");
  const home = String(homeRuntimeSource || "");
  const liveCoords = home.includes("agent_plane::live_coords");
  const emptyLaunch = /async fn launch_runtime_agent\s*\([^)]*\)\s*\{\s*\}/.test(home);
  const hop = home.includes("async fn launch_runtime_agent") && !emptyLaunch;
  const ok = registered && dispatch && asksPlane && liveCoords && hop;
  let reason = "";
  if (!registered) reason = "the launch route is not registered";
  else if (!dispatch) reason = "the gateway does not dispatch the approved plan";
  else if (!asksPlane) reason = "the launch route does not start the agent on the in-process plane";
  else if (!liveCoords) reason = "the launch does not call the plane's live coordinates";
  else if (emptyLaunch) reason = "launch_runtime_agent is empty";
  else if (!hop) reason = "gateway_home_runtime.rs does not define launch_runtime_agent";
  return { ok, route, reason };
}

// The gateway process owns the port named in agent-runtime-coords.json.
// macOS asks lsof. Linux reads /proc. The arguments are fixed. No shell.
export function gatewayOwnsListener(pid, port) {
  const id = Number(pid);
  const listen = Number(port);
  if (!Number.isInteger(id) || id <= 0 || !Number.isInteger(listen) || listen <= 0 || listen > 65535) {
    return false;
  }
  if (process.platform === "darwin") {
    const result = spawnSync("lsof", [
      "-nP", "-a", "-p", String(id), `-iTCP:${listen}`, "-sTCP:LISTEN",
    ], { encoding: "utf8" });
    return result.status === 0;
  }
  if (process.platform === "linux") return linuxOwnsListener(id, listen);
  return false;
}

function linuxOwnsListener(pid, port) {
  const portHex = port.toString(16).toUpperCase().padStart(4, "0");
  const inodes = new Set();
  for (const name of ["tcp", "tcp6"]) {
    let text = "";
    try {
      text = fs.readFileSync(`/proc/net/${name}`, "utf8");
    } catch {
      continue;
    }
    for (const line of text.split("\n").slice(1)) {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 10 || parts[3] !== "0A") continue;
      const hexPort = (parts[1] || "").split(":")[1] || "";
      if (hexPort.toUpperCase() !== portHex) continue;
      inodes.add(parts[9]);
    }
  }
  if (inodes.size === 0) return false;
  let fds = [];
  try {
    fds = fs.readdirSync(`/proc/${pid}/fd`);
  } catch {
    return false;
  }
  for (const fd of fds) {
    let link = "";
    try {
      link = fs.readlinkSync(`/proc/${pid}/fd/${fd}`);
    } catch {
      continue;
    }
    const match = /^socket:\[(\d+)\]$/.exec(link);
    if (match && inodes.has(match[1])) return true;
  }
  return false;
}

export const FULL_MODE_NOTICE = "Full mode needs the agents-in-gateway change. It is not proof of anything until that change is in the gateway.";

// The installed path contains a space (Application Support). Splitting the
// command on whitespace would read that space as the subcommand.
export function elastosSubcommand(command, binaries) {
  const text = String(command || "").trim();
  const prefixes = (Array.isArray(binaries) ? binaries : [binaries])
    .filter((item) => typeof item === "string" && item.length > 0);
  for (const prefix of prefixes) {
    if (text === prefix) return "elastos";
    if (text.startsWith(`${prefix} `)) {
      const next = text.slice(prefix.length).trim().split(/\s+/)[0];
      return next || "elastos";
    }
  }
  return "";
}

export function executableInsideHome(exe, home) {
  if (typeof exe !== "string" || typeof home !== "string") return false;
  const cleaned = exe.replace(/ \(deleted\)$/, "").trim();
  if (cleaned.length === 0 || home.length === 0) return false;
  const root = path.resolve(home);
  const file = path.resolve(cleaned);
  return file === root || file.startsWith(root + path.sep);
}

export function throwawayAllowed(home, scratch) {
  let homeReal;
  let scratchReal;
  try {
    homeReal = fs.realpathSync(home);
    scratchReal = fs.realpathSync(scratch);
  } catch {
    return false;
  }
  const relative = path.relative(scratchReal, homeReal);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) return false;
  const marker = path.join(homeReal, ".a15r-throwaway");
  if (!fs.existsSync(marker)) return false;
  let marked = "";
  try {
    marked = fs.realpathSync(fs.readFileSync(marker, "utf8").trim());
  } catch {
    return false;
  }
  return marked === homeReal;
}

export function removeStaleReceipt(dir) {
  const file = path.join(dir, "receipt.json");
  if (fs.existsSync(file)) fs.rmSync(file, { force: true });
  return !fs.existsSync(file);
}
