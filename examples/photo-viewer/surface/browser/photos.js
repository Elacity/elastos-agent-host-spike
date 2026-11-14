// Photos: the render-only surface for the photo-viewer playlist.
//
// It holds nothing but the launch token Runtime put in this frame's fragment,
// and reads only through the two reads of the content launch it was opened
// for (viewer_gateway.rs, `viewer_launch_output` and `viewer_launch_content`):
// the playlist the photo core wrote to the launch's output, and each picture
// of the launched set by its path. A picture's path comes from its `uri`, and
// only a plain path under `elastos://launch/content/` is ever asked for: any
// other `uri` is listed as not in the set. The token reaches only that one
// launch, so no path the page builds can name anything outside the set it was
// opened with. Text from the playlist is shown with textContent only. No
// storage, no messages, no other network.
//
// Everything it touches comes in through `env` (the window in a browser), so
// the tests can drive it with a fake fetch and a fake document.

export const PLAYLIST_ROUTE = "/api/viewers/image-viewer/launch/output/playlist.json";
export const CONTENT_ROUTE = "/api/viewers/image-viewer/launch/content/";
export const LAUNCH_CONTENT = "elastos://launch/content/";
export const PLAYLIST_SCHEMA = "elastos.photo-viewer.playlist/v1";
export const TOKEN_HEADER = "x-elastos-home-token";

// The same bounds the photo-viewer core applies (examples/photo-viewer/src/lib.rs).
export const IMAGE_TYPES = ["image/png", "image/jpeg", "image/webp"];
export const MAX_ITEMS = 64;
export const MIN_DURATION_MS = 1000;
export const MAX_DURATION_MS = 60000;
export const DEFAULT_DURATION_MS = 5000;
const MAX_MESSAGE_CHARS = 200;

/** The launch token from `#home_token=...`, or "". */
export function launchToken(hash) {
  return new URLSearchParams(String(hash || "").replace(/^#/, "")).get("home_token") || "";
}

/**
 * The path of a picture in the launched set, from its `uri`: the plain path
 * after `elastos://launch/content/` (one or more parts, none empty, `.` or
 * `..`, no backslash), or null for any other `uri`.
 */
export function launchPath(uri) {
  if (typeof uri !== "string" || !uri.startsWith(LAUNCH_CONTENT)) return null;
  const path = uri.slice(LAUNCH_CONTENT.length);
  const plainPart = (part) => part !== "" && part !== "." && part !== "..";
  const plain = path !== "" && !path.includes("\\") && path.split("/").every(plainPart);
  return plain ? path : null;
}

function isPosition(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function shortText(value, fallback) {
  const text = typeof value === "string" ? value : fallback;
  return text.length > MAX_MESSAGE_CHARS ? `${text.slice(0, MAX_MESSAGE_CHARS)}…` : text;
}

/**
 * What to show, from the playlist bytes' JSON. Throws on a playlist that is
 * not one. An entry that is not a showable image of the launched set becomes a
 * "not shown" line; nothing from an entry is used except its position, its
 * path in the set, its type, size and duration.
 */
export function readPlaylist(value) {
  if (!value || typeof value !== "object" || value.schema !== PLAYLIST_SCHEMA) {
    throw new Error("This is not a Photos playlist.");
  }
  const items = Array.isArray(value.items) ? value.items : [];
  const skippedIn = Array.isArray(value.skipped) ? value.skipped : [];
  if (items.length > MAX_ITEMS) {
    throw new Error(`The playlist has more than ${MAX_ITEMS} photos.`);
  }
  const slides = [];
  const skipped = [];
  const seen = new Set();
  for (const item of items) {
    const order = item && item.order;
    if (!isPosition(order) || seen.has(order)) {
      skipped.push({ order: isPosition(order) ? order : null, message: "This entry could not be read." });
      continue;
    }
    seen.add(order);
    if (!IMAGE_TYPES.includes(item.mime)) {
      skipped.push({ order, message: "This entry is not a PNG, JPEG or WebP image." });
      continue;
    }
    const path = launchPath(item.uri);
    if (path === null) {
      skipped.push({ order, message: "This entry is not in the photo set this page was opened with." });
      continue;
    }
    const duration = Number.isSafeInteger(item.duration_ms) ? item.duration_ms : DEFAULT_DURATION_MS;
    slides.push({
      order,
      path,
      mime: item.mime,
      width: Number.isSafeInteger(item.width) ? item.width : null,
      height: Number.isSafeInteger(item.height) ? item.height : null,
      durationMs: Math.min(MAX_DURATION_MS, Math.max(MIN_DURATION_MS, duration)),
    });
  }
  for (const skip of skippedIn.slice(0, MAX_ITEMS)) {
    const order = skip && skip.order;
    skipped.push({
      order: isPosition(order) ? order : null,
      message: shortText(skip && skip.message, "Not shown."),
    });
  }
  slides.sort((a, b) => a.order - b.order);
  skipped.sort((a, b) => (a.order ?? Infinity) - (b.order ?? Infinity));
  return { slides, skipped };
}

/** The only requests this page makes. */
export function photosClient(fetchFn, token) {
  async function get(route) {
    const response = await fetchFn(route, {
      method: "GET",
      headers: { [TOKEN_HEADER]: token },
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
    });
    if (!response.ok) {
      let reason = "";
      try {
        const body = await response.json();
        reason = body && typeof body.error === "string" ? body.error : "";
      } catch {
        reason = "";
      }
      const error = new Error(shortText(reason || null, `Photos could not read this (${response.status}).`));
      error.status = response.status;
      throw error;
    }
    return response;
  }
  return {
    async playlist() {
      return (await get(PLAYLIST_ROUTE)).json();
    },
    async item(path) {
      if (launchPath(`${LAUNCH_CONTENT}${path}`) !== path) {
        throw new Error("A photo is asked for by its path in the set only.");
      }
      const route = `${CONTENT_ROUTE}${path.split("/").map(encodeURIComponent).join("/")}`;
      return (await get(route)).arrayBuffer();
    },
  };
}

/** Mounts the slideshow on `env.document`. Returns its controls (for tests). */
export function mountPhotos(env) {
  const doc = env.document;
  const byId = (id) => doc.getElementById(id);
  const view = {
    photo: byId("photo"),
    caption: byId("caption"),
    status: byId("status"),
    skipped: byId("skipped"),
    skippedTitle: byId("skipped-title"),
    previous: byId("previous"),
    pause: byId("pause"),
    next: byId("next"),
  };
  const state = { slides: [], index: 0, playing: true, url: "", timer: null, shown: 0, ready: null };
  const setStatus = (text) => {
    view.status.textContent = text;
  };

  const token = launchToken(env.location && env.location.hash);
  if (!token) {
    setStatus("Open Photos from Home.");
    state.ready = Promise.resolve();
    return controls();
  }
  const client = photosClient(env.fetch.bind(env), token);

  function renderSkipped(skipped) {
    for (const skip of skipped) {
      const line = doc.createElement("li");
      line.textContent = skip.order === null ? skip.message : `Photo ${skip.order + 1}: ${skip.message}`;
      view.skipped.appendChild(line);
    }
    view.skippedTitle.hidden = skipped.length === 0;
  }

  function schedule() {
    if (state.timer !== null) {
      env.clearTimeout(state.timer);
      state.timer = null;
    }
    const slide = state.slides[state.index];
    if (state.playing && slide && state.slides.length > 1) {
      state.timer = env.setTimeout(() => show(state.index + 1), slide.durationMs);
    }
  }

  async function show(index) {
    if (state.slides.length === 0) return;
    state.index = ((index % state.slides.length) + state.slides.length) % state.slides.length;
    const slide = state.slides[state.index];
    const ticket = ++state.shown;
    schedule();
    try {
      const bytes = await client.item(slide.path);
      if (ticket !== state.shown) return; // a later choice won
      const url = env.URL.createObjectURL(new env.Blob([bytes], { type: slide.mime }));
      if (state.url) env.URL.revokeObjectURL(state.url);
      state.url = url;
      view.photo.src = url;
      view.photo.alt = `Photo ${state.index + 1} of ${state.slides.length}`;
      view.caption.textContent =
        slide.width && slide.height
          ? `${state.index + 1} / ${state.slides.length} · ${slide.width} × ${slide.height}`
          : `${state.index + 1} / ${state.slides.length}`;
      setStatus("");
    } catch (error) {
      if (ticket !== state.shown) return;
      setStatus(error.message);
    }
  }

  function togglePause() {
    state.playing = !state.playing;
    view.pause.textContent = state.playing ? "Pause" : "Play";
    schedule();
  }

  view.previous.addEventListener("click", () => show(state.index - 1));
  view.next.addEventListener("click", () => show(state.index + 1));
  view.pause.addEventListener("click", togglePause);
  doc.addEventListener("keydown", (event) => {
    if (event.key === "ArrowLeft") show(state.index - 1);
    else if (event.key === "ArrowRight") show(state.index + 1);
    else if (event.key === " ") togglePause();
    else return;
    event.preventDefault();
  });

  state.ready = (async () => {
    try {
      const { slides, skipped } = readPlaylist(await client.playlist());
      state.slides = slides;
      renderSkipped(skipped);
      if (slides.length === 0) {
        setStatus("There are no photos to show.");
        return;
      }
      await show(0);
    } catch (error) {
      setStatus(error.message);
    }
  })();

  function controls() {
    return {
      state,
      ready: () => state.ready,
      next: () => show(state.index + 1),
      previous: () => show(state.index - 1),
      togglePause,
    };
  }
  return controls();
}
