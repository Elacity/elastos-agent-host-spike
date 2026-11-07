/* Opens the built page again. This is not Assistant and not the store. */

export function appendDemoCard(grid, hideLauncher) {
  const template = document.querySelector("#launcher-item-template");
  if (!template || !grid || grid.querySelector("[data-target='demo']")) {
    return;
  }
  const card = template.content.firstElementChild.cloneNode(true);
  card.dataset.target = "demo";
  card.dataset.search = "demo";
  card.title = "The built page";
  const icon = card.querySelector(".launcher-item-icon");
  if (icon) {
    icon.textContent = "D";
  }
  const title = card.querySelector(".launcher-card-title");
  if (title) {
    title.textContent = "Demo";
  }
  card.setAttribute("aria-label", "Open Demo");
  card.addEventListener("click", () => {
    hideLauncher?.();
    openDemoWindow();
  });
  grid.appendChild(card);
}

function demoHeading(text) {
  const match = /^<h1>([^<]*)<\/h1>$/.exec(text);
  return match ? match[1] : text;
}

async function openDemoWindow() {
  const existing = document.querySelector("#demo-app-window");
  if (existing) {
    existing.hidden = false;
    existing.removeAttribute("aria-hidden");
    return;
  }
  const template = document.querySelector("#window-template");
  const desktop = document.querySelector("#desktop");
  if (!template || !desktop) {
    return;
  }
  let text = "";
  try {
    const response = await fetch(new URL("./file-versions.json", import.meta.url));
    if (response.ok) {
      const saved = await response.json();
      const observations = Array.isArray(saved?.observations) ? saved.observations : [];
      const last = observations[observations.length - 1];
      text = typeof last?.text === "string" ? last.text : "";
    }
  } catch (_error) {
    text = "";
  }
  const node = template.content.firstElementChild.cloneNode(true);
  node.id = "demo-app-window";
  node.hidden = false;
  node.removeAttribute("aria-hidden");
  node.style.left = "180px";
  node.style.top = "72px";
  node.style.width = "720px";
  node.style.height = "480px";
  node.style.zIndex = "30";
  const title = node.querySelector(".window-head-title");
  if (title) {
    title.textContent = "Demo";
  }
  const body = node.querySelector(".window-body");
  if (body) {
    body.classList.add("window-body-frame");
    const page = document.createElement("div");
    page.className = "demo-app-page";
    const heading = document.createElement("h1");
    heading.textContent = demoHeading(text);
    page.appendChild(heading);
    body.appendChild(page);
  }
  node.querySelector("[data-action='close']")?.addEventListener("click", () => {
    node.remove();
  });
  desktop.appendChild(node);
}
