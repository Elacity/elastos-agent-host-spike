import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { paintFrame } from "./home-frame.js";

function element(tag) {
  return {
    tag,
    textContent: "",
    children: [],
    style: {},
    dir: "",
    alt: "",
    src: "",
    appendChild(child) {
      this.children.push(child);
      return child;
    },
  };
}

function root() {
  const panel = element("section");
  panel.ownerDocument = { createElement: (tag) => element(tag) };
  panel.replaceChildren = () => {
    panel.children.length = 0;
  };
  panel.setAttribute = (name, value) => {
    panel[name] = value;
  };
  panel.removeAttribute = (name) => {
    delete panel[name];
  };
  return panel;
}

function texts(node) {
  const own = node.textContent ? [node.textContent] : [];
  return own.concat(node.children.flatMap(texts));
}

const trip = JSON.parse(
  readFileSync(
    new URL("../../../examples/docs-viewer/bus2/fixtures/trip-frame.json", import.meta.url),
    "utf8",
  ),
);

test("each kind is an element and its text is text", () => {
  const panel = root();
  paintFrame(panel, trip);
  assert.deepEqual(
    panel.children.map((child) => child.tag),
    ["h1", "p", "ul", "ol", "blockquote", "hr", "pre", "p"],
  );
  assert.equal(texts(panel.children[0]).join(""), "Trip notes");
  assert.equal(texts(panel.children[1]).join(""), "Pack boots, socks and a map.");
  assert.deepEqual(
    panel.children[1].children.map((child) => child.tag),
    ["span", "strong", "span", "em", "span", "code", "span"],
  );
  assert.equal(panel.children[2].tag, "ul");
  assert.deepEqual(panel.children[2].children.map((item) => texts(item).join("")), ["tent", "stove"]);
  assert.deepEqual(panel.children[3].children.map((item) => texts(item).join("")), ["drive", "walk"]);
  assert.equal(texts(panel.children[4]).join(""), "Leave early.");
  assert.equal(panel.children[6].children[0].tag, "code");
  assert.equal(panel.children[6].children[0].textContent, "fn go() {}");
  assert.equal(panel.children[7].textContent, "a cat");
});

test("a long token wraps at phone width and a right-to-left line stays text", () => {
  const panel = root();
  const long = "x".repeat(4000);
  const rtl = "עברית שלום";
  paintFrame(panel, {
    nodes: [
      { kind: "paragraph", spans: [{ style: "plain", text: long }] },
      { kind: "paragraph", spans: [{ style: "plain", text: rtl }] },
    ],
  });
  assert.equal(panel.children[0].children[0].textContent, long);
  assert.equal(panel.children[1].children[0].textContent, rtl);
  assert.equal(panel.dir, "auto");
  assert.equal(panel.style.maxWidth, "100%");
  assert.equal(panel.style.overflowWrap, "anywhere");
  assert.equal(panel.children[0].style.overflowWrap, "anywhere");
});

test("a script-shaped string is text and an empty image is only its name", () => {
  const panel = root();
  let reads = 0;
  const readImage = () => {
    reads += 1;
    return "blob:owner";
  };
  paintFrame(
    panel,
    {
      nodes: [
        { kind: "paragraph", spans: [{ style: "plain", text: "<script>alert(1)</script>" }] },
        { kind: "image", resource: "localhost://photo", alt: "", empty: false },
      ],
    },
    readImage,
  );
  assert.equal(panel.children[0].children[0].textContent, "<script>alert(1)</script>");
  assert.equal(panel.children[0].children[0].tag, "span");
  assert.equal(panel.children[1].tag, "img");
  assert.equal(panel.children[1].src, "blob:owner");
  assert.equal(reads, 1);
  paintFrame(
    panel,
    { nodes: [{ kind: "image", resource: "localhost://photo", alt: "a cat", empty: true }] },
    readImage,
  );
  assert.equal(panel.children[0].tag, "p");
  assert.equal(panel.children[0].textContent, "a cat");
  assert.equal(reads, 1);
  paintFrame(panel, {
    nodes: [{ kind: "image", resource: "localhost://photo", alt: "", empty: false }],
  });
  assert.equal(panel.children[0].textContent, "localhost://photo");
  const source = readFileSync(new URL("./home-frame.js", import.meta.url), "utf8");
  assert.equal(source.includes("innerHTML"), false);
  assert.equal(source.includes("outerHTML"), false);
  assert.equal(source.includes("href"), false);
  assert.equal(source.includes("fetch("), false);
  assert.equal(source.includes("http://"), false);
});
