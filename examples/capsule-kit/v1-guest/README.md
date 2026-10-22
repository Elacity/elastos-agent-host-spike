# Bus v1 guest sources (kit item A1)

One copy of the Bus v1 guest code every component capsule here shares. A guest links these files into its
own `src/` with a relative symlink, so they are compiled as that guest's own modules:

| File | Linked as | What |
|---|---|---|
| `bus.rs` | `src/bus.rs` | The `Bus` trait, the read window, the write, the one-pass reply parser |
| `component.rs` | `src/component.rs` | `WitBus`: `Bus` over the generated `elastos:bus@v1` imports. Needs `wit_bindgen::generate!` for `product-capsule-v1` at the crate root, and `#[cfg(target_arch = "wasm32")] mod component;` |
| `fake.rs` | `src/fake.rs` | `FakeBus`, the fake Runtime for guest tests (`#[cfg(test)] mod fake;`) |

Used by `examples/photo-viewer` and `examples/docs-viewer`.

## Why links, not a crate or `#[path]`

The photo viewer's guest is named by its hash (`add93842…`). Both other ways change that hash with no change
to what the guest does:

- **`#[path = "../../capsule-kit/v1-guest/bus.rs"] mod bus;`** with the same bytes gave `606e1587…`. The
  source path reaches LLVM's internal symbol suffixes, and those change the layout.
- **A separate crate** changes every symbol's crate name, and so the link order.

A link keeps the path rustc sees (`src/bus.rs`), and the hash stays `add93842…`.

## What is not here, and why

- **`Refusal`, `grant`, `read_at`, `read_bounded`, the URI check.** Each viewer keeps its own. Moving them
  into a module (even with the same text) changes their symbol paths, and the photo guest's hash: moving
  only the three read helpers gave `c5114d14…`. They also carry each app's name in their messages.
- **The cheaper write.** The documents viewer wrote its output straight into a string instead of a
  `serde_json::Value` per byte (its worst shelf: 52.9% of the fuel, against 63.3% with this `bus.rs`). One
  `bus.rs` means one write. Taking the cheaper one changes the photo guest's bytes, so it waits for a photo
  release that may take a new hash.
