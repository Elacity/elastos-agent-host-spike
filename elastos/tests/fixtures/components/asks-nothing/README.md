# The asks-nothing component fixture

This folder is test input, not an installable product capsule.

It is the smallest bundle a start by CID takes: a manifest that uses only keys
on that start's closed list, and a component that imports only the bus types,
exports the lifecycle `run`, and returns success. It calls nothing, so it
needs no person, no bridge and no grant. A run of it ends well.

- `asks-nothing.wat`: the component as WebAssembly text. This is the source.
- `bundle/`: the bundle itself, and nothing else. A bundle's CID is the CID
  of every file in its folder, so this README and the text are kept outside
  it.
  - `bundle/asks-nothing.component.wasm`: the same component as a binary
    file, so that the folder can be staged and started as it is, with the
    same bytes and therefore the same CID on every machine.
  - `bundle/capsule.json`: its manifest.

The binary is not built by a script. A test in the server
(`bundle_start_tests.rs`, `the_asks_nothing_fixture_is_its_text_and_has_its_recorded_cid`)
turns the text into a component with the `wat` crate and compares the result,
byte for byte, with the committed file; and it holds the bundle's CID to a
constant recorded in that test. That constant was not taken from the code
under test: it comes from the Python rule for a bundle's CID in
`lab/capsule-identity/README.md`, run over the two files of `bundle/`. So the
file cannot drift from its text, and a change to the text, the binary or the
manifest shows as a failing test. To change the fixture: edit the text, run
that test, write the bytes it reports into the binary file, compute the new
CID with the Python rule, and record it.

The other component fixture, `../bus-v1`, calls the bus and insists on its own
person; this one is for runs that must end well with no authority at all.
