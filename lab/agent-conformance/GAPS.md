# Probe boundary

AC-002-ARGS remains open. Runtime owns the channel that supplies a selector to
the component and returns its result. The intended selector is one of
`read:<path>`, `net:<resource>`, `model:<resource>` or `address:<instance>`.

The existing `elastos/wit/elastos-bus-v1.wit:87` exports `lifecycle.run()` with zero
arguments and `result<_, bus-error>`. Its imported interfaces expose runtime
information, identity, capability requests and provider invocation. They expose
neither launch arguments nor an output stream. `ComponentProvider::start` in
`elastos/crates/elastos-compute/src/providers/component.rs:133` calls this entry
without forwarding `CapsuleHandle.args`. Thus a selector on `elastos run` cannot
reach this component. The probe returns the explicit unavailable reason until
Runtime supplies the channel. Effect dispatch and parseable successful output
remain blocked on its owning Runtime task.

The current import fixture in `component.rs` includes `types`, `runtime`,
`identity`, `capabilities` and `providers`; the task's three-interface description
is older than that fixture. The artifact check retains the task's narrower
three-interface set (`types`, `runtime`, `identity`). This component needs only
Bus types for its refusal. Enabling an effect will also need agreement on the
requested import scope.

The tests prove valid component bytes, manifest/WIT agreement, imports and two
independent builds on this machine. The printed SHA-256 identifies the component
artifact. A signed complete bundle, its published CID, Runtime admission and
launch by that CID remain unverified. Task 001's isolated Runtime harness is
also absent. These artifact checks cannot close task 002's full acceptance.
