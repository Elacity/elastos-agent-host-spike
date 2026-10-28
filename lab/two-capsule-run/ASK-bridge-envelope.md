# Ask: one bridge-envelope entry on the stand-in

Route to cx-agent-conformance through Flint.

The Runtime hostcall is `Fn(&str, &str, Option<&str>) -> Result<String, String>`
(`elastos/crates/elastos-compute/src/providers/mod.rs:10-11`). `call_bridge`
passes one envelope line, the capsule id and the optional principal
(`component.rs:315-325`). The hostcall forwards bytes only and decides nothing.

Add one public, synchronous `StandIn` method with these parameters after the
receiver: `line: &str`, `capsule_id: &str`, `principal: Option<&str>`, and the
return type `Result<String, String>`. It records the request under the capsule
id it is given and returns the response line.

Grant refusal stays inside the stand-in. Use the reason it already returns for
a mismatched caller; do not add a second refusal path.

Also bind an instance to its component hash before anyone claims A3 credit.
This record claims none. This lane's later hostcall will pass the three
arguments through and return the string.
