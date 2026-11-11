//! A manifest read together with the CIDs it pins.
//!
//! A capsule may pin a capsule it requires: `requires[i].cid`. The ordinary
//! manifest type has no such key and refuses it, so no start path can read a
//! pin and ignore it. This second type is the only reader of pins. It checks
//! each pin, then reads everything else as an ordinary manifest, so every
//! rule of the ordinary type holds here too. It starts nothing, and it gives
//! no way to take the ordinary manifest out.

use crate::cid_form::cid_form;
use crate::manifest::{CapsuleManifest, CapsuleRole, CapsuleType};
use serde::de::{Deserialize, Deserializer, Error, MapAccess, SeqAccess, Visitor};
use std::collections::BTreeSet;
use std::fmt;

/// A pin is not a package root in its one spelling, is not a JSON string, or
/// sits on a requirement whose kind is not `capsule`.
pub const PIN_FORM_INVALID: &str = "pin_form_invalid";
/// In a manifest with a pin: two requirements share a name, or two pin one CID.
pub const REQUIREMENT_DUPLICATE: &str = "requirement_duplicate";

/// Why [`PinnedManifest::parse`] refused. The three cases stay apart because
/// a caller answers them differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinnedManifestError {
    /// Not JSON, or the ordinary manifest type refuses it. Serde's text.
    Unparsed(String),
    /// The ordinary manifest's `validate()` refuses it. Its text.
    Invalid(String),
    /// A pin is refused: [`PIN_FORM_INVALID`] or [`REQUIREMENT_DUPLICATE`],
    /// with the requirement's name (empty when it has none; for a CID pinned
    /// twice, the second requirement that pins it).
    Pin {
        code: &'static str,
        requirement: String,
    },
}

/// A manifest and the CIDs it pins. See the module text.
pub struct PinnedManifest {
    manifest: CapsuleManifest,
    pins: Vec<(String, String)>,
}

impl PinnedManifest {
    /// Reads `capsule.json` bytes. A manifest without a pin is read by the
    /// ordinary parse from the same bytes, so its answer, error text
    /// included, is the ordinary one.
    pub fn parse(bytes: &[u8]) -> Result<Self, PinnedManifestError> {
        let unparsed = |error: serde_json::Error| PinnedManifestError::Unparsed(error.to_string());
        let mut pins = Vec::new();
        let mut without_pins = None;
        if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(bytes) {
            pins = take_pins(&mut value)?;
            if !pins.is_empty() {
                // The value has already merged a key written twice; the
                // ordinary parse refuses one, so refuse it from the bytes.
                serde_json::from_slice::<NoRepeatedKey>(bytes).map_err(unparsed)?;
                without_pins = Some(value);
            }
        }
        let manifest: CapsuleManifest = match without_pins {
            Some(value) => serde_json::from_value(value).map_err(unparsed)?,
            None => serde_json::from_slice(bytes).map_err(unparsed)?,
        };
        manifest.validate().map_err(PinnedManifestError::Invalid)?;
        Ok(Self { manifest, pins })
    }

    pub fn name(&self) -> &str {
        &self.manifest.name
    }

    pub fn role(&self) -> &CapsuleRole {
        &self.manifest.role
    }

    pub fn capsule_type(&self) -> &CapsuleType {
        &self.manifest.capsule_type
    }

    /// Requirement name and CID text of each pin, in the manifest's order.
    pub fn pins(&self) -> &[(String, String)] {
        &self.pins
    }
}

/// The name and the pins only: the manifest inside is not printed.
impl fmt::Debug for PinnedManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedManifest")
            .field("name", &self.manifest.name)
            .field("pins", &self.pins)
            .finish_non_exhaustive()
    }
}

/// Takes each `requires[i].cid` out of `value` and checks it. Anything that
/// is not the expected shape is left as it is, for the strict parse to refuse
/// in its own words. Every pin's form is checked first, in the manifest's
/// order; the duplicate checks (names, then CIDs) run only after that, and
/// only when there is a pin.
fn take_pins(value: &mut serde_json::Value) -> Result<Vec<(String, String)>, PinnedManifestError> {
    let refused = |code, requirement: &str| PinnedManifestError::Pin {
        code,
        requirement: requirement.to_string(),
    };
    let mut pins = Vec::new();
    let mut names = Vec::new();
    let requires = value
        .get_mut("requires")
        .and_then(|list| list.as_array_mut());
    for requirement in requires.into_iter().flatten() {
        let Some(object) = requirement.as_object_mut() else {
            continue;
        };
        let name = object.get("name").and_then(|name| name.as_str());
        let name = name.unwrap_or_default().to_string();
        names.push(name.clone());
        let Some(cid) = object.remove("cid") else {
            continue;
        };
        let on_a_capsule = object.get("kind").and_then(|kind| kind.as_str()) == Some("capsule");
        match cid.as_str().filter(|text| cid_form(text).is_some()) {
            Some(text) if on_a_capsule => pins.push((name, text.to_string())),
            _ => return Err(refused(PIN_FORM_INVALID, &name)),
        }
    }
    if pins.is_empty() {
        return Ok(pins);
    }
    let mut seen = BTreeSet::new();
    if let Some(repeated) = names.iter().find(|name| !seen.insert(name.as_str())) {
        return Err(refused(REQUIREMENT_DUPLICATE, repeated));
    }
    let mut seen = BTreeSet::new();
    if let Some((name, _)) = pins.iter().find(|(_, cid)| !seen.insert(cid.as_str())) {
        return Err(refused(REQUIREMENT_DUPLICATE, name));
    }
    Ok(pins)
}

/// Reads any JSON and refuses an object that has one key twice, at any
/// depth. A manifest with a pin is read from a JSON value, where the later of
/// two equal keys has silently replaced the earlier; the ordinary parse reads
/// the bytes and refuses a repeated field. This keeps that refusal.
struct NoRepeatedKey;

impl<'de> Deserialize<'de> for NoRepeatedKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Walk;
        impl<'de> Visitor<'de> for Walk {
            type Value = NoRepeatedKey;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON with no key written twice in one object")
            }

            // A scalar has no keys.
            fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
                Ok(NoRepeatedKey)
            }
            fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
                Ok(NoRepeatedKey)
            }
            fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
                Ok(NoRepeatedKey)
            }
            fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
                Ok(NoRepeatedKey)
            }
            fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
                Ok(NoRepeatedKey)
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(NoRepeatedKey)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut list: A) -> Result<Self::Value, A::Error> {
                while list.next_element::<NoRepeatedKey>()?.is_some() {}
                Ok(NoRepeatedKey)
            }

            fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Self::Value, A::Error> {
                let mut seen = BTreeSet::new();
                while let Some(key) = object.next_key::<String>()? {
                    if seen.contains(&key) {
                        return Err(A::Error::custom(format!("duplicate key `{key}`")));
                    }
                    seen.insert(key);
                    object.next_value::<NoRepeatedKey>()?;
                }
                Ok(NoRepeatedKey)
            }
        }
        deserializer.deserialize_any(Walk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Three package roots that Kubo 0.42.0 printed (`ipfs add --only-hash`):
    // constants this code did not produce.
    const ROOT_A: &str = "bafybeicesjf2ejdmnav65ijpbr3qq2blx4ldp6c5tdtczmv5bwim3ndbsy";
    const ROOT_B: &str = "bafybeialfcatqw2f3lxgz7epy2jarcfbv6sdz3kwmiurhjm3khj4lvtwdm";
    const ROOT_C: &str = "bafybeibjgbkgok3255r5jguuyziq6an6z7rpng36r4vzkutlipc2zgltwu";

    fn manifest(extra: serde_json::Value) -> Vec<u8> {
        let mut value = json!({
            "schema": "elastos.capsule/v1", "name": "pin-fixture", "version": "0.1.0",
            "role": "app", "type": "data", "entrypoint": "index.html"
        });
        let extra = extra.as_object().unwrap().clone();
        value.as_object_mut().unwrap().extend(extra);
        serde_json::to_vec_pretty(&value).unwrap()
    }

    fn requires(list: serde_json::Value) -> Vec<u8> {
        manifest(json!({ "requires": list }))
    }

    fn pinned(name: &str, cid: &str) -> serde_json::Value {
        json!({"name": name, "kind": "capsule", "cid": cid})
    }

    fn refusal(bytes: &[u8]) -> PinnedManifestError {
        PinnedManifest::parse(bytes).expect_err("a refusal")
    }

    fn pin_refusal(bytes: &[u8]) -> (&'static str, String) {
        match refusal(bytes) {
            PinnedManifestError::Pin { code, requirement } => (code, requirement),
            other => panic!("expected a refused pin, got {other:?}"),
        }
    }

    fn ordinary_error(bytes: &[u8]) -> String {
        serde_json::from_slice::<CapsuleManifest>(bytes)
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn one_valid_pin_is_read_and_the_ordinary_type_refuses_the_same_bytes() {
        let bytes = requires(json!([pinned("viewer", ROOT_A)]));
        let parsed = PinnedManifest::parse(&bytes).unwrap();
        assert_eq!(parsed.name(), "pin-fixture");
        assert_eq!(parsed.pins(), [("viewer".to_string(), ROOT_A.to_string())]);
        assert!(ordinary_error(&bytes).contains("unknown field `cid`"));
    }

    #[test]
    fn every_rule_of_the_ordinary_type_holds_for_a_pinned_manifest() {
        for (extra, expected) in [
            (
                json!({"schema": "elastos.capsule/v0"}),
                "unsupported schema",
            ),
            (json!({"entrypoint": "../index.html"}), "path traversal"),
            (
                json!({"capabilities": ["elastos://net/*"]}),
                "system-only backend",
            ),
        ] {
            let mut value = json!({"requires": [pinned("viewer", ROOT_A)]});
            let extra = extra.as_object().unwrap().clone();
            value.as_object_mut().unwrap().extend(extra);
            match refusal(&manifest(value)) {
                PinnedManifestError::Invalid(text) => assert!(text.contains(expected), "{text}"),
                other => panic!("{expected}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_pin_that_is_not_a_root_on_a_capsule_requirement_is_pin_form_invalid() {
        for (what, requirement) in [
            (
                "on kind external",
                json!({"name": "kubo", "kind": "external", "cid": ROOT_A}),
            ),
            (
                "null",
                json!({"name": "kubo", "kind": "capsule", "cid": null}),
            ),
            (
                "a number",
                json!({"name": "kubo", "kind": "capsule", "cid": 7}),
            ),
            (
                "an object",
                json!({"name": "kubo", "kind": "capsule", "cid": {"/": ROOT_A}}),
            ),
            (
                "true",
                json!({"name": "kubo", "kind": "capsule", "cid": true}),
            ),
            (
                "a list",
                json!({"name": "kubo", "kind": "capsule", "cid": [ROOT_A]}),
            ),
            (
                "a raw leaf",
                pinned(
                    "kubo",
                    "bafkreiexeojjebb246sivqmgnpofipuzhepe3t5c656s34piqcdkr5doxa",
                ),
            ),
        ] {
            let refusal = pin_refusal(&requires(json!([requirement])));
            assert_eq!(refusal, (PIN_FORM_INVALID, "kubo".to_string()), "{what}");
        }
    }

    #[test]
    fn a_repeated_name_or_a_cid_pinned_twice_is_requirement_duplicate() {
        let unpinned = json!({"name": "viewer", "kind": "capsule"});
        let same_name = requires(json!([pinned("viewer", ROOT_A), unpinned]));
        assert_eq!(
            pin_refusal(&same_name),
            (REQUIREMENT_DUPLICATE, "viewer".to_string())
        );
        let same_cid = requires(json!([pinned("first", ROOT_A), pinned("second", ROOT_A)]));
        assert_eq!(
            pin_refusal(&same_cid),
            (REQUIREMENT_DUPLICATE, "second".to_string())
        );
    }

    /// Every pin's form is checked before any duplicate: the malformed pin
    /// is the last requirement, after two that share a name.
    #[test]
    fn a_malformed_pin_is_reported_before_a_duplicate() {
        let bytes = requires(json!([
            pinned("viewer", ROOT_A),
            {"name": "viewer", "kind": "capsule"},
            pinned("last", "bafy")
        ]));
        assert_eq!(pin_refusal(&bytes), (PIN_FORM_INVALID, "last".to_string()));
    }

    #[test]
    fn pins_keep_the_order_of_the_manifest() {
        let bytes = requires(json!([
            pinned("m", ROOT_C),
            pinned("z", ROOT_A),
            pinned("a", ROOT_B)
        ]));
        let parsed = PinnedManifest::parse(&bytes).unwrap();
        let order: Vec<(&str, &str)> = parsed
            .pins()
            .iter()
            .map(|(name, cid)| (name.as_str(), cid.as_str()))
            .collect();
        assert_eq!(order, [("m", ROOT_C), ("z", ROOT_A), ("a", ROOT_B)]);
    }

    #[test]
    fn a_manifest_without_a_pin_gets_the_ordinary_answer_to_the_letter() {
        let fine = requires(json!([{"name": "viewer", "kind": "capsule"}]));
        assert!(PinnedManifest::parse(&fine).unwrap().pins().is_empty());
        for bytes in [
            b"{\n  \"schema\": \"elastos.capsule/v1\",\n".to_vec(),
            manifest(json!({"cid": ROOT_A})),
            manifest(json!({"name": 7})),
            requires(json!("viewer")),
            requires(json!([7])),
        ] {
            let expected = PinnedManifestError::Unparsed(ordinary_error(&bytes));
            assert_eq!(refusal(&bytes), expected);
            assert!(ordinary_error(&bytes).contains(" at line "));
        }
        let beside_a_pin = requires(json!([7, pinned("viewer", ROOT_A)]));
        assert!(matches!(
            refusal(&beside_a_pin),
            PinnedManifestError::Unparsed(_)
        ));
    }

    #[test]
    fn requirement_names_must_be_unique_only_when_there_is_a_pin() {
        let twice = json!({"name": "viewer", "kind": "capsule"});
        let without_a_pin = requires(json!([twice.clone(), twice.clone()]));
        let ordinary: CapsuleManifest = serde_json::from_slice(&without_a_pin).unwrap();
        ordinary.validate().unwrap();
        assert!(PinnedManifest::parse(&without_a_pin).is_ok());
        let with_a_pin = requires(json!([twice.clone(), twice, pinned("other", ROOT_A)]));
        assert_eq!(
            pin_refusal(&with_a_pin),
            (REQUIREMENT_DUPLICATE, "viewer".to_string())
        );
    }

    #[test]
    fn the_three_refusals_stay_apart() {
        let invalid = manifest(json!({"entrypoint": "/index.html"}));
        assert!(matches!(refusal(&invalid), PinnedManifestError::Invalid(_)));
        assert!(matches!(
            refusal(b"not json"),
            PinnedManifestError::Unparsed(_)
        ));
        let pin = requires(json!([pinned("viewer", "not-a-root")]));
        assert!(matches!(refusal(&pin), PinnedManifestError::Pin { .. }));
    }

    #[test]
    fn the_role_and_the_type_are_the_manifests() {
        let data = PinnedManifest::parse(&manifest(json!({}))).unwrap();
        assert_eq!(data.role(), &CapsuleRole::App);
        assert_eq!(data.capsule_type(), &CapsuleType::Data);
        let wasm = manifest(json!({"role": "viewer", "type": "wasm", "entrypoint": "app.wasm"}));
        let wasm = PinnedManifest::parse(&wasm).unwrap();
        assert_eq!(wasm.role(), &CapsuleRole::Viewer);
        assert_eq!(wasm.capsule_type(), &CapsuleType::Wasm);
    }

    #[test]
    fn debug_prints_the_name_and_the_pins_and_not_the_manifest_inside() {
        let bytes = manifest(json!({
            "description": "MARKER-IN-THE-DESCRIPTION",
            "requires": [pinned("viewer", ROOT_A)]
        }));
        let printed = format!("{:?}", PinnedManifest::parse(&bytes).unwrap());
        assert!(printed.contains("pin-fixture") && printed.contains(ROOT_A));
        assert!(!printed.contains("MARKER"), "{printed}");
    }

    /// A manifest with a pin is read from a JSON value, which keeps only the
    /// later of two equal keys. The ordinary parse refuses a field written
    /// twice, and so does this type: at the top level, inside a requirement
    /// (where a second `cid` would otherwise replace the first unseen), and
    /// in a nested object. The control is the same manifest with one key.
    #[test]
    fn a_key_written_twice_in_a_manifest_with_a_pin_is_refused() {
        let text = String::from_utf8(requires(json!([pinned("viewer", ROOT_A)]))).unwrap();
        assert!(PinnedManifest::parse(text.as_bytes()).is_ok());
        let entrypoint = "\"entrypoint\": \"index.html\"";
        let cid = format!("\"cid\": \"{ROOT_A}\"");
        let nested = "\"requires\": [";
        for (what, repeated, key) in [
            (
                "a top-level field",
                text.replace(
                    entrypoint,
                    &format!("\"entrypoint\": \"other.html\", {entrypoint}"),
                ),
                "entrypoint",
            ),
            (
                "a pin",
                text.replace(&cid, &format!("\"cid\": \"not-a-root\", {cid}")),
                "cid",
            ),
            (
                "a key of a nested object",
                text.replace(
                    nested,
                    &format!("\"resources\": {{\"x\": 1, \"x\": 2}}, {nested}"),
                ),
                "x",
            ),
        ] {
            assert_ne!(repeated, text, "{what}: the fixture was not changed");
            match refusal(repeated.as_bytes()) {
                PinnedManifestError::Unparsed(error) => {
                    assert!(
                        error.contains(&format!("duplicate key `{key}`")),
                        "{what}: {error}"
                    )
                }
                other => panic!("{what}: {other:?}"),
            }
        }
        // Without a pin the ordinary parse answers, in its own words.
        let pinless = requires(json!([{"name": "viewer", "kind": "capsule"}]));
        let pinless = String::from_utf8(pinless).unwrap();
        let pinless = pinless.replace(entrypoint, &format!("\"entrypoint\": \"a\", {entrypoint}"));
        assert_eq!(
            refusal(pinless.as_bytes()),
            PinnedManifestError::Unparsed(ordinary_error(pinless.as_bytes()))
        );
        assert!(ordinary_error(pinless.as_bytes()).contains("duplicate field `entrypoint`"));
    }

    /// The crate has no compile-fail harness, so this is a check of the
    /// source text: the manifest inside is a private field, the type derives
    /// nothing, and no public function or conversion hands the manifest out.
    #[test]
    fn nothing_hands_the_ordinary_manifest_out_of_a_pinned_one() {
        let source = include_str!("pinned_manifest.rs");
        let production = source.split("\n#[cfg(test)]\nmod tests {").next().unwrap();
        let declared = "/// A manifest and the CIDs it pins. See the module text.\n\
                        pub struct PinnedManifest {\n    manifest: CapsuleManifest,\n";
        assert_eq!(production.matches(declared).count(), 1);
        for line in production.lines().filter(|line| line.contains("pub fn")) {
            assert!(!line.contains("CapsuleManifest"), "{line}");
        }
        let impls: Vec<&str> = production
            .lines()
            .filter(|line| line.starts_with("impl"))
            .collect();
        assert_eq!(
            impls,
            [
                "impl PinnedManifest {",
                "impl fmt::Debug for PinnedManifest {",
                "impl<'de> Deserialize<'de> for NoRepeatedKey {"
            ]
        );
    }
}
