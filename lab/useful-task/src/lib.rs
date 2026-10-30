//! Judge one recorded agent answer against its task acceptance spec.
//!
//! The answer is an untrusted proposal. The checker judges that proposal and
//! grants nothing. It reads no file and opens no socket; the caller supplies
//! the spec, input and recorded value.

use std::cell::Cell;
use std::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The canonical refusal checks, in the order every spec must name them.
const CHECK_ORDER: [Reason; 9] = [
    Reason::Task,
    Reason::Input,
    Reason::Recorded,
    Reason::Empty,
    Reason::Echo,
    Reason::FixedString,
    Reason::Shape,
    Reason::Duplicate,
    Reason::Mismatch,
];

/// One task acceptance spec, validated by [`load_spec`].
///
/// Callers can inspect the spec through shared references. Only the loader can
/// construct it, so every call to [`judge`] uses the validated check sequence.
///
/// Clearing the checks is a compile-time error:
/// ```compile_fail,E0616
/// fn bypass(mut spec: useful_task::Spec) {
///     spec.reasons.clear();
/// }
/// ```
/// Removing only the comparison check is also a compile-time error:
/// ```compile_fail,E0616
/// fn bypass(mut spec: useful_task::Spec) {
///     spec.reasons.retain(|reason| *reason != useful_task::Reason::Mismatch);
/// }
/// ```
/// The accessor keeps the checks read-only:
/// ```compile_fail,E0599
/// fn bypass(mut spec: useful_task::Spec) {
///     spec.reasons().clear();
/// }
/// ```
/// The fixed strings are also read-only:
/// ```compile_fail,E0599
/// fn bypass(mut spec: useful_task::Spec) {
///     spec.fixed_strings().clear();
/// }
/// ```
/// Schema fields also stay behind a shared reference:
/// ```compile_fail,E0596
/// fn bypass(mut spec: useful_task::Spec) {
///     match spec.schema() {
///         useful_task::Schema::Fields(fields) | useful_task::Schema::Items(fields) => {
///             fields.clear();
///         }
///     }
/// }
/// ```
/// Direct construction requires the loader's validation:
/// ```compile_fail,E0451
/// let spec = useful_task::Spec {
///     task_id: String::new(),
///     m1: String::new(),
///     input_sha256: String::new(),
///     recorded_sha256: String::new(),
///     fixed_strings: Vec::new(),
///     reasons: Vec::new(),
///     schema: useful_task::Schema::Fields(Vec::new()),
/// };
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spec {
    task_id: String,
    m1: String,
    input_sha256: String,
    recorded_sha256: String,
    fixed_strings: Vec<String>,
    reasons: Vec<Reason>,
    schema: Schema,
}

impl Spec {
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn m1(&self) -> &str {
        &self.m1
    }

    pub fn input_sha256(&self) -> &str {
        &self.input_sha256
    }

    pub fn recorded_sha256(&self) -> &str {
        &self.recorded_sha256
    }

    pub fn fixed_strings(&self) -> &[String] {
        &self.fixed_strings
    }

    pub fn reasons(&self) -> &[Reason] {
        &self.reasons
    }

    pub fn schema(&self) -> &Schema {
        &self.schema
    }
}

/// One reason an answer is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The spec is not one of the two named task specs.
    Task,
    Input,
    Recorded,
    Empty,
    Echo,
    FixedString,
    Shape,
    /// The answer repeats an object key, so no one value is its proposal.
    Duplicate,
    Mismatch,
}

impl Reason {
    /// The spec label and the verdict reason for this check.
    pub fn label(self) -> &'static str {
        match self {
            Reason::Task => "task",
            Reason::Input => "input",
            Reason::Recorded => "recorded",
            Reason::Empty => "empty",
            Reason::Echo => "echo",
            Reason::FixedString => "fixed-string",
            Reason::Shape => "shape",
            Reason::Duplicate => "duplicate",
            Reason::Mismatch => "mismatch",
        }
    }

    fn from_label(label: &str) -> Option<Self> {
        CHECK_ORDER
            .iter()
            .copied()
            .find(|reason| reason.label() == label)
    }
}

/// The answer shape named by one spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Schema {
    /// One object whose keys are exactly these fields, each a string.
    Fields(Vec<String>),
    /// One object whose only key is `items`, an array of objects whose keys
    /// are exactly these fields, each a string.
    Items(Vec<String>),
}

impl Schema {
    fn matches(&self, value: &Value) -> bool {
        match self {
            Schema::Fields(fields) => object_matches(value, fields),
            Schema::Items(fields) => {
                let Some(object) = value.as_object() else {
                    return false;
                };
                if object.len() != 1 {
                    return false;
                }
                let Some(items) = object.get("items").and_then(Value::as_array) else {
                    return false;
                };
                items.iter().all(|item| object_matches(item, fields))
            }
        }
    }
}

fn object_matches(value: &Value, fields: &[String]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.len() == fields.len()
        && fields
            .iter()
            .all(|field| object.get(field).is_some_and(Value::is_string))
}

/// Outcome of judging one answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept { answer_sha256: String },
    Refuse { reason: &'static str },
}

/// Parse one acceptance spec from its bytes.
///
/// The spec text uses the same unique-key parser as the answer, so a spec that
/// repeats an object key is refused instead of collapsing to its last value.
pub fn load_spec(bytes: &str) -> Result<Spec, String> {
    let value = match parse_answer(bytes) {
        AnswerParse::Value(value) => value,
        AnswerParse::Duplicate => return Err("spec repeats a key".to_owned()),
        AnswerParse::Invalid => {
            return match serde_json::from_str::<Value>(bytes) {
                Ok(_) => Err("spec is not JSON".to_owned()),
                Err(error) => Err(format!("spec is not JSON: {error}")),
            }
        }
    };
    let object = value
        .as_object()
        .ok_or_else(|| "spec is not an object".to_owned())?;

    let kind = string_field(object, "kind")?;
    let (schema, kind_key) = match kind.as_str() {
        "fields" => {
            let fields = unique_strings(object, "fields")?;
            (Schema::Fields(fields), "fields")
        }
        "items" => {
            let fields = unique_strings(object, "item_fields")?;
            (Schema::Items(fields), "item_fields")
        }
        _ => return Err(format!("spec kind {kind} is unknown")),
    };

    for key in object.keys() {
        let known = matches!(
            key.as_str(),
            "task_id"
                | "m1"
                | "reasons"
                | "fixed_strings"
                | "input_sha256"
                | "recorded_sha256"
                | "kind"
        ) || key == kind_key;
        if !known {
            return Err(format!("spec has unexpected key {key}"));
        }
    }

    let labels = strings(object, "reasons")?;
    let mut reasons = Vec::with_capacity(labels.len());
    for label in &labels {
        let reason =
            Reason::from_label(label).ok_or_else(|| format!("spec reason {label} is unknown"))?;
        reasons.push(reason);
    }
    if reasons.as_slice() != CHECK_ORDER.as_slice() {
        return Err("spec reasons are not the canonical checks".to_owned());
    }

    Ok(Spec {
        task_id: string_field(object, "task_id")?,
        m1: string_field(object, "m1")?,
        input_sha256: sha256_field(object, "input_sha256")?,
        recorded_sha256: sha256_field(object, "recorded_sha256")?,
        fixed_strings: strings(object, "fixed_strings")?,
        reasons,
        schema,
    })
}

/// Judge `answer` against `spec`, the input bytes and the expected bytes.
pub fn judge(spec: &Spec, input: &str, expected: &str, answer: &str) -> Verdict {
    let trimmed = trim_json_whitespace(answer);
    let parsed = parse_answer(trimmed);
    let expected_value = serde_json::from_str::<Value>(expected).ok();

    for reason in &spec.reasons {
        let refused = match reason {
            Reason::Task => !is_named_task(spec),
            Reason::Input => sha256_hex(input) != spec.input_sha256(),
            Reason::Recorded => sha256_hex(expected) != spec.recorded_sha256(),
            Reason::Empty => trimmed.is_empty(),
            Reason::Echo => trimmed == trim_json_whitespace(input),
            Reason::FixedString => spec.fixed_strings.iter().any(|fixed| fixed == trimmed),
            Reason::Shape => match &parsed {
                AnswerParse::Value(value) => !spec.schema.matches(value),
                AnswerParse::Invalid => true,
                AnswerParse::Duplicate => false,
            },
            Reason::Duplicate => matches!(parsed, AnswerParse::Duplicate),
            Reason::Mismatch => matches!(
                &parsed,
                AnswerParse::Value(value)
                    if spec.schema.matches(value) && Some(value) != expected_value.as_ref()
            ),
        };
        if refused {
            return Verdict::Refuse {
                reason: reason.label(),
            };
        }
    }

    Verdict::Accept {
        answer_sha256: sha256_hex(trimmed),
    }
}

/// Remove only the four JSON whitespace characters from both ends of `text`.
///
/// JSON whitespace is space, tab, line feed and carriage return. `str::trim`
/// also removes other characters such as U+00A0, so an answer wrapped in one
/// of those would parse as the recorded value and be accepted.
fn trim_json_whitespace(text: &str) -> &str {
    text.trim_matches(&[' ', '\t', '\n', '\r'][..])
}

/// What one parse of the answer text found.
enum AnswerParse {
    /// One JSON value whose object keys are all unique.
    Value(Value),
    /// JSON that repeats an object key, so no single value is kept.
    Duplicate,
    /// Text that is not one JSON value, or has trailing non-whitespace.
    Invalid,
}

/// Deserialize one JSON value and report a repeated object key.
///
/// `serde_json::Value::deserialize` keeps the last value of a repeated key, so
/// the earlier value disappears. This visitor records that second occurrence
/// instead and keeps the first, which stops one answer from carrying two
/// different proposals for the same field.
struct UniqueValue<'a> {
    repeated: &'a Cell<bool>,
}

impl<'de, 'a> Visitor<'de> for UniqueValue<'a> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one JSON value with unique object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut access: A) -> Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut items = Vec::new();
        while let Some(item) = access.next_element_seed(UniqueValue {
            repeated: self.repeated,
        })? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A>(self, mut access: A) -> Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            let value = access.next_value_seed(UniqueValue {
                repeated: self.repeated,
            })?;
            if object.insert(key, value).is_some() {
                self.repeated.set(true);
                return Err(de::Error::custom("duplicate key"));
            }
        }
        Ok(Value::Object(object))
    }
}

impl<'de, 'a> DeserializeSeed<'de> for UniqueValue<'a> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

/// Parse the answer text once, refusing a repeated object key anywhere.
///
/// The one deserializer reads one value, then `end` requires only trailing
/// whitespace. A unique-key value is [`AnswerParse::Value`]; a repeated key is
/// [`AnswerParse::Duplicate`]; any other parse error is [`AnswerParse::Invalid`].
fn parse_answer(text: &str) -> AnswerParse {
    let repeated = Cell::new(false);
    let visitor = UniqueValue {
        repeated: &repeated,
    };
    let mut deserializer = serde_json::Deserializer::from_str(text);
    match visitor.deserialize(&mut deserializer) {
        Ok(value) => match deserializer.end() {
            Ok(()) => AnswerParse::Value(value),
            Err(_) => AnswerParse::Invalid,
        },
        Err(_) if repeated.get() => AnswerParse::Duplicate,
        Err(_) => AnswerParse::Invalid,
    }
}

/// True only when `spec` is the `Spec` loaded from one of the two named tasks.
fn is_named_task(spec: &Spec) -> bool {
    let mut named = false;
    for bytes in [
        include_str!("../tasks/agent-a/accept.json"),
        include_str!("../tasks/agent-b/accept.json"),
    ] {
        match load_spec(bytes) {
            Ok(task) if &task == spec => named = true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    named
}

/// Lower-case SHA-256 hex of exactly these bytes.
pub fn sha256_hex(bytes: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }
    hex
}

fn required<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Value, String> {
    object
        .get(key)
        .ok_or_else(|| format!("spec is missing {key}"))
}

fn string_field(object: &Map<String, Value>, key: &str) -> Result<String, String> {
    required(object, key)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("spec {key} is not a string"))
}

fn sha256_field(object: &Map<String, Value>, key: &str) -> Result<String, String> {
    let value = string_field(object, key)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!("spec {key} is not a sha256 hex"));
    }
    Ok(value)
}

fn strings(object: &Map<String, Value>, key: &str) -> Result<Vec<String>, String> {
    let values = required(object, key)?
        .as_array()
        .ok_or_else(|| format!("spec {key} is not an array"))?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("spec {key} holds a non-string"))
        })
        .collect()
}

fn unique_strings(object: &Map<String, Value>, key: &str) -> Result<Vec<String>, String> {
    let values = strings(object, key)?;
    if values.is_empty() {
        return Err(format!("spec {key} is empty"));
    }
    for (index, value) in values.iter().enumerate() {
        if values[..index].contains(value) {
            return Err(format!("spec {key} repeats {value}"));
        }
    }
    Ok(values)
}
