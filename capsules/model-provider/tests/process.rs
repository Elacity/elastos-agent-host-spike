#![cfg(unix)]

#[path = "../src/test_support.rs"]
mod test_support;

/// The shared live-grant stand-in (`lab/agent-conformance/standin-runtime/`),
/// read here rather than copied: one RA-1 path (P10). The agent-conformance
/// crate takes the same file in with its own `#[path]` line
/// (`lab/agent-conformance/src/lib.rs:9-10`). Its `#[cfg(test)] mod tests`
/// compiles into this binary too, so the shared stand-in's own tests run here.
#[allow(dead_code)]
#[path = "../../../lab/agent-conformance/standin-runtime/mod.rs"]
mod standin_runtime;

use standin_runtime::{Caller, Life, StandIn};
use test_support::FIXTURE_EVENT_TIMEOUT;

use elastos_model_contract::{
    model_input_hash, model_run_id, RuntimeAccessBinding, RuntimeCreateBinding,
    RUNTIME_ACCESS_BINDING_SCHEMA, RUNTIME_CREATE_BINDING_SCHEMA,
};
use serde_json::{json, Value};
use std::io::{BufRead as _, BufReader, Read, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const MAX_STDERR_BYTES: usize = 64 * 1024;

struct ProviderProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    responses: Receiver<Value>,
    stderr: Receiver<std::io::Result<(Vec<u8>, bool)>>,
}

impl ProviderProcess {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_model-provider"))
            .env(
                "ELASTOS_MODEL_PROVIDER_TEST_FREE_MEMORY",
                (8_u64 << 30).to_string(),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let (stderr_tx, stderr_rx) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let result = (|| -> std::io::Result<_> {
                let mut captured = Vec::new();
                let mut overflow = false;
                let mut buffer = [0u8; 4096];
                loop {
                    let count = stderr.read(&mut buffer)?;
                    if count == 0 {
                        return Ok((captured, overflow));
                    }
                    let retained = count.min(MAX_STDERR_BYTES - captured.len());
                    captured.extend_from_slice(&buffer[..retained]);
                    overflow |= retained < count;
                    // Drain after the cap too, so diagnostics cannot block the child.
                }
            })();
            let _ = stderr_tx.send(result);
        });
        let (response_tx, responses) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else {
                    break;
                };
                let Ok(value) = serde_json::from_str(&line) else {
                    break;
                };
                if response_tx.send(value).is_err() {
                    break;
                }
            }
        });
        Self {
            stdin: child.stdin.take(),
            child,
            responses,
            stderr: stderr_rx,
        }
    }

    fn request(&mut self, request: Value) -> Value {
        let stdin = self.stdin.as_mut().unwrap();
        serde_json::to_writer(&mut *stdin, &request).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
        self.responses.recv_timeout(FIXTURE_EVENT_TIMEOUT).unwrap()
    }

    fn hard_kill(&mut self) {
        let pid = self.child.id() as libc::pid_t;
        assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
        self.stdin.take();
        let status = wait_for_child_exit(&mut self.child)
            .unwrap_or_else(|| panic!("model provider {pid} remained alive"));
        assert!(!status.success());
        assert!(!process_exists(pid), "model provider {pid} remained alive");
    }

    fn shutdown(&mut self) {
        let response = self.request(json!({"op": "shutdown"}));
        assert_eq!(response["status"], "ok");
        self.stdin.take();
        let pid = self.child.id() as libc::pid_t;
        let status = wait_for_child_exit(&mut self.child)
            .unwrap_or_else(|| panic!("model provider {pid} remained alive"));
        assert!(status.success());
        assert!(!process_exists(pid), "model provider {pid} remained alive");
    }
}

impl Drop for ProviderProcess {
    fn drop(&mut self) {
        self.stdin.take();
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn start_local_llama_run(label: &str) -> (ProviderProcess, PathBuf) {
    let (provider, events, _, _) =
        start_local_llama_fixture(label, "healthy_with_subtree", "process-lifecycle");
    (provider, events)
}

fn start_local_llama_fixture(
    label: &str,
    mode: &str,
    prompt: &str,
) -> (ProviderProcess, PathBuf, Value, Value) {
    let root = test_support::temp_root_path("model-provider-process", label);
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (engine, model, events) = test_support::write_fake_llama_server(&root, mode);
    let offer = json!({
        "id": "local-text",
        "title": "Local Text",
        "operation": "text.generate",
        "input_modalities": ["text/plain"],
        "output_modalities": ["text/plain"],
        "policy": {
            "concurrency_limit": 1,
            "input_bytes_limit": 8192,
            "inline_output_bytes_limit": 8192,
            "event_bytes_limit": 8192,
            "runtime_ms_limit": 30000,
            "retention_secs": 60,
            "cancel_settlement_timeout_ms": 20
        },
        "adapter": {
            "kind": "local_llama_cpp_text",
            "engine": {
                "path": engine,
                "sha256": test_support::sha256_file(&engine)
            },
            "model": {
                "path": model,
                "sha256": test_support::sha256_file(&model)
            },
            "settings": {
                "context_size": 256,
                "parallel": 1,
                "threads": 1,
                "batch_threads": 1,
                "gpu_layers": 0,
                "health_timeout_ms": FIXTURE_EVENT_TIMEOUT.as_millis() as u64,
                "shutdown_timeout_ms": 250,
                "enable_thinking": false
            }
        },
        "enabled": true
    });
    let mut provider = ProviderProcess::start();
    let init_request = json!({
        "op": "init",
        "config": {
            "base_path": root,
            "allowed_paths": [],
            "read_only": false,
            "encryption_key": "",
            "extra": {
                "provider_id": "model-provider",
                "journal_dir": root.join("journal"),
                "offers": [offer]
            }
        }
    });
    let init = provider.request(init_request.clone());
    assert_eq!(init["status"], "ok", "unexpected init response: {init}");

    let input = json!({
        "schema": "elastos.model.input.text/v1",
        "prompt": prompt
    });
    let create_request = json!({
        "op": "runs_create",
        "offer_id": "local-text",
        "operation": "text.generate",
        "input": input,
        "runtime_binding": {
            "schema": RUNTIME_CREATE_BINDING_SCHEMA,
            "principal_id": "person:local:test",
            "session_id": "session:test",
            "capsule_id": "assistant",
            "grant_id": "grant:test",
            "request_id": test_support::fixture_model_request_id(&format!("request:{label}")),
            "offer_id": "local-text",
            "operation": "text.generate",
            "input_hash": model_input_hash(&input).unwrap()
        }
    });
    let create = provider.request(create_request.clone());
    assert_eq!(
        create["status"], "ok",
        "unexpected create response: {create}"
    );
    wait_for_event(&events, "start:");
    wait_for_event(&events, "parent:");
    if mode.ends_with("with_subtree") {
        wait_for_event(&events, "subtree:");
    }
    (provider, events, init_request, create_request)
}

fn access_binding(create: &Value) -> Value {
    let create: RuntimeCreateBinding =
        serde_json::from_value(create["runtime_binding"].clone()).unwrap();
    let binding = RuntimeAccessBinding {
        schema: RUNTIME_ACCESS_BINDING_SCHEMA.into(),
        run_id: model_run_id(&create),
        principal_id: create.principal_id,
        session_id: create.session_id,
        capsule_id: create.capsule_id,
        grant_id: create.grant_id,
        request_id: create.request_id,
    };
    binding.validate(&binding.run_id).unwrap();
    serde_json::to_value(binding).unwrap()
}

fn wait_for_run_terminal(provider: &mut ProviderProcess, run_id: &str, binding: &Value) -> Value {
    wait_for_run_terminal_within(provider, run_id, binding, FIXTURE_EVENT_TIMEOUT)
}

/// Waits for the run to settle within `deadline`. The fixture tests keep
/// `FIXTURE_EVENT_TIMEOUT`; the opt-in real turn passes its own longer budget,
/// because a real model turn is slower than the fixture backend.
fn wait_for_run_terminal_within(
    provider: &mut ProviderProcess,
    run_id: &str,
    binding: &Value,
    deadline: Duration,
) -> Value {
    let deadline = Instant::now() + deadline;
    loop {
        let run =
            provider.request(json!({"op":"runs_get", "run_id":run_id, "runtime_binding":binding}));
        assert_eq!(run["status"], "ok", "unexpected run response: {run}");
        if run["data"]["terminal"].is_object() {
            return run;
        }
        assert!(Instant::now() < deadline, "model run did not settle: {run}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_event(path: &Path, prefix: &str) {
    let deadline = Instant::now() + FIXTURE_EVENT_TIMEOUT;
    while !event_lines(path)
        .iter()
        .any(|line| line.starts_with(prefix))
    {
        assert!(Instant::now() < deadline, "missing process event {prefix}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn event_lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

fn engine_pid(path: &Path) -> libc::pid_t {
    recorded_pid(path, "start:")
}

fn guard_pid(path: &Path) -> libc::pid_t {
    recorded_pid(path, "parent:")
}

fn subtree_pid(path: &Path) -> libc::pid_t {
    recorded_pid(path, "subtree:")
}

fn recorded_pid(path: &Path, prefix: &str) -> libc::pid_t {
    event_lines(path)
        .into_iter()
        .find_map(|line| line.strip_prefix(prefix)?.parse().ok())
        .unwrap()
}

fn process_exists(pid: libc::pid_t) -> bool {
    (unsafe { libc::kill(pid, 0) }) == 0
}

fn wait_for_child_exit(child: &mut Child) -> Option<ExitStatus> {
    let deadline = Instant::now() + FIXTURE_EVENT_TIMEOUT;
    loop {
        match child.try_wait().unwrap() {
            Some(status) => return Some(status),
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            None => return None,
        }
    }
}

fn wait_for_process_exit(pid: libc::pid_t) -> bool {
    let deadline = Instant::now() + FIXTURE_EVENT_TIMEOUT;
    while process_exists(pid) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    !process_exists(pid)
}

fn assert_guard_and_engine_stopped(events: &Path) {
    let pids = [guard_pid(events), engine_pid(events), subtree_pid(events)];
    let stopped = pids.map(wait_for_process_exit);
    for (pid, stopped) in pids.into_iter().zip(stopped) {
        if !stopped {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        assert!(stopped, "model process {pid} remained alive");
    }
}

#[test]
fn hard_killed_provider_reaps_local_llama_engine() {
    let (mut provider, events) = start_local_llama_run("hard-kill");

    provider.hard_kill();

    assert_guard_and_engine_stopped(&events);
}

#[test]
fn normal_provider_shutdown_reaps_local_llama_engine() {
    let (mut provider, events) = start_local_llama_run("shutdown");

    provider.shutdown();

    assert_guard_and_engine_stopped(&events);
    assert_eq!(
        event_lines(&events)
            .iter()
            .filter(|line| line.as_str() == "term")
            .count(),
        1
    );
    let (stderr, overflow) = provider
        .stderr
        .recv_timeout(FIXTURE_EVENT_TIMEOUT)
        .unwrap()
        .unwrap();
    assert!(!overflow, "provider stderr exceeded fixture limit");
    let stderr = String::from_utf8_lossy(&stderr);
    assert!(
        !stderr.contains("local engine closure"),
        "normal shutdown did not confirm engine closure: {stderr}"
    );
}

#[test]
fn managed_streaming_stop_reaps_engine_and_activates_different_model_without_restart() {
    managed_streaming_stop_switch("streaming-stop-switch", "stream_then_stall_with_subtree");
}

#[test]
fn managed_streaming_stop_reaps_stubborn_engine_before_different_model_activation() {
    #[cfg(target_os = "linux")]
    {
        const CHILD_FIXTURE: &str = "ELASTOS_MODEL_PROVIDER_SUBREAPER_FIXTURE";
        if std::env::var_os(CHILD_FIXTURE).is_none() {
            // Give the orphan a deterministic owner that can keep its zombie
            // visible. This child runs only this test; other tests keep their
            // usual process ownership and reaping behavior.
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "managed_streaming_stop_reaps_stubborn_engine_before_different_model_activation", "--nocapture"])
                .env(CHILD_FIXTURE, "1")
                .status()
                .unwrap();
            assert!(
                status.success(),
                "stubborn engine owner-close fixture failed"
            );
            return;
        }
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
    }
    managed_streaming_stop_switch(
        "stubborn-streaming-stop-switch",
        "stream_then_stall_ignore_term",
    );
}

fn managed_streaming_stop_switch(label: &str, mode: &str) {
    let (mut provider, events, mut init, create) = start_local_llama_fixture(label, mode, "stall");
    wait_for_event(&events, "stream_delta");
    let run_id = provider.request(create.clone())["data"]["run_id"]
        .as_str()
        .unwrap()
        .to_string();
    let binding = access_binding(&create);
    assert_eq!(binding["run_id"], run_id);
    let deadline = Instant::now() + FIXTURE_EVENT_TIMEOUT;
    loop {
        let page = provider.request(json!({"op":"runs_events", "run_id":run_id, "runtime_binding":binding, "after_sequence":0}));
        assert_eq!(page["status"], "ok", "unexpected events response: {page}");
        if page["data"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["kind"] == "text_delta")
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "streaming reply did not reach the journal: {page}"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let stop =
        provider.request(json!({"op":"runs_cancel", "run_id":run_id, "runtime_binding":binding}));
    assert_eq!(stop["status"], "ok");
    let terminal = wait_for_run_terminal(&mut provider, &run_id, &binding);
    // This runs the shipped binary and its real process-group guard. Library
    // fixtures launch the engine directly and cannot prove this close path.
    if mode.ends_with("with_subtree") {
        assert_guard_and_engine_stopped(&events);
    } else {
        #[cfg(target_os = "linux")]
        {
            // Clean the exact adopted fixture child on the fail-before path.
            // The settled result above already records whether the provider
            // owner could reap it and establish whole-group absence itself.
            let _ =
                unsafe { libc::waitpid(engine_pid(&events), std::ptr::null_mut(), libc::WNOHANG) };
        }
        assert!(wait_for_process_exit(guard_pid(&events)));
        assert!(wait_for_process_exit(engine_pid(&events)));
    }
    assert_eq!(terminal["data"]["status"], "cancelled", "{terminal}");
    let before = event_lines(&events);
    assert_eq!(
        provider.request(create.clone())["data"]["terminal"],
        terminal["data"]["terminal"]
    );
    assert_eq!(event_lines(&events), before);

    let root = PathBuf::from(init["config"]["base_path"].as_str().unwrap());
    let (engine, model, later_events) =
        test_support::write_fake_llama_server(&root.join("different-model"), "healthy");
    let mut different = init["config"]["extra"]["offers"][0].clone();
    different["id"] = json!("different-model");
    different["adapter"]["engine"] =
        json!({"path":engine,"sha256":test_support::sha256_file(&engine)});
    different["adapter"]["model"] =
        json!({"path":model,"sha256":test_support::sha256_file(&model)});
    init["config"]["extra"]["offers"]
        .as_array_mut()
        .unwrap()
        .push(different);
    let deadline = Instant::now() + FIXTURE_EVENT_TIMEOUT;
    loop {
        let activated = provider.request(init.clone());
        if activated["status"] == "ok" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "different model activation refused: {activated}"
        );
        assert_eq!(activated["code"], "selection_unavailable");
        thread::sleep(Duration::from_millis(10));
    }
    let input = json!({"schema":"elastos.model.input.text/v1", "prompt":"after stop"});
    let mut other_create = create;
    other_create["offer_id"] = json!("different-model");
    other_create["input"] = input.clone();
    other_create["runtime_binding"]["offer_id"] = json!("different-model");
    other_create["runtime_binding"]["request_id"] = json!(test_support::fixture_model_request_id(
        "request:after-streaming-stop"
    ));
    other_create["runtime_binding"]["input_hash"] = json!(model_input_hash(&input).unwrap());
    let created = provider.request(other_create.clone());
    assert_eq!(created["status"], "ok", "{created}");
    let completed = wait_for_run_terminal(
        &mut provider,
        created["data"]["run_id"].as_str().unwrap(),
        &access_binding(&other_create),
    );
    assert_eq!(completed["data"]["status"], "completed");
    assert_eq!(
        completed["data"]["terminal"]["output"]["text"],
        "reply:after stop"
    );
    provider.shutdown();
    assert!(wait_for_process_exit(engine_pid(&later_events)));
}

#[test]
fn wedged_guard_forces_local_llama_group_cleanup() {
    let (mut provider, events) = start_local_llama_run("wedged-guard");
    let guard = guard_pid(&events);
    assert_eq!(unsafe { libc::kill(guard, libc::SIGSTOP) }, 0);

    provider.shutdown();

    assert_guard_and_engine_stopped(&events);
}

#[test]
fn unexpected_guard_exit_forces_local_llama_group_cleanup() {
    let (mut provider, events) = start_local_llama_run("guard-exit");
    let guard = guard_pid(&events);
    assert_eq!(unsafe { libc::kill(guard, libc::SIGKILL) }, 0);

    provider.shutdown();

    assert_guard_and_engine_stopped(&events);
}

#[test]
fn production_provider_refuses_every_external_adapter_before_socket_and_after_restart() {
    let sink = TcpListener::bind("127.0.0.1:0").unwrap();
    sink.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", sink.local_addr().unwrap());
    let root = test_support::temp_root_path("model-provider-process", "external-paused");
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let policy = json!({
        "concurrency_limit": 1, "input_bytes_limit": 8192,
        "inline_output_bytes_limit": 8192, "event_bytes_limit": 8192,
        "runtime_ms_limit": 30000, "retention_secs": 60,
        "cancel_settlement_timeout_ms": 20
    });
    let hosted = json!({
        "backend_provider_label": "Fixture Provider", "selection_mode": "pinned",
        "privacy_policy_ref": "fixture:privacy:v1", "terms_ref": "fixture:terms:v1",
        "upstream_routing_fallback_assertion": "operator_asserted_disabled",
        "model_privacy": ""
    });
    let adapters = [
        (
            "decisions",
            "decision.evaluate",
            json!({"kind":"open_router_decisions",
            "api_url":format!("{endpoint}/decisions"),"api_key":"fixture-key","model":"fixture/jev",
            "hosted":hosted}),
        ),
        (
            "chat",
            "text.generate",
            json!({"kind":"open_ai_compatible_text",
            "api_url":format!("{endpoint}/chat"),"api_key":"fixture-key","model":"fixture/text",
            "hosted":hosted}),
        ),
        (
            "responses",
            "text.generate",
            json!({"kind":"open_ai_responses_text",
            "api_url":format!("{endpoint}/responses"),"api_key":"fixture-key","model":"fixture/text",
            "hosted":hosted}),
        ),
        (
            "job",
            "image.generate",
            json!({"kind":"http_job_artifact",
            "create_url":format!("{endpoint}/create"),"status_url":format!("{endpoint}/status"),
            "cancel_url":format!("{endpoint}/cancel"),"bearer_token":"fixture-key",
            "poll_interval_ms":1000}),
        ),
    ];
    let offers = adapters.iter().map(|(id, operation, adapter)| json!({
        "id":id,"title":id,"operation":operation,
        "input_modalities":if *id=="chat" || *id=="responses" {json!(["text/plain"])} else {json!(["application/json"])},
        "output_modalities":if *id=="chat" || *id=="responses" {json!(["text/plain"])} else {json!(["application/json"])},
        "policy":policy,"adapter":adapter,"enabled":true
    })).collect::<Vec<_>>();
    let init = json!({"op":"init","config":{
        "base_path":root,"allowed_paths":[],"read_only":false,"encryption_key":"",
        "extra":{"provider_id":"model-provider","journal_dir":root.join("journal"),"offers":offers}
    }});
    for pass in 0..2 {
        let mut provider = ProviderProcess::start();
        let started = provider.request(init.clone());
        assert_eq!(
            started["status"], "ok",
            "existing offers must survive startup: {started}"
        );
        let listed = provider.request(json!({"op":"offers_list"}));
        for (id, expected) in [
            (
                "chat",
                json!([
                    elastos_model_contract::TEXT_INPUT_V1_SCHEMA,
                    elastos_model_contract::TEXT_INPUT_V2_SCHEMA
                ]),
            ),
            (
                "responses",
                json!([elastos_model_contract::TEXT_INPUT_V1_SCHEMA]),
            ),
        ] {
            let offer = listed["data"]["offers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|offer| offer["id"] == id)
                .unwrap();
            assert_eq!(offer["input_schemas"], expected);
        }
        // Trace the production offer reply through the canonical Assistant selector.
        // Load as a data module so this fixture also works on older Node runtimes.
        let ui = Command::new("node")
            .args(["--input-type=module", "-e", r#"
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const source = readFileSync('../assistant/browser/model-contract.js', 'utf8');
const contract = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const reply = JSON.parse(process.argv[1]);
const messages = [{role:'system',content:'Be concise.'},{role:'user',content:'first'},
  {role:'agent',content:'reply'},{role:'user',content:'last'}];
const rows = contract.textOfferRows(contract.eligibleTextOffers(reply));
for (const id of ['chat','responses']) {
  const row = rows.find(row => row.offerId === id);
  const body = contract.textRunCreateBody({offer:row,messages,requestId:'fixture'});
  assert.equal(body.input.schema, id === 'chat' ? contract.MODEL_TEXT_INPUT_V2_SCHEMA : contract.MODEL_TEXT_INPUT_SCHEMA);
  if (id === 'chat') assert.deepEqual(body.input.messages, messages.map(m=>({...m,role:m.role==='agent'?'assistant':m.role})));
  else assert.equal(body.input.prompt, contract.transcriptPrompt(messages));
}
"#])
            .arg(listed.to_string())
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("Node is required for the Assistant contract fixture");
        assert!(
            ui.status.success(),
            "Assistant offer negotiation: {}",
            String::from_utf8_lossy(&ui.stderr)
        );
        for (id, operation, _) in &adapters {
            let input = json!({});
            let request_id = test_support::fixture_model_request_id(&format!(
                "request:external-paused:{pass}:{id}"
            ));
            let create = json!({"op":"runs_create","offer_id":id,"operation":operation,
            "input":input,"runtime_binding":{
                "schema":RUNTIME_CREATE_BINDING_SCHEMA,"principal_id":"person:local:test",
                "session_id":"session:test","capsule_id":"assistant","grant_id":"grant:test",
                "request_id":request_id,"offer_id":id,"operation":operation,
                "input_hash":model_input_hash(&input).unwrap()
            }});
            let reply = provider.request(create.clone());
            assert!(
                reply
                    .to_string()
                    .contains("Hosted external HTTPS is paused."),
                "{id}: {reply}"
            );
            let retry = provider.request(create);
            assert!(
                retry
                    .to_string()
                    .contains("Hosted external HTTPS is paused."),
                "retry {id}: {retry}"
            );
        }
        provider.shutdown();
    }
    assert!(matches!(sink.accept(), Err(error) if error.kind()==std::io::ErrorKind::WouldBlock));
}

const HOSTED_EFFECT_OFFER: &str = "hosted-text";

/// The text output schema the provider's contract names
/// (`capsules/model-provider/src/contract.rs:22`). This test binary cannot see
/// the provider's private contract module.
const RUN_OUTPUT_TEXT_SCHEMA: &str = "elastos.model.output.text/v1";

/// The backend report schema the provider's contract names
/// (`capsules/model-provider/src/contract.rs:17`).
const BACKEND_REPORT_SCHEMA: &str = "elastos.model.backend-report/v1";

/// The header names the Runtime's hosted effect reader accepts, compared in
/// lower case. Any other name, a repeated name, and a `host` other than
/// `runtime.invalid` are refused
/// (`elastos/crates/elastos-server/src/api/model_provider_egress.rs:549-578`).
/// This test copies the list instead of depending on `elastos-server`, which is
/// a separate Cargo workspace.
const RUNTIME_HOSTED_HEADER_NAMES: [&str; 11] = [
    "host",
    "accept",
    "accept-encoding",
    "user-agent",
    "content-type",
    "content-length",
    "x-elastos-offer-id",
    "x-elastos-effect",
    "x-elastos-run-id",
    "x-elastos-request-id",
    "x-elastos-job-id",
];

/// The Runtime's answer when it refuses a hosted request before dispatch.
const RUNTIME_HOSTED_REFUSAL: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nX-Elastos-Hosted-Access: refused\r\n\
      Content-Length: 0\r\nConnection: close\r\n\r\n";

/// The shared stand-in's shell scope marker. The shared file names it once
/// (`LIVE_SCOPE`, `lab/agent-conformance/standin-runtime/mod.rs:16`), and its
/// shell route call takes it as the one scope argument
/// (`get_capability_list(Caller::Shell, Some(...))`, `:128-139`). This test
/// passes the same text to that one call; it keeps no entry fields and no
/// grant states of its own.
const SHELL_LIVE_GRANT_SCOPE: &str = "all_sessions_live";

/// The session id every fixture hosted run carries in its runtime binding.
/// It is the session of the one grant the test seeds.
const HOSTED_FIXTURE_SESSION_ID: &str = "session:test";

/// The two backend stream events the source test sends
/// (`capsules/model-provider/src/execution.rs:4514-4535`), and the marker end.
/// The usage event carries no `cost` field, so the run records `cost` as
/// unknown (`capsules/model-provider/src/adapters.rs:416-418`, `:437-443`).
const RUNTIME_HOSTED_STREAM_EVENTS: [&str; 2] = [
    r#"{"model":"resolved-model","choices":[{"delta":{"content":"ready"}}]}"#,
    r#"{"model":"resolved-model","choices":[],"usage":{"prompt_tokens":7,"completion_tokens":1,"total_tokens":8}}"#,
];

/// The Runtime's accepted head, copied from `write_response_head`
/// (`elastos/crates/elastos-server/src/api/model_provider_egress.rs:1662-1670`).
/// The Runtime forwards the backend's content type (`:1589-1599`), so this
/// head says `text/event-stream`. Only a refusal carries
/// `X-Elastos-Hosted-Access` (`:2453-2486`).
fn runtime_hosted_stream_head() -> Vec<u8> {
    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        .to_vec()
}

/// Adds one backend chunk as `{len:X}\r\n{bytes}\r\n`, the Runtime's copy at
/// `elastos/crates/elastos-server/src/api/model_provider_egress.rs:1644-1648`.
fn push_runtime_hosted_stream_frame(answer: &mut Vec<u8>, frame: &[u8]) {
    answer.extend_from_slice(format!("{:X}\r\n", frame.len()).as_bytes());
    answer.extend_from_slice(frame);
    answer.extend_from_slice(b"\r\n");
}

/// The three `data:` frames a whole backend stream carries: the two backend
/// events and the end marker. The Runtime's accepted answer writes each one as
/// an HTTP chunk, and the local relay backend writes them as one plain
/// `text/event-stream` body, so the frames have one copy (P10).
fn runtime_hosted_stream_frames() -> [String; 3] {
    [
        format!("data: {}\n\n", RUNTIME_HOSTED_STREAM_EVENTS[0]),
        format!("data: {}\n\n", RUNTIME_HOSTED_STREAM_EVENTS[1]),
        "data: [DONE]\n\n".to_string(),
    ]
}

/// The Runtime's answer when it accepts a hosted effect and copies the whole
/// backend stream: the head, each backend chunk, and the end `0\r\n\r\n`
/// (`elastos/crates/elastos-server/src/api/model_provider_egress.rs:1650`).
fn runtime_hosted_stream_answer() -> Vec<u8> {
    let mut answer = runtime_hosted_stream_head();
    for frame in runtime_hosted_stream_frames() {
        push_runtime_hosted_stream_frame(&mut answer, frame.as_bytes());
    }
    answer.extend_from_slice(b"0\r\n\r\n");
    answer
}

/// Fields a hosted stream may carry beside answer text. The caller must not
/// see them: `extract_stream_text_delta` reads `content` only.
const HOSTED_STREAM_PRIVATE_MARKERS: [&str; 5] = [
    "fixture-private-reasoning",
    "call-fixture",
    "runs_create",
    "grant:from-model",
    "tool_calls",
];

/// The Runtime's accepted answer for a stream that also carries private
/// reasoning and a proposed tool call. The bytes are the same head, chunk
/// framing and closing `0\r\n\r\n` as `runtime_hosted_stream_answer`. Frame
/// order: the `ready` content event, a delta with `content: null` and
/// `reasoning_content`, a `tool_calls` delta, a ` set` content delta, an
/// empty delta with `finish_reason: "stop"`, the usage event, then `[DONE]`.
fn runtime_hosted_tool_and_reasoning_frames() -> Vec<u8> {
    let reasoning = serde_json::to_string(&json!({
        "model": "resolved-model",
        "choices": [{
            "delta": {
                "content": null,
                "reasoning_content": "fixture-private-reasoning"
            }
        }]
    }))
    .expect("the reasoning frame is json");
    let tool_call = serde_json::to_string(&json!({
        "model": "resolved-model",
        "choices": [{
            "delta": {
                "tool_calls": [{
                    "id": "call-fixture",
                    "function": {
                        "name": "runs_create",
                        "arguments": "{\"grant_id\":\"grant:from-model\"}"
                    }
                }]
            }
        }]
    }))
    .expect("the tool-call frame is json");
    let continuation = serde_json::to_string(&json!({
        "model": "resolved-model",
        "choices": [{
            "delta": {"content": " set"}
        }]
    }))
    .expect("the continuation frame is json");
    let finish = serde_json::to_string(&json!({
        "model": "resolved-model",
        "choices": [{
            "delta": {},
            "finish_reason": "stop"
        }]
    }))
    .expect("the finish frame is json");
    let payloads = [
        RUNTIME_HOSTED_STREAM_EVENTS[0],
        reasoning.as_str(),
        tool_call.as_str(),
        continuation.as_str(),
        finish.as_str(),
        RUNTIME_HOSTED_STREAM_EVENTS[1],
        "[DONE]",
    ];
    let mut answer = runtime_hosted_stream_head();
    for payload in payloads {
        let frame = format!("data: {payload}\n\n");
        push_runtime_hosted_stream_frame(&mut answer, frame.as_bytes());
    }
    answer.extend_from_slice(b"0\r\n\r\n");
    answer
}

/// The Runtime's accepted answer for caller-supplied Chat Completions frames
/// followed by `[DONE]`. The bytes use the same head, `push_runtime_hosted_stream_frame`
/// and closing `0\r\n\r\n` as `runtime_hosted_stream_answer`.
fn runtime_hosted_chat_frames_answer(payloads: &[String]) -> Vec<u8> {
    let mut answer = runtime_hosted_stream_head();
    for payload in payloads {
        let frame = format!("data: {payload}\n\n");
        push_runtime_hosted_stream_frame(&mut answer, frame.as_bytes());
    }
    push_runtime_hosted_stream_frame(&mut answer, b"data: [DONE]\n\n");
    answer.extend_from_slice(b"0\r\n\r\n");
    answer
}

/// The Runtime's answer when it cuts a hosted stream: the head, then one chunk
/// that holds the first event, and the connection closes with no `0\r\n\r\n`
/// and no usage event. The Runtime returns an error after the head when the
/// grant ends or the body grows too large
/// (`elastos/crates/elastos-server/src/api/model_provider_egress.rs:1631`,
/// `:1638-1642`), and the closing chunk is only written at `:1650`, so a cut
/// stream never reaches it. Its caller shuts the socket down when `forward`
/// returns an error (`:531-532`), so the provider reads an incomplete chunked
/// body.
fn runtime_hosted_cut_answer() -> Vec<u8> {
    let mut answer = runtime_hosted_stream_head();
    push_runtime_hosted_stream_frame(
        &mut answer,
        format!("data: {}\n\n", RUNTIME_HOSTED_STREAM_EVENTS[0]).as_bytes(),
    );
    answer
}

/// What the stand-in answers: the Runtime's refusal, which is the default, its
/// accepted head followed by the whole backend stream, its accepted head
/// followed by a cut stream, a real backend answer relayed through that same
/// head and framing, or that relay only when the shared RA-1 grant store holds
/// a live grant for the effect's request id and session.
#[derive(Clone)]
enum HostedEffectAnswer {
    Refused,
    /// The Runtime's accepted stream. `None` is `runtime_hosted_stream_answer`.
    /// `Some` is the same response shape with the caller's frames.
    Streaming {
        frames: Option<Vec<u8>>,
    },
    Cut,
    /// Relays the recorded request body to this base URL and copies the backend
    /// answer back as the Runtime's hosted stream.
    Relay {
        backend_url: String,
    },
    /// Checks the shared stand-in's shell live-grant view for the effect's
    /// request id, then asks the shared stand-in's `authorise` whether that
    /// grant is for `served_session`, before it relays: no live entry, or a
    /// grant `authorise` refuses, answers with the Runtime's refusal
    /// (`RUNTIME_HOSTED_REFUSAL`) and reaches no backend.
    Granted {
        grants: Arc<Mutex<StandIn>>,
        /// The session this stand-in serves. The effect carries no session id
        /// (`src/adapters.rs:61-66`), so the stand-in applies the session of
        /// the hosted run it serves; this is the stand-in's rule, not a claim
        /// about how the Runtime finds an effect's session.
        served_session: String,
        backend_url: String,
    },
}

/// One request the stand-in read to its end: the request line and every header
/// line, with the name as sent.
struct RecordedRequest {
    request_line: String,
    headers: Vec<(String, String)>,
    /// Header lines with no colon, recorded rather than dropped. The Runtime's
    /// reader refuses such a line
    /// (`elastos/crates/elastos-server/src/api/model_provider_egress.rs:556`).
    colonless: Vec<String>,
    /// The request body, kept so a relaying answer forwards the provider's own
    /// bytes and the test can read them.
    body: Vec<u8>,
}

impl RecordedRequest {
    /// The recorded request head, the request line and all header lines.
    fn head(&self) -> String {
        let mut head = self.request_line.clone();
        for (name, value) in &self.headers {
            head.push_str("\r\n");
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
        }
        head
    }

    /// The value of the first header with this name, compared without case.
    fn value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(sent, _)| sent.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// The shared stand-in's shell live-grant view: `GET /api/capability/list`
/// with `?scope=all_sessions_live`
/// (`lab/agent-conformance/standin-runtime/README.md`). It is a method call,
/// not a socket route, because this test needs the live-grant record only.
fn shell_live_grant_view(grants: &Mutex<StandIn>) -> Value {
    grants
        .lock()
        .unwrap()
        .get_capability_list(Caller::Shell, Some(SHELL_LIVE_GRANT_SCOPE))
        .expect("the shared stand-in answers the shell live-grant view")
}

/// True when that view lists one entry whose `request_id` equals `request_id`.
/// The shared stand-in keeps only `Live` grants
/// (`lab/agent-conformance/standin-runtime/mod.rs:128-139`), so an exhausted,
/// revoked or expired grant never admits an effect.
fn shell_view_lists_live_grant(grants: &Mutex<StandIn>, request_id: &str) -> bool {
    shell_live_grant_view(grants)["capabilities"]
        .as_array()
        .expect("the shared stand-in shell view lists capabilities")
        .iter()
        .any(|entry| entry["request_id"] == request_id)
}

/// Stand-in for the Runtime-owned hosted effect socket that `init` names in
/// `runtime_hosted_socket`. It stays in this file because
/// `tests/confine/main.rs` is cc-model-confine's file in another test binary,
/// and `src/test_support.rs` is under `src/`, where a change needs a fresh
/// Sasha note. It counts each connection when `accept` returns it, reads that
/// connection's one request to its end, records the request, and answers as the
/// Runtime refuses before dispatch, or, when asked at `bind_streaming`, with
/// the Runtime's accepted head and the backend stream. `hold_answer` keeps that
/// answer back, so the run stays open for as long as the test needs it. A
/// stand-in bound with `bind_granting` answers only an effect whose request id
/// holds a live entry in the shared stand-in's shell view for the session that
/// stand-in serves, and records the named reason for every refusal in this
/// stand-in.
struct HostedEffectStandIn {
    path: PathBuf,
    listener: Arc<UnixListener>,
    connections: Arc<AtomicUsize>,
    requests: Receiver<RecordedRequest>,
    /// False while `hold_answer` holds each answer back.
    answer_released: Arc<(Mutex<bool>, Condvar)>,
    /// What the backend answered, when the answer relays.
    relay_outcome: Arc<Mutex<Option<RelayOutcome>>>,
    /// The shared stand-in's live-grant view when the answer checks grants
    /// before it relays, and `None` for the answer modes that do not.
    grants: Option<Arc<Mutex<StandIn>>>,
    /// The named reason this stand-in recorded for every effect it refused.
    refusals: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    accept_loop: Option<thread::JoinHandle<()>>,
}

impl HostedEffectStandIn {
    /// Binds the stand-in that answers as the Runtime refuses a hosted request
    /// before dispatch.
    fn bind(label: &str) -> Self {
        Self::bind_answering(label, HostedEffectAnswer::Refused, None)
    }

    /// Binds the stand-in that answers as the Runtime does when it accepts a
    /// hosted effect. The answer is `runtime_hosted_stream_answer`.
    fn bind_streaming(label: &str) -> Self {
        Self::bind_answering(label, HostedEffectAnswer::Streaming { frames: None }, None)
    }

    /// Binds the stand-in that answers with `frames`, the same accepted-stream
    /// path as `bind_streaming`. `bind_streaming` stays the default-frame caller.
    fn bind_streaming_frames(label: &str, frames: Vec<u8>) -> Self {
        Self::bind_answering(
            label,
            HostedEffectAnswer::Streaming {
                frames: Some(frames),
            },
            None,
        )
    }

    /// Binds the stand-in that answers as the Runtime does when it cuts a
    /// hosted stream after the head and one chunk.
    fn bind_cut(label: &str) -> Self {
        Self::bind_answering(label, HostedEffectAnswer::Cut, None)
    }

    /// Binds the stand-in that relays each hosted effect to the real backend at
    /// `backend_url` and answers in the Runtime's accepted stream shape.
    fn bind_relaying(label: &str, backend_url: &str) -> Self {
        Self::bind_answering(
            label,
            HostedEffectAnswer::Relay {
                backend_url: backend_url.to_string(),
            },
            None,
        )
    }

    /// Binds the stand-in that relays a hosted effect to the real backend at
    /// `backend_url` only when `grants` lists a live entry for the effect's
    /// request id that is for `served_session`, and answers with the Runtime's
    /// refusal otherwise. `served_session` is this stand-in's rule for the
    /// hosted run it serves, not a claim about how the Runtime finds an
    /// effect's session: the effect carries no session id
    /// (`src/adapters.rs:61-66`).
    fn bind_granting(
        label: &str,
        backend_url: &str,
        grants: Arc<Mutex<StandIn>>,
        served_session: &str,
    ) -> Self {
        Self::bind_answering(
            label,
            HostedEffectAnswer::Granted {
                grants: Arc::clone(&grants),
                served_session: served_session.to_string(),
                backend_url: backend_url.to_string(),
            },
            Some(grants),
        )
    }

    fn bind_answering(
        label: &str,
        answer: HostedEffectAnswer,
        grants: Option<Arc<Mutex<StandIn>>>,
    ) -> Self {
        // The provider refuses a socket path of 104 bytes or more
        // (`src/config.rs:163`), so bind under `/tmp` rather than under the
        // fixture's temporary root.
        let path =
            Path::new("/tmp").join(format!("mp-process-{label}-{}.sock", std::process::id()));
        // Only a killed run of this process id can have left this path.
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind the Runtime hosted effect stand-in");
        listener
            .set_nonblocking(true)
            .expect("a stoppable Runtime hosted effect stand-in");
        let listener = Arc::new(listener);
        let connections = Arc::new(AtomicUsize::new(0));
        let (request_tx, requests) = mpsc::channel();
        let answer_released = Arc::new((Mutex::new(true), Condvar::new()));
        let relay_outcome = Arc::new(Mutex::new(None));
        let refusals = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let accept_loop = {
            let listener = Arc::clone(&listener);
            let connections = Arc::clone(&connections);
            let answer_released = Arc::clone(&answer_released);
            let relay_outcome = Arc::clone(&relay_outcome);
            let refusals = Arc::clone(&refusals);
            let stopping = Arc::clone(&stop);
            thread::spawn(move || {
                while !stopping.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            connections.fetch_add(1, Ordering::Relaxed);
                            let request_tx = request_tx.clone();
                            let answer_released = Arc::clone(&answer_released);
                            let relay_outcome = Arc::clone(&relay_outcome);
                            let refusals = Arc::clone(&refusals);
                            let answer = answer.clone();
                            thread::spawn(move || {
                                serve_hosted_effect(
                                    stream,
                                    request_tx,
                                    answer_released,
                                    answer,
                                    relay_outcome,
                                    refusals,
                                )
                            });
                        }
                        Err(_) => thread::sleep(Duration::from_millis(5)),
                    }
                }
            })
        };
        Self {
            path,
            listener,
            connections,
            requests,
            answer_released,
            relay_outcome,
            grants,
            refusals,
            stop,
            accept_loop: Some(accept_loop),
        }
    }

    /// Holds each answer back until `release_answer`, so the hosted run stays
    /// open. Call it before the provider starts.
    fn hold_answer(&self) {
        let (released, _) = &*self.answer_released;
        *released.lock().unwrap() = false;
    }

    /// Lets every held answer go with the Runtime's refusal.
    fn release_answer(&self) {
        let (released, wake) = &*self.answer_released;
        *released.lock().unwrap() = true;
        wake.notify_all();
    }

    /// The connections the accept loop has returned so far.
    fn connection_count(&self) -> usize {
        self.connections.load(Ordering::Relaxed)
    }

    /// What the backend answered, when the answer relays. `None` before the
    /// backend answered, or when the answer does not relay.
    fn relay_outcome(&self) -> Option<RelayOutcome> {
        self.relay_outcome.lock().unwrap().clone()
    }

    /// The shared stand-in's shell live-grant view, read through the one
    /// `get_capability_list` call. It is a method, not a socket route: RA-1
    /// defines `GET /api/capability/list` for a shell session, and this test
    /// needs the live-grant record only.
    fn ra1_view(&self) -> Value {
        shell_live_grant_view(self.grant_view())
    }

    /// The named reason this stand-in recorded for every effect it refused.
    fn refusal_reasons(&self) -> Vec<String> {
        self.refusals.lock().unwrap().clone()
    }

    /// The shared stand-in's live-grant view a granting stand-in answers from.
    fn grant_view(&self) -> &Mutex<StandIn> {
        self.grants
            .as_ref()
            .expect("only a grant-checking stand-in keeps a live-grant view")
    }

    /// Waits for the accept loop to return `expected` connections, failing
    /// after `FIXTURE_EVENT_TIMEOUT`.
    fn wait_for_connections(&self, expected: usize) {
        let deadline = Instant::now() + FIXTURE_EVENT_TIMEOUT;
        while self.connection_count() < expected {
            assert!(
                Instant::now() < deadline,
                "the hosted run opened {} connections, not {expected}",
                self.connection_count()
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn stop_accepting(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(accept_loop) = self.accept_loop.take() {
            let _ = accept_loop.join();
        }
    }

    /// The connections accepted and every request read. It waits for the first
    /// recorded request, stops the accept loop, then counts every connection
    /// still queued on the listener. The stand-in records a request before it
    /// answers it, so a run that settled on the refusal always finds its record,
    /// and the short wait after the accept loop stops lets the last serving
    /// thread finish its record.
    fn observe(mut self) -> (usize, Vec<RecordedRequest>) {
        let first = self
            .requests
            .recv_timeout(FIXTURE_EVENT_TIMEOUT)
            .expect("the hosted effect request must reach the Runtime socket stand-in");
        self.stop_accepting();
        while let Ok((stream, _)) = self.listener.accept() {
            self.connections.fetch_add(1, Ordering::Relaxed);
            drop(stream);
        }
        let mut recorded = vec![first];
        let deadline = Instant::now() + Duration::from_millis(200);
        loop {
            match self.requests.recv_timeout(Duration::from_millis(20)) {
                Ok(request) => recorded.push(request),
                Err(_) if Instant::now() < deadline => continue,
                Err(_) => break,
            }
        }
        (self.connections.load(Ordering::Relaxed), recorded)
    }
}

impl Drop for HostedEffectStandIn {
    fn drop(&mut self) {
        self.stop_accepting();
        let _ = std::fs::remove_file(&self.path);
    }
}

fn serve_hosted_effect(
    stream: UnixStream,
    request_tx: mpsc::Sender<RecordedRequest>,
    answer_released: Arc<(Mutex<bool>, Condvar)>,
    answer: HostedEffectAnswer,
    relay_outcome: Arc<Mutex<Option<RelayOutcome>>>,
    refusals: Arc<Mutex<Vec<String>>>,
) {
    let recorded = read_hosted_effect_request(&stream);
    // The runtime binding's request id is the one tie between an effect and
    // its grant: the provider sends it as `x-elastos-request-id`
    // (`src/adapters.rs:45-70`) and the effect carries no grant id. It is read
    // before the record moves to the test.
    let request_id = recorded
        .value("x-elastos-request-id")
        .unwrap_or_default()
        .to_string();
    // A relaying answer forwards the provider's exact bytes, which the record
    // keeps for the test. The request is recorded before any wait, so a held
    // answer still counts the send the provider made.
    let body = recorded.body.clone();
    let _ = request_tx.send(recorded);
    {
        let (released, wake) = &*answer_released;
        let mut released = released.lock().unwrap();
        while !*released {
            released = wake.wait(released).unwrap();
        }
    }
    let response = match answer {
        HostedEffectAnswer::Refused => RUNTIME_HOSTED_REFUSAL.to_vec(),
        HostedEffectAnswer::Streaming { frames } => {
            frames.unwrap_or_else(runtime_hosted_stream_answer)
        }
        HostedEffectAnswer::Cut => runtime_hosted_cut_answer(),
        HostedEffectAnswer::Relay { backend_url } => {
            let outcome = relay_hosted_effect(&stream, &body, &backend_url);
            *relay_outcome.lock().unwrap() = Some(outcome);
            return;
        }
        HostedEffectAnswer::Granted {
            grants,
            served_session,
            backend_url,
        } => {
            // The check's first decision: an effect with no live entry for its
            // request id is refused.
            if !shell_view_lists_live_grant(&grants, &request_id) {
                // The refusal reaches the run as `hosted_effect_refused` with
                // class `access_refused` (`src/adapters.rs:2799-2829`), and no
                // backend sees the effect.
                refusals
                    .lock()
                    .unwrap()
                    .push(format!("no live grant for request {request_id}"));
                let _ = (&stream).write_all(RUNTIME_HOSTED_REFUSAL);
                return;
            }
            // The same check's session tie is the shared stand-in's one
            // admission rule, `StandIn::authorise`
            // (`lab/agent-conformance/standin-runtime/mod.rs:146-161`): the
            // grant must be for the session this stand-in serves, or it refuses
            // with its own reason, which names both sessions (`:504-510`).
            if let Err((_, reason)) = grants.lock().unwrap().authorise(
                Caller::Client {
                    session_id: &served_session,
                },
                &request_id,
            ) {
                refusals.lock().unwrap().push(reason);
                let _ = (&stream).write_all(RUNTIME_HOSTED_REFUSAL);
                return;
            }
            let relayed = relay_hosted_effect(&stream, &body, &backend_url);
            *relay_outcome.lock().unwrap() = Some(relayed);
            return;
        }
    };
    let _ = (&stream).write_all(&response);
}

/// What a relaying answer read from the backend: its status with the first
/// bytes of its answer, or the reason no answer arrived. A backend that refuses
/// the turn fails the test with its own status and body, not only with the
/// provider's error code.
#[derive(Clone)]
enum RelayOutcome {
    Answered { status: u16, first_bytes: Vec<u8> },
    Unreachable { reason: String },
}

/// The backend's answer prefix that a failure message carries.
const RELAY_FAILURE_BYTES: usize = 1024;

/// One relayed hosted effect: the stand-in sends the provider's body to the
/// backend, then writes the Runtime's accepted head, each backend body chunk as
/// one HTTP chunk, and the end `0\r\n\r\n`, the same framing
/// `runtime_hosted_stream_answer` builds
/// (`elastos/crates/elastos-server/src/api/model_provider_egress.rs:1644-1648`,
/// `:1650`, `:1662-1670`). It adds no field and no key, so the backend's body
/// is exactly the body the provider sent. Its only header of its own is
/// `content-type`; the client adds its own defaults.
fn relay_hosted_effect(stream: &UnixStream, body: &[u8], backend_url: &str) -> RelayOutcome {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return RelayOutcome::Unreachable {
            reason: "the stand-in could not build its relay runtime".to_string(),
        };
    };
    runtime.block_on(relay_turn(stream, body, backend_url))
}

async fn relay_turn(stream: &UnixStream, body: &[u8], backend_url: &str) -> RelayOutcome {
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(REAL_TURN_TIMEOUT)
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            return RelayOutcome::Unreachable {
                reason: format!("the stand-in could not build its client: {err}"),
            }
        }
    };
    let endpoint = format!("{}/v1/chat/completions", backend_url.trim_end_matches('/'));
    let mut response = match client
        .post(&endpoint)
        .header("content-type", "application/json")
        .body(body.to_vec())
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            return RelayOutcome::Unreachable {
                reason: reason_chain(&err),
            }
        }
    };
    let status = response.status();
    if !status.is_success() {
        let first_bytes = read_backend_prefix(&mut response).await;
        let mut answer = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Unknown"),
            first_bytes.len()
        )
        .into_bytes();
        answer.extend_from_slice(&first_bytes);
        let _ = (&*stream).write_all(&answer);
        return RelayOutcome::Answered {
            status: status.as_u16(),
            first_bytes,
        };
    }
    let _ = (&*stream).write_all(&runtime_hosted_stream_head());
    let mut frame = Vec::new();
    loop {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(err) => {
                // The head is written and the stream has no end, so the provider
                // reads an incomplete chunked body and fails the run closed.
                return RelayOutcome::Unreachable {
                    reason: format!("the backend stream broke after the head: {err}"),
                };
            }
        };
        frame.clear();
        push_runtime_hosted_stream_frame(&mut frame, &chunk);
        if let Err(err) = (&*stream).write_all(&frame) {
            // The provider closed its end of the Runtime socket, so the answer
            // stops here: the record says which socket failed, not that the
            // backend answered (P11).
            return RelayOutcome::Unreachable {
                reason: format!(
                    "the provider closed its Runtime socket before the stream ended: {err}"
                ),
            };
        }
    }
    let _ = (&*stream).write_all(b"0\r\n\r\n");
    RelayOutcome::Answered {
        status: status.as_u16(),
        first_bytes: Vec::new(),
    }
}

/// The full cause chain of a transport failure, so the failure names
/// `connection refused` and not only the client's wrapper text.
fn reason_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut reason = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        reason.push_str(": ");
        reason.push_str(&cause.to_string());
        source = cause.source();
    }
    reason
}

/// The backend's answer prefix, read to the end or to `RELAY_FAILURE_BYTES`.
async fn read_backend_prefix(response: &mut reqwest::Response) -> Vec<u8> {
    let mut prefix = Vec::new();
    while prefix.len() < RELAY_FAILURE_BYTES {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let room = RELAY_FAILURE_BYTES - prefix.len();
                prefix.extend_from_slice(&chunk[..chunk.len().min(room)]);
            }
            Ok(None) | Err(_) => break,
        }
    }
    prefix
}

/// Reads one request head and its body to the end, waiting at most
/// `FIXTURE_EVENT_TIMEOUT` for each read.
fn read_hosted_effect_request(stream: &UnixStream) -> RecordedRequest {
    // On macOS an accepted socket keeps the listener's non-blocking mode.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(FIXTURE_EVENT_TIMEOUT));
    read_request(stream)
}

/// Reads one request head and its body to the end from any reader, waiting at
/// most `FIXTURE_EVENT_TIMEOUT` for each read. The Runtime socket stand-in and
/// the local relay backend read a request this same way (P10).
fn read_request(reader: impl Read) -> RecordedRequest {
    let mut reader = BufReader::new(reader);
    let mut request_line = String::new();
    let _ = reader.read_line(&mut request_line);
    let mut headers = Vec::new();
    let mut colonless = Vec::new();
    let mut body_bytes = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                body_bytes = value.trim().parse().unwrap_or(0);
            }
            headers.push((name.to_string(), value.trim().to_string()));
        } else {
            // The Runtime refuses a header line that has no colon
            // (`elastos/crates/elastos-server/src/api/model_provider_egress.rs:556`),
            // so keep the line for the test to refuse it as the Runtime does.
            colonless.push(line.to_string());
        }
    }
    // Read the body to its end, so the refusal answers a complete request.
    let mut body = vec![0; body_bytes];
    let _ = reader.read_exact(&mut body);
    RecordedRequest {
        request_line: request_line.trim_end().to_string(),
        headers,
        colonless,
        body,
    }
}

/// A local loopback backend for the relaying stand-in. It accepts and answers
/// every connection until the test observes it: each connection's one request
/// is read to its end with `read_request`, recorded, and answered `200` with
/// the backend stream (`runtime_hosted_stream_frames`) as one plain
/// `text/event-stream` body and `Connection: close`. The relay test uses it to
/// read the bytes the relay actually sent, and no network leaves the loopback
/// interface.
struct LocalRelayBackend {
    url: String,
    listener: Arc<TcpListener>,
    sender: mpsc::Sender<RecordedRequest>,
    requests: Receiver<RecordedRequest>,
    stop: Arc<AtomicBool>,
    accept: Option<thread::JoinHandle<()>>,
}

impl LocalRelayBackend {
    fn bind() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the local relay backend");
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener
            .set_nonblocking(true)
            .expect("a stoppable local relay backend");
        let listener = Arc::new(listener);
        let (sender, requests) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let accept = {
            let listener = Arc::clone(&listener);
            let stopping = Arc::clone(&stop);
            let sender = sender.clone();
            thread::spawn(move || {
                while !stopping.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => serve_local_relay_request(stream, &sender),
                        Err(_) => thread::sleep(Duration::from_millis(5)),
                    }
                }
            })
        };
        Self {
            url,
            listener,
            sender,
            requests,
            stop,
            accept: Some(accept),
        }
    }

    fn url(&self) -> &str {
        &self.url
    }

    /// Every request the backend read, waiting `FIXTURE_EVENT_TIMEOUT` for the
    /// first one, then stopping the accept loop and answering the connections
    /// still queued on the listener. Every wait is bounded by
    /// `FIXTURE_EVENT_TIMEOUT`, so a relay that sends no request fails with
    /// "the relay must reach the local backend" and one that reaches the
    /// backend twice records two requests.
    fn observe(mut self) -> Vec<RecordedRequest> {
        let first = self
            .requests
            .recv_timeout(FIXTURE_EVENT_TIMEOUT)
            .expect("the relay must reach the local backend");
        self.stop.store(true, Ordering::Relaxed);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        // A connection the relay made just before the stop can still wait on
        // the listener, so answer it here before counting the records.
        while let Ok((stream, _)) = self.listener.accept() {
            serve_local_relay_request(stream, &self.sender);
        }
        let mut recorded = vec![first];
        while let Ok(request) = self.requests.try_recv() {
            recorded.push(request);
        }
        recorded
    }

    /// Every request already recorded, including none. A refusal returns before
    /// the relay, so this call's backend has no request to wait for.
    fn take_requests(mut self) -> Vec<RecordedRequest> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        while let Ok((stream, _)) = self.listener.accept() {
            serve_local_relay_request(stream, &self.sender);
        }
        let mut recorded = Vec::new();
        let deadline = Instant::now() + Duration::from_millis(200);
        loop {
            match self.requests.try_recv() {
                Ok(request) => recorded.push(request),
                Err(_) if recorded.is_empty() && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
        recorded
    }
}

/// Reads one request from an accepted loopback connection, records it, and
/// answers `200` with the backend stream (`runtime_hosted_stream_frames`) as
/// one plain `text/event-stream` body and `Connection: close`.
fn serve_local_relay_request(stream: TcpStream, sender: &mpsc::Sender<RecordedRequest>) {
    // On macOS an accepted socket keeps the listener's non-blocking mode.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(FIXTURE_EVENT_TIMEOUT));
    let recorded = read_request(&stream);
    let _ = sender.send(recorded);
    let body = runtime_hosted_stream_frames().concat();
    let mut answer = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    answer.extend_from_slice(body.as_bytes());
    let _ = (&stream).write_all(&answer);
}

/// The provider's half of the join with the Runtime's hosted effect transport.
/// With `runtime_hosted_socket` set, macOS sends each hosted effect to
/// `http://runtime.invalid/v1/hosted-effect` with the offer, run, request and
/// effect headers and no key (`effect_request` at `src/adapters.rs:45-70`), and
/// the OpenAI-compatible text worker adds the bearer header only when no
/// Runtime socket is set (`src/adapters.rs:1980-1984`). The Runtime's reader
/// accepts one exact request line and a closed header list
/// (`elastos/crates/elastos-server/src/api/model_provider_egress.rs:549-578`),
/// so a drift fails the run closed there with no named test in this lane
/// saying why. This test pins the four headers, the contract run id, and the
/// absent key.
///
/// The stand-in lives in this file: `tests/confine/main.rs` is cc-model-confine's
/// file in another test binary, and `src/test_support.rs` is under `src/`, where
/// a change needs a fresh Sasha note.
///
/// Off macOS the provider refuses every hosted run before any socket, so the
/// test prints one `SKIP` line and returns.
#[test]
fn hosted_run_posts_the_runtime_effect_headers_with_the_contract_run_id_and_no_key() {
    if !cfg!(target_os = "macos") {
        eprintln!(
            "SKIP model-provider hosted effect headers: off macOS the provider \
             refuses every hosted run before any socket"
        );
        return;
    }
    let root = test_support::temp_root_path("model-provider-process", "hosted-effect-headers");
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let stand_in = HostedEffectStandIn::bind("hosted-effect-headers");
    let init = hosted_effect_init(
        &root,
        &stand_in,
        HOSTED_FIXTURE_MODEL,
        HOSTED_FIXTURE_RUNTIME_MS_LIMIT,
    );
    let mut provider = ProviderProcess::start();
    let started = provider.request(init);
    assert_eq!(
        started["status"], "ok",
        "unexpected init response: {started}"
    );

    let input = json!({
        "schema": elastos_model_contract::TEXT_INPUT_V1_SCHEMA,
        "prompt": "hosted effect headers"
    });
    let create_request = json!({
        "op": "runs_create",
        "offer_id": HOSTED_EFFECT_OFFER,
        "operation": "text.generate",
        "input": input,
        "runtime_binding": {
            "schema": RUNTIME_CREATE_BINDING_SCHEMA,
            "principal_id": "person:local:test",
            "session_id": "session:test",
            "capsule_id": "assistant",
            "grant_id": "grant:test",
            "request_id": test_support::fixture_model_request_id("request:hosted-effect-headers"),
            "offer_id": HOSTED_EFFECT_OFFER,
            "operation": "text.generate",
            "input_hash": model_input_hash(&input).unwrap()
        }
    });
    let create = provider.request(create_request.clone());
    assert_eq!(
        create["status"], "ok",
        "unexpected create response: {create}"
    );
    let returned_run_id = create["data"]["run_id"]
        .as_str()
        .expect("runs_create returns the run id")
        .to_string();
    let binding: RuntimeCreateBinding =
        serde_json::from_value(create_request["runtime_binding"].clone()).unwrap();
    let expected_run_id = model_run_id(&binding);
    assert_eq!(
        returned_run_id, expected_run_id,
        "runs_create must return the contract run id"
    );
    let settled = wait_for_run_terminal(
        &mut provider,
        &returned_run_id,
        &access_binding(&create_request),
    );
    assert_eq!(
        settled["data"]["status"], "failed",
        "the Runtime refusal must fail the run: {settled}"
    );
    assert_eq!(
        settled["data"]["terminal"]["error"]["code"], "hosted_effect_refused",
        "the Runtime refusal must settle the run with its reason: {settled}"
    );

    let (connections, requests) = stand_in.observe();
    assert_eq!(
        connections, 1,
        "the hosted run must open exactly one connection to the Runtime socket"
    );
    assert_eq!(
        requests.len(),
        1,
        "the hosted run must send exactly one request"
    );
    let recorded = &requests[0];
    assert_eq!(recorded.request_line, "POST /v1/hosted-effect HTTP/1.1");
    let mut names: Vec<String> = Vec::new();
    for (name, _) in &recorded.headers {
        let name = name.to_ascii_lowercase();
        assert!(
            RUNTIME_HOSTED_HEADER_NAMES.contains(&name.as_str()),
            "the Runtime refuses every other header name: {name}"
        );
        assert!(
            !names.contains(&name),
            "the Runtime refuses a repeated header name: {name}"
        );
        names.push(name);
    }
    assert_eq!(recorded.value("host"), Some("runtime.invalid"));
    assert_eq!(recorded.value("x-elastos-effect"), Some("text"));
    assert_eq!(
        recorded.value("x-elastos-offer-id"),
        Some(HOSTED_EFFECT_OFFER)
    );
    assert_eq!(
        recorded.value("x-elastos-request-id"),
        create_request["runtime_binding"]["request_id"].as_str()
    );
    assert_eq!(
        recorded.value("x-elastos-run-id"),
        Some(expected_run_id.as_str())
    );
    assert_eq!(
        recorded.value("authorization"),
        None,
        "a hosted run must carry no bearer key"
    );
    assert_eq!(
        recorded.value("x-elastos-job-id"),
        None,
        "a text effect carries no job id"
    );
    assert!(
        !recorded.head().contains("fixture-key"),
        "the offer's key must appear nowhere in the recorded request head: {}",
        recorded.head()
    );

    provider.shutdown();
}

/// The answer leg of the provider's join with the Runtime's hosted transport.
/// The Runtime writes its own head, forwards each backend chunk as an HTTP
/// chunk and ends the stream
/// (`elastos/crates/elastos-server/src/api/model_provider_egress.rs:1662-1670`,
/// `:1644-1648`, `:1650`). Task 035 pins the request leg and the Runtime's
/// refusal; this test pins the accepted answer: one hosted text run completes
/// with the streamed text and the backend's usage. The stand-in answers in
/// exactly that shape with the source test's events
/// (`capsules/model-provider/src/execution.rs:4514-4535`), and no cost is in
/// the stream, so the run records cost as unknown
/// (`capsules/model-provider/src/adapters.rs:416-418`, `:437-443`).
///
/// Off macOS the provider refuses every hosted run before any socket, so the
/// test prints one `SKIP` line and returns.
#[test]
fn hosted_answer_through_the_runtime_socket_completes_the_run_with_text_and_usage() {
    if !cfg!(target_os = "macos") {
        eprintln!(
            "SKIP model-provider hosted accepted answer: off macOS the provider \
             refuses every hosted run before any socket"
        );
        return;
    }
    let root = test_support::temp_root_path("model-provider-process", "hosted-accepted-answer");
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let stand_in = HostedEffectStandIn::bind_streaming("hosted-accepted-answer");
    let init = hosted_effect_init(
        &root,
        &stand_in,
        HOSTED_FIXTURE_MODEL,
        HOSTED_FIXTURE_RUNTIME_MS_LIMIT,
    );
    let mut provider = ProviderProcess::start();
    let started = provider.request(init);
    assert_eq!(
        started["status"], "ok",
        "unexpected init response: {started}"
    );

    let input = json!({
        "schema": elastos_model_contract::TEXT_INPUT_V1_SCHEMA,
        "prompt": "a hosted answer"
    });
    let create_request = json!({
        "op": "runs_create",
        "offer_id": HOSTED_EFFECT_OFFER,
        "operation": "text.generate",
        "input": input,
        "runtime_binding": {
            "schema": RUNTIME_CREATE_BINDING_SCHEMA,
            "principal_id": "person:local:test",
            "session_id": "session:test",
            "capsule_id": "assistant",
            "grant_id": "grant:test",
            "request_id": test_support::fixture_model_request_id(
                "request:hosted-accepted-answer"
            ),
            "offer_id": HOSTED_EFFECT_OFFER,
            "operation": "text.generate",
            "input_hash": model_input_hash(&input).unwrap()
        }
    });
    let binding: RuntimeCreateBinding =
        serde_json::from_value(create_request["runtime_binding"].clone()).unwrap();
    let expected_run_id = model_run_id(&binding);
    let create = provider.request(create_request.clone());
    assert_eq!(
        create["status"], "ok",
        "unexpected create response: {create}"
    );
    assert_eq!(
        create["data"]["run_id"], expected_run_id,
        "runs_create must return the contract run id"
    );

    let settled = wait_for_run_terminal(
        &mut provider,
        &expected_run_id,
        &access_binding(&create_request),
    );
    assert_eq!(
        settled["data"]["run_id"], expected_run_id,
        "runs_get must return the contract run id"
    );
    assert_eq!(
        settled["data"]["status"], "completed",
        "the Runtime's accepted answer must complete the run: {settled}"
    );
    assert_eq!(
        settled["data"]["terminal"]["output"],
        json!({"schema": RUN_OUTPUT_TEXT_SCHEMA, "text": "ready"}),
        "the run must carry the streamed text: {settled}"
    );
    assert_eq!(
        settled["data"]["terminal"]["backend_report"],
        json!({
            "schema": BACKEND_REPORT_SCHEMA,
            "resolved_model": {"status": "reported", "value": "resolved-model"},
            "usage": {
                "status": "reported",
                "value": {"input_tokens": 7, "output_tokens": 1, "total_tokens": 8},
            },
            // The usage event carries no `cost` or `cost_unit`, so the worker
            // observes cost only when one is present and the report says
            // unknown (`src/adapters.rs:416-418`, `:437-443`).
            "cost": {"status": "unknown"},
        }),
        "the run must carry the backend's evidence: {settled}"
    );

    let (connections, requests) = stand_in.observe();
    assert_eq!(
        connections, 1,
        "the accepted run must open exactly one connection to the Runtime socket"
    );
    assert_eq!(
        requests.len(),
        1,
        "the accepted run must send exactly one request"
    );
    let recorded = &requests[0];
    assert_eq!(recorded.request_line, "POST /v1/hosted-effect HTTP/1.1");
    assert!(
        recorded.colonless.is_empty(),
        "the Runtime refuses a header line with no colon: {:?}",
        recorded.colonless
    );
    assert_eq!(
        recorded.value("authorization"),
        None,
        "a hosted run must carry no bearer key"
    );

    provider.shutdown();
}

/// The model every fixture hosted test pins. The one real turn passes
/// `deepseek-v4-flash` instead.
const HOSTED_FIXTURE_MODEL: &str = "fixture/text";

/// The run limit every fixture hosted test gives the one offer. The real turn
/// passes its own, longer limit.
const HOSTED_FIXTURE_RUNTIME_MS_LIMIT: u64 = 30_000;

/// The hosted `open_ai_compatible_text` offer task 035 uses, with the fixture
/// key that a hosted run must never put on the Runtime socket. Every hosted
/// test calls `hosted_effect_init`, so there is one copy of this offer. The
/// model id and the run limit are parameters because the opt-in real turn pins
/// the DeepSeek selector and needs a longer run limit than the fixture.
fn hosted_effect_offer(model: &str, runtime_ms_limit: u64) -> Value {
    let policy = json!({
        "concurrency_limit": 1, "input_bytes_limit": 8192,
        "inline_output_bytes_limit": 8192, "event_bytes_limit": 8192,
        "runtime_ms_limit": runtime_ms_limit, "retention_secs": 60,
        "cancel_settlement_timeout_ms": 20
    });
    let hosted = json!({
        "backend_provider_label": "Fixture Provider", "selection_mode": "pinned",
        "privacy_policy_ref": "fixture:privacy:v1", "terms_ref": "fixture:terms:v1",
        "upstream_routing_fallback_assertion": "operator_asserted_disabled",
        "model_privacy": ""
    });
    json!({
        "id": HOSTED_EFFECT_OFFER, "title": "Hosted Text",
        "operation": "text.generate",
        "input_modalities": ["text/plain"], "output_modalities": ["text/plain"],
        "policy": policy,
        "adapter": {"kind": "open_ai_compatible_text",
        "api_url": "https://hosted.invalid/v1/chat/completions",
        "api_key": "fixture-key", "model": model, "hosted": hosted},
        "enabled": true
    })
}

/// The `init` request every hosted test sends: the shared offer and the
/// stand-in's socket, with the fixture root as `base_path` and its `journal`
/// folder as `journal_dir`. The offer's model id and run limit are parameters,
/// so the opt-in real turn pins the DeepSeek selector through this one init.
fn hosted_effect_init(
    root: &Path,
    stand_in: &HostedEffectStandIn,
    model: &str,
    runtime_ms_limit: u64,
) -> Value {
    json!({"op": "init", "config": {
        "base_path": root, "allowed_paths": [], "read_only": false, "encryption_key": "",
        "extra": {"provider_id": "model-provider", "journal_dir": root.join("journal"),
        "offers": [hosted_effect_offer(model, runtime_ms_limit)],
        "runtime_hosted_socket": &stand_in.path}
    }})
}

/// A retry of an open hosted run is a replay, not a second send. The stored
/// run owns its result (`src/state.rs:518-531`): the retry returns the same run
/// before any dispatch (`:530`), and the third request returns the
/// settled result. The held stand-in keeps the first effect open, so the test
/// can count connections and requests while the run is still running and after
/// it settles. A second send here would give the Runtime two hosted effects for
/// one run, which the one account across retries must not see. Off macOS the
/// provider refuses every hosted run before any socket, so the test prints one
/// `SKIP` line and returns.
#[test]
fn hosted_retry_of_an_open_run_returns_the_same_run_and_sends_no_second_effect() {
    if !cfg!(target_os = "macos") {
        eprintln!(
            "SKIP model-provider hosted open-run retry: off macOS the provider \
             refuses every hosted run before any socket"
        );
        return;
    }
    let root = test_support::temp_root_path("model-provider-process", "hosted-open-run-retry");
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let stand_in = HostedEffectStandIn::bind("hosted-open-run-retry");
    stand_in.hold_answer();
    let init = hosted_effect_init(
        &root,
        &stand_in,
        HOSTED_FIXTURE_MODEL,
        HOSTED_FIXTURE_RUNTIME_MS_LIMIT,
    );
    let mut provider = ProviderProcess::start();
    let started = provider.request(init);
    assert_eq!(
        started["status"], "ok",
        "unexpected init response: {started}"
    );

    let input = json!({
        "schema": elastos_model_contract::TEXT_INPUT_V1_SCHEMA,
        "prompt": "hosted open run retry"
    });
    let create_request = json!({
        "op": "runs_create",
        "offer_id": HOSTED_EFFECT_OFFER,
        "operation": "text.generate",
        "input": input,
        "runtime_binding": {
            "schema": RUNTIME_CREATE_BINDING_SCHEMA,
            "principal_id": "person:local:test",
            "session_id": "session:test",
            "capsule_id": "assistant",
            "grant_id": "grant:test",
            "request_id": test_support::fixture_model_request_id("request:hosted-open-run-retry"),
            "offer_id": HOSTED_EFFECT_OFFER,
            "operation": "text.generate",
            "input_hash": model_input_hash(&input).unwrap()
        }
    });
    let binding: RuntimeCreateBinding =
        serde_json::from_value(create_request["runtime_binding"].clone()).unwrap();
    let expected_run_id = model_run_id(&binding);

    let create = provider.request(create_request.clone());
    assert_eq!(
        create["status"], "ok",
        "unexpected create response: {create}"
    );
    assert_eq!(
        create["data"]["run_id"], expected_run_id,
        "runs_create must return the contract run id"
    );
    assert!(
        create["data"]["terminal"].is_null(),
        "the first hosted run must stay open while the Runtime socket holds its answer: {create}"
    );
    assert!(
        matches!(
            create["data"]["status"].as_str(),
            Some("prepared" | "running")
        ),
        "the first hosted run must report an open status: {create}"
    );
    stand_in.wait_for_connections(1);
    assert_eq!(
        stand_in.connection_count(),
        1,
        "the hosted run must open exactly one connection to the Runtime socket"
    );

    let retry = provider.request(create_request.clone());
    assert_eq!(retry["status"], "ok", "unexpected retry response: {retry}");
    assert_eq!(
        retry["data"]["run_id"], expected_run_id,
        "the retry must return the same run id"
    );
    assert!(
        retry["data"]["terminal"].is_null(),
        "the retry of an open run must return its open status: {retry}"
    );
    assert!(
        matches!(
            retry["data"]["status"].as_str(),
            Some("prepared" | "running")
        ),
        "the retry of an open run must report an open status: {retry}"
    );
    assert_eq!(
        stand_in.connection_count(),
        1,
        "the retry must send no second hosted effect: {retry}"
    );

    stand_in.release_answer();
    let settled = wait_for_run_terminal(
        &mut provider,
        &expected_run_id,
        &access_binding(&create_request),
    );
    assert_eq!(
        settled["data"]["status"], "failed",
        "the Runtime refusal must fail the held run: {settled}"
    );
    assert_eq!(
        settled["data"]["terminal"]["error"]["code"], "hosted_effect_refused",
        "the Runtime refusal must settle the run with its reason: {settled}"
    );

    let replay = provider.request(create_request);
    assert_eq!(
        replay["status"], "ok",
        "unexpected replay response: {replay}"
    );
    assert_eq!(
        replay["data"]["run_id"], expected_run_id,
        "the settled retry must return the same run id"
    );
    assert_eq!(
        replay["data"]["status"], "failed",
        "the settled retry must return the stored terminal status: {replay}"
    );
    assert_eq!(
        replay["data"]["terminal"]["error"]["code"], "hosted_effect_refused",
        "the settled retry must return the stored reason: {replay}"
    );

    let (connections, requests) = stand_in.observe();
    assert_eq!(
        connections, 1,
        "the open-run retry must not open a second connection to the Runtime socket"
    );
    assert_eq!(
        requests.len(),
        1,
        "the open-run retry must not send a second hosted request"
    );

    provider.shutdown();
}

/// What the provider records when the Runtime cuts a hosted answer part way
/// through. The Runtime writes its own head and copies each backend chunk; it
/// returns an error after the head and some chunks when the grant ends or the
/// body grows too large
/// (`elastos/crates/elastos-server/src/api/model_provider_egress.rs:1631`,
/// `:1638-1642`), and it never writes the closing `0\r\n\r\n`, which is only
/// at `:1650`. Its caller shuts the socket down when `forward` returns an
/// error (`:531-532`), so the provider reads an incomplete chunked body. The
/// worker's chunk read then maps the error through
/// `map_text_reqwest_failure` (`capsules/model-provider/src/adapters.rs:2027`,
/// `:2397`) to `map_reqwest_failure` (`:2773`) and `AdapterFault::transport`
/// (`:159-168`). That fault becomes a `failed` terminal with
/// `output: None` and `backend_report: None` (`:1489-1509`), so the
/// `resolved-model` the cut stream already named is dropped. The state layer
/// stores `BackendReport::unknown()` for a hosted run with no report
/// (`capsules/model-provider/src/state.rs:1352-1354`): `resolved_model`,
/// `usage` and `cost` are all unknown
/// (`capsules/model-provider/src/contract.rs:212-219`). A clean end with no
/// `[DONE]` would instead be `response_malformed` "text stream ended before
/// terminal marker" (`src/adapters.rs:2029-2033`), so the code assertion tells
/// the two apart.
///
/// The buffered `ready` delta is not asserted: whether it is published before
/// the fault depends on the flush timer (`src/adapters.rs:2007-2026`).
///
/// Off macOS the provider refuses every hosted run before any socket, so the
/// test prints one `SKIP` line and returns.
#[test]
fn hosted_stream_cut_by_the_runtime_fails_the_run_with_unknown_usage() {
    if !cfg!(target_os = "macos") {
        eprintln!(
            "SKIP model-provider hosted stream cut: off macOS the provider \
             refuses every hosted run before any socket"
        );
        return;
    }
    let root = test_support::temp_root_path("model-provider-process", "hosted-stream-cut");
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let stand_in = HostedEffectStandIn::bind_cut("hosted-stream-cut");
    let init = hosted_effect_init(
        &root,
        &stand_in,
        HOSTED_FIXTURE_MODEL,
        HOSTED_FIXTURE_RUNTIME_MS_LIMIT,
    );
    let mut provider = ProviderProcess::start();
    let started = provider.request(init);
    assert_eq!(
        started["status"], "ok",
        "unexpected init response: {started}"
    );

    let input = json!({
        "schema": elastos_model_contract::TEXT_INPUT_V1_SCHEMA,
        "prompt": "a hosted answer the Runtime cuts"
    });
    let create_request = json!({
        "op": "runs_create",
        "offer_id": HOSTED_EFFECT_OFFER,
        "operation": "text.generate",
        "input": input,
        "runtime_binding": {
            "schema": RUNTIME_CREATE_BINDING_SCHEMA,
            "principal_id": "person:local:test",
            "session_id": "session:test",
            "capsule_id": "assistant",
            "grant_id": "grant:test",
            "request_id": test_support::fixture_model_request_id("request:hosted-stream-cut"),
            "offer_id": HOSTED_EFFECT_OFFER,
            "operation": "text.generate",
            "input_hash": model_input_hash(&input).unwrap()
        }
    });
    let binding: RuntimeCreateBinding =
        serde_json::from_value(create_request["runtime_binding"].clone()).unwrap();
    let expected_run_id = model_run_id(&binding);
    let create = provider.request(create_request.clone());
    assert_eq!(
        create["status"], "ok",
        "unexpected create response: {create}"
    );
    assert_eq!(
        create["data"]["run_id"], expected_run_id,
        "runs_create must return the contract run id"
    );

    let settled = wait_for_run_terminal(
        &mut provider,
        &expected_run_id,
        &access_binding(&create_request),
    );
    assert_eq!(
        settled["data"]["run_id"], expected_run_id,
        "runs_get must return the contract run id"
    );
    assert_eq!(
        settled["data"]["status"], "failed",
        "a cut hosted stream must fail the run: {settled}"
    );
    // The incomplete chunked body is a chunk read error, not a clean end
    // (`src/adapters.rs:2027`, then `:2773-2785` and `:159-168`).
    assert_eq!(
        settled["data"]["terminal"]["error"]["code"], "transport_interrupted",
        "a cut hosted stream must settle with the transport fault: {settled}"
    );
    assert!(
        settled["data"]["terminal"]["output"].is_null(),
        "a failed run must carry no output: {settled}"
    );
    assert_eq!(
        settled["data"]["terminal"]["backend_report"],
        json!({
            "schema": BACKEND_REPORT_SCHEMA,
            "resolved_model": {"status": "unknown"},
            "usage": {"status": "unknown"},
            "cost": {"status": "unknown"},
        }),
        "a cut hosted stream must record resolved_model, usage and cost as unknown: {settled}"
    );

    let (connections, requests) = stand_in.observe();
    assert_eq!(
        connections, 1,
        "the cut run must open exactly one connection to the Runtime socket"
    );
    assert_eq!(
        requests.len(),
        1,
        "the cut run must send exactly one request"
    );
    let recorded = &requests[0];
    assert_eq!(recorded.request_line, "POST /v1/hosted-effect HTTP/1.1");
    assert_eq!(
        recorded.value("authorization"),
        None,
        "a hosted run must carry no bearer key"
    );

    provider.shutdown();
}

/// What the provider does when an agent cancels a hosted text run while the
/// Runtime still holds the answer. Every text adapter's `cancel` goes to
/// `cancel_local_text` (`capsules/model-provider/src/adapters.rs:1240-1245`,
/// function at `:1455-1474`), which sends only the worker's `cancel_tx`
/// (`:1469`) and returns `Reconciling` (`:1470-1473`). It sends no cancel
/// effect to the Runtime socket. The worker's open-send select
/// (`src/adapters.rs:1990-1996`) and its chunk read (`:2015-2019`) both return
/// `cancel_text_worker` (`:2292-2300`), which for any backend that is not
/// local llama returns `worker_settlement_unknown_result()`
/// (`:2685-2697`): status `settlement_unknown`, code `settlement_unknown`,
/// no output and no backend report. The state layer stores
/// `BackendReport::unknown()` for a hosted run with no report
/// (`src/state.rs:1352-1355`), so `resolved_model`, `usage` and `cost` are all
/// `unknown` (`src/contract.rs:212-219`). The stand-in therefore sees one
/// connection and one request in total, with no cancel request.
///
/// The terminal is read while the stand-in still holds the answer, so the
/// settlement cannot come from the Runtime's refusal or from a released
/// answer. Off macOS the provider refuses every hosted run before any socket,
/// so the test prints one `SKIP` line and returns.
#[test]
fn hosted_cancel_while_the_answer_is_held_settles_unknown_and_sends_nothing_more() {
    if !cfg!(target_os = "macos") {
        eprintln!(
            "SKIP model-provider hosted cancel while held: off macOS the provider \
             refuses every hosted run before any socket"
        );
        return;
    }
    let root = test_support::temp_root_path("model-provider-process", "hosted-cancel-held");
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let stand_in = HostedEffectStandIn::bind("hosted-cancel-held");
    stand_in.hold_answer();
    let init = hosted_effect_init(
        &root,
        &stand_in,
        HOSTED_FIXTURE_MODEL,
        HOSTED_FIXTURE_RUNTIME_MS_LIMIT,
    );
    let mut provider = ProviderProcess::start();
    let started = provider.request(init);
    assert_eq!(
        started["status"], "ok",
        "unexpected init response: {started}"
    );

    let input = json!({
        "schema": elastos_model_contract::TEXT_INPUT_V1_SCHEMA,
        "prompt": "a hosted answer held through a cancel"
    });
    let create_request = json!({
        "op": "runs_create",
        "offer_id": HOSTED_EFFECT_OFFER,
        "operation": "text.generate",
        "input": input,
        "runtime_binding": {
            "schema": RUNTIME_CREATE_BINDING_SCHEMA,
            "principal_id": "person:local:test",
            "session_id": "session:test",
            "capsule_id": "assistant",
            "grant_id": "grant:test",
            "request_id": test_support::fixture_model_request_id("request:hosted-cancel-held"),
            "offer_id": HOSTED_EFFECT_OFFER,
            "operation": "text.generate",
            "input_hash": model_input_hash(&input).unwrap()
        }
    });
    let binding: RuntimeCreateBinding =
        serde_json::from_value(create_request["runtime_binding"].clone()).unwrap();
    let expected_run_id = model_run_id(&binding);

    let create = provider.request(create_request.clone());
    assert_eq!(
        create["status"], "ok",
        "unexpected create response: {create}"
    );
    assert_eq!(
        create["data"]["run_id"], expected_run_id,
        "runs_create must return the contract run id"
    );
    assert!(
        matches!(
            create["data"]["status"].as_str(),
            Some("prepared" | "running")
        ),
        "the hosted run must report an open status while the answer is held: {create}"
    );
    // The stand-in reads and records the request while `request.send()` is
    // still the pending arm of the worker's select
    // (`src/adapters.rs:1990-1996`), so the worker owns the open send before
    // the cancel arrives.
    stand_in.wait_for_connections(1);

    let cancel = provider.request(json!({
        "op": "runs_cancel",
        "run_id": expected_run_id,
        "runtime_binding": access_binding(&create_request)
    }));
    assert_eq!(
        cancel["status"], "ok",
        "unexpected cancel response: {cancel}"
    );
    assert_eq!(
        cancel["data"]["run_id"], expected_run_id,
        "runs_cancel must return the same run id"
    );
    // `cancel_local_text` signals the worker and returns `Reconciling`
    // (`src/adapters.rs:1469-1473`); it sends nothing to the Runtime socket.
    assert_eq!(
        cancel["data"]["status"], "reconciling",
        "a hosted cancel of an open send must report reconciling: {cancel}"
    );

    // The answer is still held: this terminal comes from the worker's cancel
    // arm (`src/adapters.rs:1990-1996` through `:2292-2300` to
    // `:2685-2697`), not from a backend answer.
    let settled = wait_for_run_terminal(
        &mut provider,
        &expected_run_id,
        &access_binding(&create_request),
    );
    assert_eq!(
        settled["data"]["run_id"], expected_run_id,
        "runs_get must return the contract run id"
    );
    assert_eq!(
        settled["data"]["status"], "settlement_unknown",
        "a hosted cancel with an open send must settle unknown: {settled}"
    );
    assert_eq!(
        settled["data"]["terminal"]["error"]["code"], "settlement_unknown",
        "a hosted cancel with an open send must carry its reason: {settled}"
    );
    assert!(
        settled["data"]["terminal"].get("output").is_none(),
        "an unknown settlement must carry no output: {settled}"
    );
    assert_eq!(
        settled["data"]["terminal"]["backend_report"],
        json!({
            "schema": BACKEND_REPORT_SCHEMA,
            "resolved_model": {"status": "unknown"},
            "usage": {"status": "unknown"},
            "cost": {"status": "unknown"},
        }),
        "a hosted cancel must record resolved_model, usage and cost as unknown: {settled}"
    );

    // Release only now, so the stand-in thread can exit; the connection and
    // request counts do not depend on when it sees the close.
    stand_in.release_answer();
    let (connections, requests) = stand_in.observe();
    assert_eq!(
        connections, 1,
        "the cancelled hosted run must open exactly one connection to the Runtime socket"
    );
    assert_eq!(
        requests.len(),
        1,
        "the cancelled hosted run must send exactly one request"
    );
    let recorded = &requests[0];
    assert_eq!(recorded.request_line, "POST /v1/hosted-effect HTTP/1.1");
    assert_eq!(
        recorded.value("authorization"),
        None,
        "a hosted run must carry no bearer key"
    );

    provider.shutdown();
}

/// A second hosted run that meets the offer's ceiling is refused before it
/// sends anything. The provider stores the prepared run, reads the offer's open
/// journal rows (`src/state.rs:606`, `:608`) and compares that count with
/// `concurrency_limit` (`:609`). A count above it fails the new run with
/// `rate_limited`/`model_busy` (`:610-620`) and returns its view (`:621`)
/// before `self.adapters.dispatch` (`:623`), so the Runtime socket sees no
/// effect for the refused run. The run is hosted and carries no report, so its
/// terminal stores `BackendReport::unknown()` (`src/state.rs:1352-1354`, the
/// arm at `:1354`), which makes `resolved_model`, `usage` and `cost` all
/// `unknown` (`src/contract.rs:212-219`). A sent run with no report records the
/// same value, so a Runtime reading only `usage` cannot tell "not sent" from
/// "sent, not reported". The third run is created after the held run settles,
/// so its admission shows the ceiling counts open runs, not every run.
///
/// Off macOS the provider refuses every hosted run before any socket, so the
/// test prints one `SKIP` line and returns.
#[test]
fn hosted_second_concurrent_run_is_refused_model_busy_and_sends_no_effect() {
    if !cfg!(target_os = "macos") {
        eprintln!(
            "SKIP model-provider hosted second concurrent run: off macOS the provider \
             refuses every hosted run before any socket"
        );
        return;
    }
    let root = test_support::temp_root_path("model-provider-process", "hosted-second-concurrent");
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let stand_in = HostedEffectStandIn::bind("hosted-second-concurrent");
    stand_in.hold_answer();
    let init = hosted_effect_init(
        &root,
        &stand_in,
        HOSTED_FIXTURE_MODEL,
        HOSTED_FIXTURE_RUNTIME_MS_LIMIT,
    );
    let mut provider = ProviderProcess::start();
    let started = provider.request(init);
    assert_eq!(
        started["status"], "ok",
        "unexpected init response: {started}"
    );

    let input = json!({
        "schema": elastos_model_contract::TEXT_INPUT_V1_SCHEMA,
        "prompt": "a second hosted run at the offer ceiling"
    });
    let create_a = json!({
        "op": "runs_create",
        "offer_id": HOSTED_EFFECT_OFFER,
        "operation": "text.generate",
        "input": input,
        "runtime_binding": {
            "schema": RUNTIME_CREATE_BINDING_SCHEMA,
            "principal_id": "person:local:test",
            "session_id": "session:test",
            "capsule_id": "assistant",
            "grant_id": "grant:test",
            "request_id": test_support::fixture_model_request_id(
                "request:hosted-second-concurrent-a"
            ),
            "offer_id": HOSTED_EFFECT_OFFER,
            "operation": "text.generate",
            "input_hash": model_input_hash(&input).unwrap()
        }
    });
    let mut create_b = create_a.clone();
    create_b["runtime_binding"]["request_id"] = json!(test_support::fixture_model_request_id(
        "request:hosted-second-concurrent-b"
    ));
    let mut create_c = create_a.clone();
    create_c["runtime_binding"]["request_id"] = json!(test_support::fixture_model_request_id(
        "request:hosted-second-concurrent-c"
    ));

    let binding_a: RuntimeCreateBinding =
        serde_json::from_value(create_a["runtime_binding"].clone()).unwrap();
    let binding_b: RuntimeCreateBinding =
        serde_json::from_value(create_b["runtime_binding"].clone()).unwrap();
    let binding_c: RuntimeCreateBinding =
        serde_json::from_value(create_c["runtime_binding"].clone()).unwrap();
    let run_a = model_run_id(&binding_a);
    let run_b = model_run_id(&binding_b);
    let run_c = model_run_id(&binding_c);
    assert_ne!(run_a, run_b, "each request id must name its own run");

    let created_a = provider.request(create_a.clone());
    assert_eq!(
        created_a["status"], "ok",
        "unexpected create response: {created_a}"
    );
    assert_eq!(
        created_a["data"]["run_id"], run_a,
        "runs_create must return the contract run id"
    );
    assert!(
        matches!(
            created_a["data"]["status"].as_str(),
            Some("prepared" | "running")
        ),
        "the first hosted run must report an open status: {created_a}"
    );
    stand_in.wait_for_connections(1);
    assert_eq!(
        stand_in.connection_count(),
        1,
        "the first hosted run must open exactly one connection to the Runtime socket"
    );

    let created_b = provider.request(create_b.clone());
    assert_eq!(
        created_b["status"], "ok",
        "unexpected create response: {created_b}"
    );
    assert_eq!(
        created_b["data"]["run_id"], run_b,
        "runs_create must return the contract run id"
    );
    // The open-run count above the offer ceiling fails the new run with
    // `rate_limited`/`model_busy` (`src/state.rs:610-620`) and returns before
    // any dispatch (`:621`, dispatch at `:623`).
    assert_eq!(
        created_b["data"]["status"], "failed",
        "a run above the offer ceiling must fail at once: {created_b}"
    );
    assert_eq!(
        created_b["data"]["terminal"]["error"]["code"], "model_busy",
        "a run above the offer ceiling must carry the busy reason: {created_b}"
    );
    assert_eq!(
        created_b["data"]["terminal"]["error"]["class"], "rate_limited",
        "a run above the offer ceiling must carry the rate-limited class: {created_b}"
    );
    assert!(
        created_b["data"]["terminal"]["output"].is_null(),
        "a refused run must carry no output: {created_b}"
    );
    // A hosted terminal transition with no report records
    // `BackendReport::unknown()` (`src/state.rs:1352-1354`).
    assert_eq!(
        created_b["data"]["terminal"]["backend_report"],
        json!({
            "schema": BACKEND_REPORT_SCHEMA,
            "resolved_model": {"status": "unknown"},
            "usage": {"status": "unknown"},
            "cost": {"status": "unknown"},
        }),
        "a refused hosted run must record resolved_model, usage and cost as unknown: {created_b}"
    );
    assert_eq!(
        stand_in.connection_count(),
        1,
        "the refused run must send nothing to the Runtime socket: {created_b}"
    );

    stand_in.release_answer();
    let settled_a = wait_for_run_terminal(&mut provider, &run_a, &access_binding(&create_a));
    assert_eq!(
        settled_a["data"]["status"], "failed",
        "the held run must settle on the stand-in's refusal: {settled_a}"
    );
    assert_eq!(
        settled_a["data"]["terminal"]["error"]["code"], "hosted_effect_refused",
        "the held run must settle with the Runtime's reason: {settled_a}"
    );

    let created_c = provider.request(create_c.clone());
    assert_eq!(
        created_c["status"], "ok",
        "unexpected create response: {created_c}"
    );
    assert_eq!(
        created_c["data"]["run_id"], run_c,
        "runs_create must return the contract run id"
    );
    let settled_c = wait_for_run_terminal(&mut provider, &run_c, &access_binding(&create_c));
    assert_eq!(
        settled_c["data"]["terminal"]["error"]["code"], "hosted_effect_refused",
        "the ceiling counts open runs, so a run after the first settles must be \
         admitted and reach the Runtime socket: {settled_c}"
    );
    stand_in.wait_for_connections(2);
    assert_eq!(
        stand_in.connection_count(),
        2,
        "the admitted run must add exactly one connection to the Runtime socket"
    );

    let (connections, requests) = stand_in.observe();
    assert_eq!(
        connections, 2,
        "only the two admitted runs may open a connection to the Runtime socket"
    );
    assert_eq!(
        requests.len(),
        2,
        "only the two admitted runs may send a hosted request"
    );
    for recorded in &requests {
        assert_eq!(recorded.request_line, "POST /v1/hosted-effect HTTP/1.1");
        assert_eq!(
            recorded.value("authorization"),
            None,
            "a hosted run must carry no bearer key"
        );
    }

    provider.shutdown();
}

/// A hosted run whose Runtime binding names no grant is refused before the
/// provider opens the Runtime socket. The binding check is the first step of
/// `handle_runs_create` after `reject_untrusted_binding_fields`
/// (`src/state.rs:507-510`); it reads `grant_id` through
/// `validate_bounded_trimmed`
/// (`elastos/crates/elastos-model-contract/src/lib.rs:136`) and maps every
/// failure to `invalid_request` with `invalid runtime binding`. The control
/// run in the same test carries a grant and reaches the stand-in exactly once,
/// so the stand-in was listening and the refused run sent nothing.
///
/// Off macOS the provider refuses every hosted run before any socket, so the
/// test prints one `SKIP` line and returns.
#[test]
fn hosted_run_with_no_grant_is_refused_before_any_send() {
    if !cfg!(target_os = "macos") {
        eprintln!(
            "SKIP model-provider hosted run with no grant: off macOS the provider \
             refuses every hosted run before any socket"
        );
        return;
    }
    let root = test_support::temp_root_path("model-provider-process", "hosted-no-grant");
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let stand_in = HostedEffectStandIn::bind("hosted-no-grant");
    let init = hosted_effect_init(
        &root,
        &stand_in,
        HOSTED_FIXTURE_MODEL,
        HOSTED_FIXTURE_RUNTIME_MS_LIMIT,
    );
    let mut provider = ProviderProcess::start();
    let started = provider.request(init);
    assert_eq!(
        started["status"], "ok",
        "unexpected init response: {started}"
    );

    let input = json!({
        "schema": elastos_model_contract::TEXT_INPUT_V1_SCHEMA,
        "prompt": "a hosted run with no grant"
    });
    let input_hash = model_input_hash(&input).unwrap();
    let refused_request = json!({
        "op": "runs_create",
        "offer_id": HOSTED_EFFECT_OFFER,
        "operation": "text.generate",
        "input": input,
        "runtime_binding": {
            "schema": RUNTIME_CREATE_BINDING_SCHEMA,
            "principal_id": "person:local:test",
            "session_id": "session:test",
            "capsule_id": "assistant",
            "grant_id": "",
            "request_id": test_support::fixture_model_request_id("request:hosted-no-grant"),
            "offer_id": HOSTED_EFFECT_OFFER,
            "operation": "text.generate",
            "input_hash": input_hash
        }
    });
    let mut accepted_request = refused_request.clone();
    accepted_request["runtime_binding"]["grant_id"] = json!("grant:test");
    accepted_request["runtime_binding"]["request_id"] = json!(
        test_support::fixture_model_request_id("request:hosted-no-grant-control")
    );

    let refused = provider.request(refused_request);
    assert_eq!(
        refused,
        json!({
            "status": "error",
            "code": "invalid_request",
            "message": "invalid runtime binding",
        }),
        "a run with no grant must be refused with the provider's own error \
         response: {refused}"
    );
    assert_eq!(
        stand_in.connection_count(),
        0,
        "the refused run must open no connection to the Runtime socket: {refused}"
    );

    // The control run is the same request with a grant and a new request id.
    let binding: RuntimeCreateBinding =
        serde_json::from_value(accepted_request["runtime_binding"].clone()).unwrap();
    let accepted = provider.request(accepted_request);
    assert_eq!(
        accepted["status"], "ok",
        "unexpected create response: {accepted}"
    );
    assert_eq!(
        accepted["data"]["run_id"],
        model_run_id(&binding),
        "runs_create must return the contract run id"
    );

    let (connections, requests) = stand_in.observe();
    assert_eq!(
        connections, 1,
        "only the control run may open a connection to the Runtime socket"
    );
    assert_eq!(
        requests.len(),
        1,
        "only the control run may send a hosted request"
    );

    provider.shutdown();
}

/// The model id the Sparks engine serves and the agent-host opt-in tests pin
/// (`examples/agent-host/src/lib.rs:10153`, `:10161`).
const REAL_TURN_MODEL: &str = "deepseek-v4-flash";

/// The real turn's budget. A Sparks prefill and decode are slower than the
/// fixture backend, so the offer's run limit, the relay's backend timeout and
/// this test's settle deadline share one longer value.
const REAL_TURN_TIMEOUT: Duration = Duration::from_secs(180);

/// A settled run's status and its error code, for a failure message that names
/// what happened without printing the run's answer text (049 review). A
/// completed run carries no error, so its code prints as `null`.
fn run_status_and_error_code(run: &Value) -> String {
    format!(
        "status {}, error code {}",
        run["data"]["status"], run["data"]["terminal"]["error"]["code"]
    )
}

/// One granted hosted run through the relaying stand-in: the stand-in, the
/// settled run, the backend's own outcome, and the provider. The opt-in real
/// turn and the loopback relay test both call
/// `run_granted_hosted_turn_through_relay`, so the run steps have one copy
/// (P10) and each test keeps its own checks.
struct RelayedHostedTurn {
    stand_in: HostedEffectStandIn,
    settled: Value,
    backend: RelayOutcome,
    provider: ProviderProcess,
}

/// The `runs_create` body every hosted text turn sends. A missing `grant_id`
/// is refused before any send, so the grant id is non-empty. The stand-in
/// decides whether a live grant exists for `request_id`. The session is the
/// fixture session.
fn hosted_text_create_request(request_id: &str, grant_id: &str, prompt: &str) -> Value {
    hosted_text_create_request_for_session(request_id, grant_id, HOSTED_FIXTURE_SESSION_ID, prompt)
}

/// The same body with the caller's session in the runtime binding. The
/// fixture helper passes `HOSTED_FIXTURE_SESSION_ID`.
fn hosted_text_create_request_for_session(
    request_id: &str,
    grant_id: &str,
    session_id: &str,
    prompt: &str,
) -> Value {
    let input = json!({
        "schema": elastos_model_contract::TEXT_INPUT_V1_SCHEMA,
        "prompt": prompt
    });
    let input_hash = model_input_hash(&input).unwrap();
    json!({
        "op": "runs_create",
        "offer_id": HOSTED_EFFECT_OFFER,
        "operation": "text.generate",
        "input": input,
        "runtime_binding": {
            "schema": RUNTIME_CREATE_BINDING_SCHEMA,
            "principal_id": "person:local:test",
            "session_id": session_id,
            "capsule_id": "assistant",
            "grant_id": grant_id,
            "request_id": request_id,
            "offer_id": HOSTED_EFFECT_OFFER,
            "operation": "text.generate",
            "input_hash": input_hash
        }
    })
}

/// One hosted text run on an already started provider: `runs_create` with the
/// binding's grant, session and request id, then the settled run. The provider
/// only checks that `grant_id` is not empty; the stand-in decides whether a
/// live grant exists for `request_id`, so the caller owns the grant.
fn run_hosted_text_turn(
    provider: &mut ProviderProcess,
    request_id: &str,
    grant_id: &str,
    session_id: &str,
    prompt: &str,
    settle_deadline: Duration,
) -> Value {
    let create_request =
        hosted_text_create_request_for_session(request_id, grant_id, session_id, prompt);
    let binding: RuntimeCreateBinding =
        serde_json::from_value(create_request["runtime_binding"].clone()).unwrap();
    let expected_run_id = model_run_id(&binding);
    let create = provider.request(create_request.clone());
    assert_eq!(
        create["status"], "ok",
        "unexpected create response: {create}"
    );
    assert_eq!(
        create["data"]["run_id"], expected_run_id,
        "runs_create must return the contract run id"
    );
    wait_for_run_terminal_within(
        provider,
        &expected_run_id,
        &access_binding(&create_request),
        settle_deadline,
    )
}

/// Waits for the relaying stand-in to record what the backend answered, failing
/// after `FIXTURE_EVENT_TIMEOUT`. The backend's own status explains a failed
/// run before the run's error code does.
fn wait_for_relay_outcome(stand_in: &HostedEffectStandIn, settled: &Value) -> RelayOutcome {
    let deadline = Instant::now() + FIXTURE_EVENT_TIMEOUT;
    loop {
        if let Some(outcome) = stand_in.relay_outcome() {
            return outcome;
        }
        assert!(
            Instant::now() < deadline,
            "the relaying stand-in recorded no backend answer: {}",
            run_status_and_error_code(settled)
        );
        thread::sleep(Duration::from_millis(5));
    }
}

/// One granted hosted run through the relaying stand-in, from the fixture root
/// to the settled run. The offer pins `model` and `runtime_ms_limit`, the input
/// carries `prompt`, and the run settles within `settle_deadline`. The run
/// carries a grant: the Runtime owns it, and the stand-in only relays. 048's
/// `MP29` is the paired refusal of a run with no grant.
fn run_granted_hosted_turn_through_relay(
    label: &str,
    backend_url: &str,
    model: &str,
    runtime_ms_limit: u64,
    settle_deadline: Duration,
    prompt: &str,
) -> RelayedHostedTurn {
    let root = test_support::temp_root_path("model-provider-process", label);
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let stand_in = HostedEffectStandIn::bind_relaying(label, backend_url);
    let init = hosted_effect_init(&root, &stand_in, model, runtime_ms_limit);
    let mut provider = ProviderProcess::start();
    let started = provider.request(init);
    assert_eq!(
        started["status"], "ok",
        "unexpected init response: {started}"
    );

    let settled = run_hosted_text_turn(
        &mut provider,
        &test_support::fixture_model_request_id(&format!("request:{label}")),
        "grant:test",
        HOSTED_FIXTURE_SESSION_ID,
        prompt,
        settle_deadline,
    );
    let backend = wait_for_relay_outcome(&stand_in, &settled);

    RelayedHostedTurn {
        stand_in,
        settled,
        backend,
        provider,
    }
}

/// The header names the relay's own client sends to the backend, in lower case
/// and sorted: the client's defaults (`accept`, `content-length`, `host`) and
/// the relay's one header of its own (`content-type`). The first passing run
/// shows this exact set, so any other name is a header the relay added.
const RELAY_BACKEND_HEADER_NAMES: [&str; 4] = ["accept", "content-length", "content-type", "host"];

/// The relay forwards the provider's hosted body to the backend byte for byte
/// and adds no key. The stand-in plays the Runtime, and the backend is a
/// loopback listener inside this test, so the run completes from the backend's
/// own three event frames with no model, no key and no network beyond loopback.
/// This test runs on every gate: a relay that changes the body fails the
/// byte-equality check (`MP30`), and a relay that adds an `authorization`
/// header fails the no-key check (`MP31`). It books no M1 check, because the
/// stand-in is not the Runtime and a loopback backend is not the A4 path.
///
/// Off macOS the provider refuses every hosted run before any socket, so the
/// test prints one `SKIP` line and returns.
#[test]
fn hosted_relay_forwards_the_provider_body_unchanged_and_no_key() {
    if !cfg!(target_os = "macos") {
        eprintln!(
            "SKIP model-provider hosted relay: off macOS the provider \
             refuses every hosted run before any socket"
        );
        return;
    }
    let backend = LocalRelayBackend::bind();
    let turn = run_granted_hosted_turn_through_relay(
        "hosted-relay",
        backend.url(),
        HOSTED_FIXTURE_MODEL,
        HOSTED_FIXTURE_RUNTIME_MS_LIMIT,
        FIXTURE_EVENT_TIMEOUT,
        "a relayed hosted turn",
    );
    let RelayedHostedTurn {
        stand_in,
        settled,
        backend: relay,
        mut provider,
    } = turn;
    match &relay {
        RelayOutcome::Answered { status: 200, .. } => {}
        RelayOutcome::Answered {
            status,
            first_bytes,
        } => panic!(
            "the local backend answered {status}, not 200: {}",
            String::from_utf8_lossy(first_bytes)
        ),
        RelayOutcome::Unreachable { reason } => {
            panic!("the local backend is unreachable: {reason}")
        }
    }

    assert_eq!(
        settled["data"]["status"],
        "completed",
        "the relayed turn must complete the run: {}",
        run_status_and_error_code(&settled)
    );
    assert_eq!(
        settled["data"]["terminal"]["output"],
        json!({"schema": RUN_OUTPUT_TEXT_SCHEMA, "text": "ready"}),
        "the relayed run must carry the streamed text: {}",
        run_status_and_error_code(&settled)
    );
    assert_eq!(
        settled["data"]["terminal"]["backend_report"],
        json!({
            "schema": BACKEND_REPORT_SCHEMA,
            "resolved_model": {"status": "reported", "value": "resolved-model"},
            "usage": {
                "status": "reported",
                "value": {"input_tokens": 7, "output_tokens": 1, "total_tokens": 8},
            },
            // The usage event carries no `cost` or `cost_unit`, so the worker
            // observes cost only when one is present and the report says
            // unknown (`src/adapters.rs:416-418`, `:437-443`).
            "cost": {"status": "unknown"},
        }),
        "the relayed run must carry the backend's evidence: {}",
        run_status_and_error_code(&settled)
    );

    let (connections, requests) = stand_in.observe();
    assert_eq!(
        connections, 1,
        "the relayed run must open exactly one connection to the Runtime socket"
    );
    assert_eq!(
        requests.len(),
        1,
        "the relayed run must send exactly one request"
    );
    let forwarded = &requests[0];
    assert_eq!(forwarded.request_line, "POST /v1/hosted-effect HTTP/1.1");

    let backend_requests = backend.observe();
    assert_eq!(
        backend_requests.len(),
        1,
        "the relay must reach the backend exactly once"
    );
    let backend_request = &backend_requests[0];
    assert_eq!(
        backend_request.request_line,
        "POST /v1/chat/completions HTTP/1.1"
    );
    assert_eq!(
        backend_request.body, forwarded.body,
        "the relay must forward the provider's body byte for byte"
    );
    // The no-key check runs before the header-name set, so an added
    // `authorization` header fails here and not on the set comparison (MP31).
    assert_eq!(
        backend_request.value("authorization"),
        None,
        "the relay must add no authorization header"
    );
    // An added header other than `authorization` passes the no-key check
    // above and fails here on the set comparison (MP34).
    let mut names: Vec<String> = backend_request
        .headers
        .iter()
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect();
    names.sort();
    assert_eq!(
        names, RELAY_BACKEND_HEADER_NAMES,
        "the relay sends only its own content-type and the client's defaults: {:?}",
        backend_request.headers
    );

    provider.shutdown();
}

/// Every `runs_events` page of one run from sequence 0, joined in order.
/// A page that says `has_more` advances the cursor by the last event it
/// returned, so the read cannot spin on one page. Sequences must start at 1
/// and rise by one, and exactly one event (the last) must be the terminal.
///
/// This is the one page-until-done walk. The local-llama poll in
/// `managed_streaming_stop_switch` reads one page until a `text_delta`
/// appears, and that poll stays its own rule. Each complete page is checked
/// for the private stream markers before its events are taken out, so the
/// page envelope is part of the exclusion.
fn read_hosted_run_events(
    provider: &mut ProviderProcess,
    run_id: &str,
    access: &Value,
) -> Vec<Value> {
    let mut events: Vec<Value> = Vec::new();
    let mut after_sequence: u64 = 0;
    loop {
        let page = provider.request(json!({
            "op": "runs_events",
            "run_id": run_id,
            "runtime_binding": access,
            "after_sequence": after_sequence
        }));
        assert_eq!(page["status"], "ok", "unexpected events response: {page}");
        let page_text = page.to_string();
        for marker in HOSTED_STREAM_PRIVATE_MARKERS {
            assert!(
                !page_text.contains(marker),
                "an events page must not carry the private marker {marker}: {page}"
            );
        }
        let page_events = page["data"]["events"]
            .as_array()
            .expect("runs_events returns an event array")
            .clone();
        let has_more = page["data"]["has_more"] == true;
        if has_more {
            let next = page_events
                .last()
                .expect("a page with more events carries at least one event")["sequence"]
                .as_u64()
                .expect("an event has a sequence");
            assert!(
                next > after_sequence,
                "a later events page must move past sequence {after_sequence}: {page}"
            );
            after_sequence = next;
        }
        events.extend(page_events);
        if !has_more {
            break;
        }
    }
    assert!(
        !events.is_empty(),
        "the run must keep its events: {events:?}"
    );
    for (position, event) in events.iter().enumerate() {
        assert_eq!(
            event["sequence"].as_u64(),
            Some(position as u64 + 1),
            "event sequences must start at 1 and rise by exactly one: {events:?}"
        );
    }
    let last = events.len() - 1;
    assert_eq!(
        events[last]["terminal"], true,
        "the last event must be the terminal: {events:?}"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event["terminal"] == true)
            .count(),
        1,
        "the run must keep exactly one terminal event: {events:?}"
    );
    events
}

/// A hosted stream that carries private reasoning and a proposed tool call
/// beside its answer text reaches the caller with only the answer text. The
/// provider's extractor reads `/choices/0/delta/content` and ignores every
/// other field (`capsules/model-provider/src/adapters.rs`,
/// `extract_stream_text_delta`), so:
/// - the private reasoning chunk (`content: null`, `reasoning_content`
///   string), the tool-call chunk (id `call-fixture`, `name: "runs_create"`,
///   arguments carrying `grant:from-model`) and the finish chunk
///   (`finish_reason: "stop"`) never reach the answer;
/// - the answer is `ready set` — the concatenation of the two content
///   deltas — and nothing else;
/// - the created run reports the resolved model, usage and cost the existing
///   answer fixture resolves, and the last event is terminal, kind `output`,
///   with that answer in `data`;
/// - every create/get response and events page is clean of `fixture-private-
///   reasoning`, `call-fixture`, `runs_create`, `grant:from-model` and
///   `tool_calls`;
/// - `observe` still reads exactly one hosted-effect connection and one
///   request with no `authorization` header, so the proposed operation
///   caused no second send.
///
/// Off macOS the provider refuses every hosted run before any socket, so the
/// test prints one `SKIP` line and returns.
#[test]
fn a_hosted_tool_call_or_reasoning_never_reaches_the_caller() {
    if !cfg!(target_os = "macos") {
        eprintln!(
            "SKIP model-provider hosted reasoning and tool call: off macOS the \
             provider refuses every hosted run before any socket"
        );
        return;
    }
    let root = test_support::temp_root_path("model-provider-process", "hosted-reasoning-tool-call");
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let stand_in = HostedEffectStandIn::bind_streaming_frames(
        "hosted-reasoning-tool-call",
        runtime_hosted_tool_and_reasoning_frames(),
    );
    let init = hosted_effect_init(
        &root,
        &stand_in,
        HOSTED_FIXTURE_MODEL,
        HOSTED_FIXTURE_RUNTIME_MS_LIMIT,
    );
    let mut provider = ProviderProcess::start();
    let init_response = provider.request(init);
    assert_eq!(
        init_response["status"], "ok",
        "unexpected init response: {init_response}"
    );

    // The whole request prompt is fixed on the test side. None of the private
    // markers may appear in it.
    let prompt = "a hosted answer whose stream carries private reasoning and a tool call";
    for marker in HOSTED_STREAM_PRIVATE_MARKERS {
        assert!(
            !prompt.contains(marker),
            "the request prompt must not carry the private marker {marker}"
        );
    }
    let create_request = hosted_text_create_request(
        &test_support::fixture_model_request_id("request:hosted-reasoning-tool-call"),
        "grant:test",
        prompt,
    );
    let binding: RuntimeCreateBinding =
        serde_json::from_value(create_request["runtime_binding"].clone()).unwrap();
    let expected_run_id = model_run_id(&binding);
    let create = provider.request(create_request.clone());
    assert_eq!(
        create["status"], "ok",
        "unexpected create response: {create}"
    );
    assert_eq!(
        create["data"]["run_id"], expected_run_id,
        "runs_create must return the contract run id"
    );

    let settled = wait_for_run_terminal_within(
        &mut provider,
        &expected_run_id,
        &access_binding(&create_request),
        FIXTURE_EVENT_TIMEOUT,
    );
    assert_eq!(
        settled["data"]["run_id"], expected_run_id,
        "runs_get must return the contract run id"
    );
    assert_eq!(
        settled["data"]["status"], "completed",
        "the reasoning and tool-call stream must complete: {settled}"
    );
    assert_eq!(
        settled["data"]["terminal"]["output"],
        json!({
            "schema": RUN_OUTPUT_TEXT_SCHEMA,
            "text": "ready set",
        }),
        "the caller must see only the answer text: {settled}"
    );
    assert_eq!(
        settled["data"]["terminal"]["backend_report"],
        json!({
            "schema": BACKEND_REPORT_SCHEMA,
            "resolved_model": {"status": "reported", "value": "resolved-model"},
            "usage": {"status": "reported", "value": {
                "input_tokens": 7,
                "output_tokens": 1,
                "total_tokens": 8,
            }},
            "cost": {"status": "unknown"},
        }),
        "the backend report must match the answer fixture: {settled}"
    );

    let events = read_hosted_run_events(
        &mut provider,
        &expected_run_id,
        &access_binding(&create_request),
    );
    let mut joined = String::new();
    for event in &events {
        if event["kind"] == "text_delta" {
            joined.push_str(event["data"]["text"].as_str().unwrap_or(""));
        }
    }
    assert_eq!(
        joined, "ready set",
        "joined text deltas must be exactly the answer: {events:?}"
    );
    let terminal = events.last().unwrap();
    assert_eq!(
        terminal["terminal"], true,
        "the last event must be the terminal: {terminal}"
    );
    assert_eq!(
        terminal["kind"], "output",
        "the last event must be the completed output: {terminal}"
    );
    assert_eq!(
        terminal["data"],
        json!({
            "schema": RUN_OUTPUT_TEXT_SCHEMA,
            "text": "ready set",
        }),
        "the terminal output must be only the answer text: {terminal}"
    );

    // Create and get are checked here. Each events page is checked inside
    // `read_hosted_run_events` before its events are taken out.
    for marker in HOSTED_STREAM_PRIVATE_MARKERS {
        assert!(
            !create.to_string().contains(marker),
            "the create response must not carry the private marker {marker}: {create}"
        );
        assert!(
            !settled.to_string().contains(marker),
            "the get response must not carry the private marker {marker}: {settled}"
        );
    }

    let (connections, requests) = stand_in.observe();
    assert_eq!(
        connections, 1,
        "the hosted run must open exactly one connection, not one per proposed effect"
    );
    assert_eq!(
        requests.len(),
        1,
        "the hosted run must send exactly one request, never one per proposed effect"
    );
    assert_eq!(
        requests[0].value("authorization"),
        None,
        "a hosted run must carry no bearer key"
    );

    provider.shutdown();
}

/// A hosted model turn is reached only through a live grant in the shared
/// stand-in's RA-1 shell view. `HostedEffectStandIn::ra1_view` reads that view
/// through the shared stand-in's own `get_capability_list` call
/// (`lab/agent-conformance/standin-runtime/mod.rs:128-139`), and a granting
/// stand-in answers only an effect whose request id matches a live entry, so no
/// route runs over a socket here (`MP35`). Run A carries a non-empty
/// `grant_id` but has no seeded grant, so the stand-in refuses it with the
/// Runtime's `403` and `X-Elastos-Hosted-Access: refused` before any backend
/// call, and the run settles `failed` with `hosted_effect_refused` and class
/// `access_refused`. One `Live` grant for run B's request id is then listed
/// with every entry field, and run B completes with `ready` and reported
/// usage. The loopback backend counts exactly one request, so only B reached
/// the model (`MP36`). The shared stand-in has no seam that spends a grant
/// (`lab/agent-conformance/standin-runtime/README.md`), so this lane models no
/// spending and the entry stays listed.
///
/// This is stand-in lab evidence for M1's A4 only: the stand-ins are not the
/// Runtime, the loopback backend is not a hosted connection, and it books no
/// M1 check and no grade point. The Runtime's own grant, its budget
/// reservation and an approved hosted connection stay with Anders.
///
/// Off macOS the provider refuses every hosted run before any socket, so the
/// test prints one `SKIP` line and returns.
#[test]
fn a_model_turn_is_reached_only_through_an_ra1_grant() {
    if !cfg!(target_os = "macos") {
        eprintln!(
            "SKIP model-provider RA-1 granted turn: off macOS the provider \
             refuses every hosted run before any socket"
        );
        return;
    }
    let grants = Arc::new(Mutex::new(StandIn::new()));
    // The shared stand-in's shell view keeps only live grants
    // (`lab/agent-conformance/standin-runtime/mod.rs:128-139`), so it starts
    // empty. `ra1_view` reads this same call.
    assert_eq!(
        shell_live_grant_view(&grants),
        json!({"scope": SHELL_LIVE_GRANT_SCOPE, "capabilities": []}),
        "the shared stand-in shell view must list no grant before one is seeded"
    );

    // Run A names a grant id, but no grant was seeded for its request id, so
    // the effect has no live entry to be reached through.
    let prompt_a = "a turn with no live grant";
    let request_a = granted_model_turn_request_id(HOSTED_FIXTURE_SESSION_ID, prompt_a);
    let denied = granted_model_turn(Arc::clone(&grants), HOSTED_FIXTURE_SESSION_ID, prompt_a);
    let settled_a = denied.settled;
    assert_eq!(
        settled_a["data"]["status"],
        "failed",
        "a turn with no live grant must fail: {}",
        run_status_and_error_code(&settled_a)
    );
    assert_eq!(
        settled_a["data"]["terminal"]["error"]["code"],
        "hosted_effect_refused",
        "the refusal must carry the Runtime's error code: {}",
        run_status_and_error_code(&settled_a)
    );
    assert_eq!(
        settled_a["data"]["terminal"]["error"]["class"],
        "access_refused",
        "the refusal must carry the access class: {}",
        run_status_and_error_code(&settled_a)
    );
    assert_eq!(
        denied.refusal_reasons,
        vec![format!("no live grant for request {request_a}")],
        "the stand-in must record why it refused run A"
    );

    // The shell seeds one `Live` grant for run B's request id. The shared
    // stand-in's `seed_grant` is its lab seam
    // (`lab/agent-conformance/standin-runtime/mod.rs:104-124`); the values are
    // this test's fixture, and the shared stand-in decides liveness.
    let prompt_b = "a turn reached only through a live grant";
    let request_b = granted_model_turn_request_id(HOSTED_FIXTURE_SESSION_ID, prompt_b);
    let resource = "model:fixture/text";
    let action = "text.generate";
    let duration = "once";
    let granted_at: u64 = 1_790_000_000;
    grants.lock().unwrap().seed_grant(
        &request_b,
        HOSTED_FIXTURE_SESSION_ID,
        resource,
        action,
        duration,
        granted_at,
        Life::Live,
        false,
    );
    let expected_entry = json!({
        "request_id": request_b,
        "session_id": HOSTED_FIXTURE_SESSION_ID,
        "resource": resource,
        "action": action,
        "duration": duration,
        "granted_at": granted_at,
    });
    assert_eq!(
        shell_live_grant_view(&grants),
        json!({
            "scope": SHELL_LIVE_GRANT_SCOPE,
            "capabilities": [expected_entry.clone()],
        }),
        "the shared stand-in shell view must list the one live grant with every field"
    );

    // Run B carries a new request id, and the one live grant reaches the model
    // through `granted_model_turn`.
    let granted = granted_model_turn(Arc::clone(&grants), HOSTED_FIXTURE_SESSION_ID, prompt_b);
    let settled_b = granted.settled;
    assert_eq!(
        settled_b["data"]["status"],
        "completed",
        "the granted turn must complete the run: {}",
        run_status_and_error_code(&settled_b)
    );
    assert_eq!(
        settled_b["data"]["terminal"]["output"],
        json!({"schema": RUN_OUTPUT_TEXT_SCHEMA, "text": "ready"}),
        "the granted run must carry the streamed text: {}",
        run_status_and_error_code(&settled_b)
    );
    assert_eq!(
        settled_b["data"]["terminal"]["backend_report"]["usage"],
        json!({
            "status": "reported",
            "value": {"input_tokens": 7, "output_tokens": 1, "total_tokens": 8},
        }),
        "the granted run must report the backend's usage: {}",
        run_status_and_error_code(&settled_b)
    );
    match granted
        .relay
        .clone()
        .expect("the granted turn records the backend answer")
    {
        RelayOutcome::Answered { status: 200, .. } => {}
        RelayOutcome::Answered {
            status,
            first_bytes,
        } => panic!(
            "the local backend answered {status}, not 200: {}",
            String::from_utf8_lossy(&first_bytes)
        ),
        RelayOutcome::Unreachable { reason } => {
            panic!("the local backend is unreachable: {reason}")
        }
    }

    // The shared stand-in has no seam that spends a grant and this lane adds
    // none, so the entry stays listed after run B.
    assert_eq!(
        shell_live_grant_view(&grants),
        json!({
            "scope": SHELL_LIVE_GRANT_SCOPE,
            "capabilities": [expected_entry],
        }),
        "the shared stand-in shell view must keep the live grant because this lane models no spending"
    );

    // Only run B reached the model: the backend counted exactly one request.
    assert!(
        denied.backend_requests.is_empty(),
        "only the granted run may reach the model; run A must send it nothing"
    );
    let backend_requests = granted.backend_requests;
    assert_eq!(
        backend_requests.len(),
        1,
        "only the granted run may reach the model; run A must send it nothing"
    );
    assert_eq!(
        backend_requests[0].request_line,
        "POST /v1/chat/completions HTTP/1.1"
    );

    // Both runs reach the stand-in, and each request carries its own binding's
    // request id.
    let connections = denied.connections + granted.connections;
    let requests_a = denied.hosted_requests;
    let requests_b = granted.hosted_requests;
    assert_eq!(
        connections, 2,
        "each run must open one connection to the Runtime socket stand-in"
    );
    assert_eq!(
        requests_a.len() + requests_b.len(),
        2,
        "each run must send one hosted request"
    );
    assert_eq!(
        requests_a[0].value("x-elastos-request-id"),
        Some(request_a.as_str())
    );
    assert_eq!(
        requests_b[0].value("x-elastos-request-id"),
        Some(request_b.as_str())
    );
}

/// A hosted model turn is reached only through a live grant for the session the
/// run's runtime binding names. 058's test shows the refusal with no grant and
/// the control whose live entry matches; this one seeds one `Live` entry for run
/// C's request id under `session:other`, so the shared stand-in's `authorise`
/// refuses C with its one reason that names both sessions
/// (`wrong capsule: expected session:other, got session:test`) and the granting
/// stand-in reaches no backend (`MP38`), then
/// seeds run D's entry under the binding's `session:test`, so D completes with
/// `ready`. The loopback backend counts exactly one request at the model
/// endpoint, so only D reached the model. The effect carries no session id
/// (`src/adapters.rs:61-66`), so the stand-in applies the session of the hosted
/// run it serves; that is the stand-in's rule, not a claim about how the Runtime
/// finds an effect's session.
///
/// This is stand-in lab evidence for M1's A4 only: the stand-ins are not the
/// Runtime, the loopback backend is not a hosted connection, and it books no M1
/// check and no grade point. The Runtime's own grant check stays with Anders.
///
/// Off macOS the provider refuses every hosted run before any socket, so the
/// test prints one `SKIP` line and returns.
#[test]
fn an_ra1_grant_for_another_session_does_not_reach_the_model() {
    if !cfg!(target_os = "macos") {
        eprintln!(
            "SKIP model-provider RA-1 grant for another session: off macOS the \
             provider refuses every hosted run before any socket"
        );
        return;
    }
    let grants = Arc::new(Mutex::new(StandIn::new()));

    // The shell seeds one `Live` grant for run C's request id, and it belongs
    // to another session than the one the stand-in serves. The values are this
    // test's fixture, and the shared stand-in decides liveness.
    let prompt_c = "a turn whose grant belongs to another session";
    let request_c = granted_model_turn_request_id(HOSTED_FIXTURE_SESSION_ID, prompt_c);
    let other_session = "session:other";
    let resource = "model:fixture/text";
    let action = "text.generate";
    let duration = "once";
    let granted_at: u64 = 1_790_000_000;
    grants.lock().unwrap().seed_grant(
        &request_c,
        other_session,
        resource,
        action,
        duration,
        granted_at,
        Life::Live,
        false,
    );
    let expected_c = json!({
        "request_id": request_c,
        "session_id": other_session,
        "resource": resource,
        "action": action,
        "duration": duration,
        "granted_at": granted_at,
    });
    assert_eq!(
        shell_live_grant_view(&grants),
        json!({
            "scope": SHELL_LIVE_GRANT_SCOPE,
            "capabilities": [expected_c],
        }),
        "the shared stand-in shell view must list the one live grant for another session with every field"
    );

    // Run C carries a non-empty `grant_id` and its own request id, so the live
    // entry exists but is for another session: the stand-in refuses C before
    // any backend call. The turn goes through `granted_model_turn`.
    let refused = granted_model_turn(Arc::clone(&grants), HOSTED_FIXTURE_SESSION_ID, prompt_c);
    let settled_c = refused.settled;
    assert_eq!(
        settled_c["data"]["status"],
        "failed",
        "a turn whose grant is for another session must fail: {}",
        run_status_and_error_code(&settled_c)
    );
    assert_eq!(
        settled_c["data"]["terminal"]["error"]["code"],
        "hosted_effect_refused",
        "the refusal must carry the Runtime's error code: {}",
        run_status_and_error_code(&settled_c)
    );
    assert_eq!(
        settled_c["data"]["terminal"]["error"]["class"],
        "access_refused",
        "the refusal must carry the access class: {}",
        run_status_and_error_code(&settled_c)
    );
    assert_eq!(
        refused.refusal_reasons,
        vec![format!(
            "wrong capsule: expected {other_session}, got {HOSTED_FIXTURE_SESSION_ID}"
        )],
        "the stand-in must record the shared stand-in's one reason that names both sessions"
    );

    // Run D's live entry is for the session the stand-in serves, so D reaches
    // the model. Its request id is not run C's, so C's grant does not hide it.
    let prompt_d = "a turn whose grant belongs to the served session";
    let request_d = granted_model_turn_request_id(HOSTED_FIXTURE_SESSION_ID, prompt_d);
    grants.lock().unwrap().seed_grant(
        &request_d,
        HOSTED_FIXTURE_SESSION_ID,
        resource,
        action,
        duration,
        granted_at,
        Life::Live,
        false,
    );
    let served = granted_model_turn(Arc::clone(&grants), HOSTED_FIXTURE_SESSION_ID, prompt_d);
    let settled_d = served.settled;
    assert_eq!(
        settled_d["data"]["status"],
        "completed",
        "the grant for the served session must complete the run: {}",
        run_status_and_error_code(&settled_d)
    );
    assert_eq!(
        settled_d["data"]["terminal"]["output"],
        json!({"schema": RUN_OUTPUT_TEXT_SCHEMA, "text": "ready"}),
        "the served-session run must carry the streamed text: {}",
        run_status_and_error_code(&settled_d)
    );
    match served
        .relay
        .clone()
        .expect("the served-session turn records the backend answer")
    {
        RelayOutcome::Answered { status: 200, .. } => {}
        RelayOutcome::Answered {
            status,
            first_bytes,
        } => panic!(
            "the local backend answered {status}, not 200: {}",
            String::from_utf8_lossy(&first_bytes)
        ),
        RelayOutcome::Unreachable { reason } => {
            panic!("the local backend is unreachable: {reason}")
        }
    }

    // Only run D reached the model: the backend counted exactly one request,
    // and it is the model endpoint the relay posts to.
    assert!(
        refused.backend_requests.is_empty(),
        "only the served-session run may reach the model; the other-session run must send it nothing"
    );
    let backend_requests = served.backend_requests;
    assert_eq!(
        backend_requests.len(),
        1,
        "only the served-session run may reach the model; the other-session run must send it nothing"
    );
    assert_eq!(
        backend_requests[0].request_line, "POST /v1/chat/completions HTTP/1.1",
        "the one request must be run D's model turn"
    );
}

/// The provider journal schema (`RUN_JOURNAL_SCHEMA` in `src/journal.rs`).
const PROVIDER_RUN_JOURNAL_SCHEMA: &str = "elastos.model.provider-run-journal/v1";

const GRANTED_MODEL_TURN_GRANT_ID: &str = "grant:granted-model-turn";

static GRANTED_MODEL_TURN_LABEL: AtomicUsize = AtomicUsize::new(0);

/// The request id `granted_model_turn` sends for this session and prompt.
/// A caller seeds a grant for this id before the call.
fn granted_model_turn_request_id(session_id: &str, prompt: &str) -> String {
    test_support::fixture_model_request_id(&format!(
        "request:granted-model-turn:{session_id}:{prompt}"
    ))
}

fn granted_model_turn_binding(session_id: &str, prompt: &str) -> RuntimeCreateBinding {
    let request = hosted_text_create_request_for_session(
        &granted_model_turn_request_id(session_id, prompt),
        GRANTED_MODEL_TURN_GRANT_ID,
        session_id,
        prompt,
    );
    serde_json::from_value(request["runtime_binding"].clone()).unwrap()
}

fn seed_live_model_grant(grants: &Arc<Mutex<StandIn>>, request_id: &str, session_id: &str) {
    grants.lock().unwrap().seed_grant(
        request_id,
        session_id,
        "model:fixture/text",
        "text.generate",
        "once",
        1_790_000_000,
        Life::Live,
        false,
    );
}

/// The one run file under `<fixture-root>/journal/runs`. `hosted_effect_init`
/// sets the journal root to `<fixture-root>/journal`, and the provider opens
/// `runs` under that root (`src/journal.rs`). This reads the file the provider
/// wrote. It does not hash the run id again.
fn read_provider_run_journal(root: &Path) -> Value {
    let runs = root.join("journal").join("runs");
    let entries = std::fs::read_dir(&runs)
        .unwrap_or_else(|error| panic!("the provider journal is at {}: {error}", runs.display()));
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry.expect("a provider journal entry").path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        let Some(rest) = name.strip_prefix("sha256-") else {
            continue;
        };
        let Some(hex) = rest.strip_suffix(".json") else {
            continue;
        };
        if !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            paths.push(path);
        }
    }
    assert_eq!(
        paths.len(),
        1,
        "the provider writes one run journal under {}",
        runs.display()
    );
    let bytes = std::fs::read(&paths[0]).expect("read the provider run journal");
    serde_json::from_slice(&bytes).expect("the provider run journal is JSON")
}

/// One granted model turn: the recorded answer, the contract run id, and the
/// provider journal when the turn completed. A refusal carries the stand-in's
/// reason and no loopback request.
struct GrantedModelTurn {
    answer: Option<String>,
    effect_id: String,
    journal: Option<Value>,
    binding: RuntimeCreateBinding,
    hosted_run_id: Option<String>,
    backend_requests: Vec<RecordedRequest>,
    refusal_reasons: Vec<String>,
    settled: Value,
    relay: Option<RelayOutcome>,
    connections: usize,
    hosted_requests: Vec<RecordedRequest>,
}

/// One lab call on the Request flow in `docs/AGENT_ARCHITECTURE.md`
/// ("Request flow"): the model request, then the same audit path as a human
/// action. The turn reaches a recorded answer only through the `Granted` arm
/// of `serve_hosted_effect`, which asks the shared stand-in before it relays.
/// A granted session returns the recorded answer `ready`, the contract run id,
/// and the provider journal `elastos.model.provider-run-journal/v1` read from
/// `<fixture-root>/journal/runs`. A missing grant returns `no live grant for
/// request <id>`. Agent A's grant on agent B's session returns `wrong capsule:
/// expected <grant session>, got <served session>`. Each refusal leaves this
/// call's loopback backend with no request. useful-task calls this read only.
/// This task adds no caller under `lab/useful-task/`.
///
/// `session_id` is the session `bind_granting` serves and the session the
/// request binding carries.
fn granted_model_turn(
    grants: Arc<Mutex<StandIn>>,
    session_id: &str,
    prompt: &str,
) -> GrantedModelTurn {
    let request_id = granted_model_turn_request_id(session_id, prompt);
    let binding = granted_model_turn_binding(session_id, prompt);
    let label = format!(
        "gmt-{}",
        GRANTED_MODEL_TURN_LABEL.fetch_add(1, Ordering::Relaxed)
    );
    let root = test_support::temp_root_path("model-provider-process", &label);
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let backend = LocalRelayBackend::bind();
    let stand_in =
        HostedEffectStandIn::bind_granting(&label, backend.url(), Arc::clone(&grants), session_id);
    let init = hosted_effect_init(
        &root,
        &stand_in,
        HOSTED_FIXTURE_MODEL,
        HOSTED_FIXTURE_RUNTIME_MS_LIMIT,
    );
    let mut provider = ProviderProcess::start();
    let started = provider.request(init);
    assert_eq!(
        started["status"], "ok",
        "unexpected init response: {started}"
    );
    let settled = run_hosted_text_turn(
        &mut provider,
        &request_id,
        GRANTED_MODEL_TURN_GRANT_ID,
        session_id,
        prompt,
        FIXTURE_EVENT_TIMEOUT,
    );
    let completed = settled["data"]["status"] == "completed";
    let relay = if completed {
        Some(wait_for_relay_outcome(&stand_in, &settled))
    } else {
        None
    };
    let refusal_reasons = stand_in.refusal_reasons();
    assert_eq!(
        stand_in.ra1_view(),
        shell_live_grant_view(&grants),
        "the granting stand-in reads the shared stand-in's shell view"
    );
    let (connections, hosted_requests) = stand_in.observe();
    let backend_requests = if completed {
        backend.observe()
    } else {
        backend.take_requests()
    };
    let answer = settled["data"]["terminal"]["output"]["text"]
        .as_str()
        .map(str::to_string);
    let effect_id = settled["data"]["run_id"]
        .as_str()
        .expect("runs_create returns the run id")
        .to_string();
    let hosted_run_id = hosted_requests
        .first()
        .and_then(|request| request.value("x-elastos-run-id"))
        .map(str::to_string);
    provider.shutdown();
    let journal = completed.then(|| read_provider_run_journal(&root));
    GrantedModelTurn {
        answer,
        effect_id,
        journal,
        binding,
        hosted_run_id,
        backend_requests,
        refusal_reasons,
        settled,
        relay,
        connections,
        hosted_requests,
    }
}

fn assert_granted_model_turn(turn: &GrantedModelTurn, session_id: &str) {
    assert_eq!(
        turn.answer.as_deref(),
        Some("ready"),
        "a granted session returns the recorded answer"
    );
    assert_eq!(
        turn.effect_id,
        model_run_id(&turn.binding),
        "the effect id is the contract run id"
    );
    assert_eq!(
        turn.hosted_requests.len(),
        1,
        "the granted call records one hosted request"
    );
    assert_eq!(
        turn.hosted_run_id.as_deref(),
        Some(turn.effect_id.as_str()),
        "the effect id is the x-elastos-run-id on the one recorded hosted request"
    );
    assert_eq!(
        turn.backend_requests.len(),
        1,
        "the loopback backend records one request for the granted call"
    );
    let journal = turn
        .journal
        .as_ref()
        .expect("a granted session returns the provider journal");
    assert_eq!(
        journal["schema"], PROVIDER_RUN_JOURNAL_SCHEMA,
        "the journal schema is elastos.model.provider-run-journal/v1"
    );
    assert_eq!(
        journal["run_id"], turn.effect_id,
        "the journal run id is the effect id"
    );
    assert_eq!(
        journal["runtime_binding"]["session_id"], session_id,
        "the journal records the supplied session"
    );
    assert_eq!(
        journal["output"]["text"], "ready",
        "the journal output text is the recorded answer"
    );
    assert_eq!(
        turn.binding.session_id, session_id,
        "the request binding carries the supplied session"
    );
}

/// A granted turn returns the recorded answer, the contract run id and the
/// provider journal. The same call returns the existing refusal reason, and
/// no loopback request, when the grant is missing or belongs to another
/// session. A granted session other than `session:test` is carried in
/// `bind_granting` and in the request binding. useful-task calls
/// `granted_model_turn` read only.
///
/// This is Runtime-socket lab evidence. It books no M1 check.
///
/// Off macOS the provider refuses every hosted run before any socket, so the
/// test prints one `SKIP` line and returns.
#[test]
fn granted_model_turn_returns_the_answer_effect_and_audit() {
    if !cfg!(target_os = "macos") {
        eprintln!(
            "SKIP model-provider granted model turn: off macOS the provider \
             refuses every hosted run before any socket"
        );
        return;
    }
    let session_id = HOSTED_FIXTURE_SESSION_ID;
    let prompt = "a granted turn returns the answer, the effect id and the journal";
    let grants = Arc::new(Mutex::new(StandIn::new()));
    seed_live_model_grant(
        &grants,
        &granted_model_turn_request_id(session_id, prompt),
        session_id,
    );
    let granted = granted_model_turn(Arc::clone(&grants), session_id, prompt);
    assert_granted_model_turn(&granted, session_id);

    let missing_prompt = "a turn with no live grant";
    let missing = granted_model_turn(
        Arc::new(Mutex::new(StandIn::new())),
        HOSTED_FIXTURE_SESSION_ID,
        missing_prompt,
    );
    let missing_id = granted_model_turn_request_id(HOSTED_FIXTURE_SESSION_ID, missing_prompt);
    assert_eq!(
        missing.refusal_reasons,
        vec![format!("no live grant for request {missing_id}")],
        "a missing grant returns the stand-in's named reason"
    );
    assert!(
        missing.backend_requests.is_empty(),
        "a missing grant leaves the loopback backend with no request"
    );

    let other_prompt = "a grant for another session";
    let other_session = "session:other";
    let other_grants = Arc::new(Mutex::new(StandIn::new()));
    seed_live_model_grant(
        &other_grants,
        &granted_model_turn_request_id(HOSTED_FIXTURE_SESSION_ID, other_prompt),
        other_session,
    );
    let other = granted_model_turn(
        Arc::clone(&other_grants),
        HOSTED_FIXTURE_SESSION_ID,
        other_prompt,
    );
    assert_eq!(
        other.refusal_reasons,
        vec![format!(
            "wrong capsule: expected {other_session}, got {HOSTED_FIXTURE_SESSION_ID}"
        )],
        "another session's grant returns the stand-in's named reason"
    );
    assert!(
        other.backend_requests.is_empty(),
        "another session's grant leaves the loopback backend with no request"
    );

    let supplied = "session:lab-granted";
    let supplied_prompt = "a granted turn for a non-default session";
    let supplied_grants = Arc::new(Mutex::new(StandIn::new()));
    seed_live_model_grant(
        &supplied_grants,
        &granted_model_turn_request_id(supplied, supplied_prompt),
        supplied,
    );
    let supplied_turn = granted_model_turn(supplied_grants, supplied, supplied_prompt);
    assert_granted_model_turn(&supplied_turn, supplied);
}

/// The relay records a provider socket that closed mid-stream as unreachable,
/// naming the closed socket. The provider can close its end of the Runtime
/// socket while the relay copies the backend stream, and the relay must not
/// record that as an answer: `Answered` would claim a status the provider never
/// received (P11). The relay end here has no peer, so its head and first frame
/// writes fail, while the loopback backend answers.
#[test]
fn relay_reports_a_closed_provider_socket_as_unreachable() {
    let backend = LocalRelayBackend::bind();
    let (provider_end, stand_in_end) = UnixStream::pair().expect("a relay socket pair");
    drop(provider_end);
    let outcome = relay_hosted_effect(&stand_in_end, b"{}", backend.url());
    assert_eq!(
        backend.observe().len(),
        1,
        "the local backend must answer the closed provider's one request"
    );
    match outcome {
        RelayOutcome::Unreachable { reason } => assert!(
            reason.starts_with("the provider closed its Runtime socket before the stream ended:"),
            "the outcome must name the closed provider socket: {reason}"
        ),
        RelayOutcome::Answered {
            status,
            first_bytes,
        } => panic!(
            "a closed provider socket must not record an answer: status {status}, \
             {} answer bytes",
            first_bytes.len()
        ),
    }
}

/// The opt-in real model turn through the provider's hosted half. The stand-in
/// plays the Runtime: it accepts the hosted effect, relays the provider's body
/// unchanged to the Sparks engine at `SPARKS_MODEL_URL`, and answers in the
/// Runtime's own stream framing. The test shows that the provider's hosted half
/// carries one real model turn end to end. It is lab evidence only: the
/// stand-in is not the Runtime, and a Sparks engine reached by URL is not
/// Anders's A4 path
/// (`examples/agent-host/handoff/reports/provider-a4-deepseek-turn-gaps.md`,
/// "The A4 path, as Anders states it"). The relay itself is checked on every
/// gate by `hosted_relay_forwards_the_provider_body_unchanged_and_no_key`
/// (`MP30`, `MP31`, `MP33`, `MP34`); this test is the real Sparks run only.
///
/// Its failure messages print the run's status and error code, never the run,
/// so a failed real turn prints no answer text (049 review).
///
/// It needs the network, so it is ignored by default and no falsifier runs it.
/// Its paired falsifier is 048's `MP29`: a run with no grant is refused before
/// any send.
#[test]
#[ignore = "opt-in: needs SPARKS_MODEL_URL and the DeepSeek model on the Sparks"]
fn opt_in_real_deepseek_turn_through_the_runtime_socket_completes_with_text_and_usage() {
    if !cfg!(target_os = "macos") {
        eprintln!(
            "SKIP model-provider real DeepSeek turn: off macOS the provider \
             refuses every hosted run before any socket"
        );
        return;
    }
    let Some(backend_url) = std::env::var("SPARKS_MODEL_URL")
        .ok()
        .filter(|url| !url.is_empty())
    else {
        eprintln!(
            "SKIP model-provider real DeepSeek turn: SPARKS_MODEL_URL is unset, \
             so no real model is called"
        );
        return;
    };

    let turn = run_granted_hosted_turn_through_relay(
        "real-deepseek-turn",
        &backend_url,
        REAL_TURN_MODEL,
        REAL_TURN_TIMEOUT.as_millis() as u64,
        REAL_TURN_TIMEOUT + FIXTURE_EVENT_TIMEOUT,
        "Reply with the single word ready",
    );
    let RelayedHostedTurn {
        stand_in,
        settled,
        backend,
        mut provider,
    } = turn;
    match &backend {
        RelayOutcome::Answered { status: 200, .. } => {}
        RelayOutcome::Answered {
            status,
            first_bytes,
        } => panic!(
            "the Sparks backend answered {status}, not 200: {}",
            String::from_utf8_lossy(first_bytes)
        ),
        RelayOutcome::Unreachable { reason } => {
            panic!("the Sparks backend is unreachable: {reason}")
        }
    }

    assert_eq!(
        settled["data"]["status"],
        "completed",
        "the permitted real turn must complete the run: {}",
        run_status_and_error_code(&settled)
    );
    let output = &settled["data"]["terminal"]["output"];
    assert_eq!(
        output["schema"],
        RUN_OUTPUT_TEXT_SCHEMA,
        "the run must carry the text output schema: {}",
        run_status_and_error_code(&settled)
    );
    let text = output["text"]
        .as_str()
        .expect("the completed run carries text");
    assert!(
        !text.trim().is_empty(),
        "the DeepSeek answer must not be empty: {}",
        run_status_and_error_code(&settled)
    );
    let report = &settled["data"]["terminal"]["backend_report"];
    assert_eq!(
        report["usage"]["status"],
        "reported",
        "the run must record the backend's usage: {}",
        run_status_and_error_code(&settled)
    );
    let input_tokens = report["usage"]["value"]["input_tokens"]
        .as_u64()
        .expect("reported usage carries input_tokens");
    let output_tokens = report["usage"]["value"]["output_tokens"]
        .as_u64()
        .expect("reported usage carries output_tokens");
    let total_tokens = report["usage"]["value"]["total_tokens"]
        .as_u64()
        .expect("reported usage carries total_tokens");
    assert!(
        input_tokens > 0,
        "the real turn must report input tokens: {}",
        run_status_and_error_code(&settled)
    );
    assert!(
        output_tokens > 0,
        "the real turn must report output tokens: {}",
        run_status_and_error_code(&settled)
    );

    let (connections, requests) = stand_in.observe();
    assert_eq!(
        connections, 1,
        "the real turn must open exactly one connection to the Runtime socket"
    );
    assert_eq!(
        requests.len(),
        1,
        "the real turn must send exactly one request"
    );
    let recorded = &requests[0];
    assert_eq!(recorded.request_line, "POST /v1/hosted-effect HTTP/1.1");
    assert_eq!(
        recorded.value("authorization"),
        None,
        "a hosted run must carry no bearer key"
    );
    let forwarded: Value = serde_json::from_slice(&recorded.body)
        .expect("the provider's hosted body is the JSON text request");
    assert_eq!(
        forwarded["model"], REAL_TURN_MODEL,
        "the forwarded body must pin the DeepSeek selector: {forwarded}"
    );

    eprintln!(
        "real DeepSeek turn: answer {} bytes, usage input_tokens {input_tokens}, \
         output_tokens {output_tokens}, total_tokens {total_tokens}",
        text.len()
    );

    provider.shutdown();
}

/// The run limit for `a_hosted_run_held_past_its_time_limit_fails_as_a_timeout`.
/// The other hosted tests keep `HOSTED_FIXTURE_RUNTIME_MS_LIMIT`.
const HOSTED_TIMEOUT_RUNTIME_MS_LIMIT: u64 = 2_000;

/// How long past that limit `wait_for_run_terminal_within` may wait. A client
/// that no longer stops at the limit stays open through this wait, so the
/// wait's `model run did not settle` is what a dropped timeout must hit.
const HOSTED_TIMEOUT_SETTLE_SLACK: Duration = Duration::from_secs(10);

/// A hosted run whose answer never comes ends on its own time limit, as one
/// `failed` terminal, and the offer's one run slot is then free.
///
/// The rule has three parts. `remaining_run_timeout`
/// (`src/adapters.rs:132-141`) gives the hosted client its timeout
/// (`src/adapters.rs:1894-1899`). The worker returns `true` on a
/// `BackendTimeout` fault (`src/adapters.rs:1486-1490`). The coordinator's
/// `Exited { timed_out: true }` arm (`src/execution.rs:399-403`) calls
/// `settle_local_text_run_timeout` (`src/state.rs:832-844`), which uses
/// `transition_timeout` (`src/state.rs:1419-1432`) and records `failed` with
/// class and code `backend_timeout`. While that worker is alive, a read does
/// not settle the run (`src/state.rs:1006-1009`), so only the worker's own
/// timeout ends it.
///
/// The design lines this pins are "prompt and event privacy, bounded
/// capacity, queues, tokens, time, and usage;" (`docs/MODEL_PROVIDER.md:536`)
/// and "each request has one terminal state;" (`docs/MODEL_PROVIDER.md:556`).
///
/// The stand-in is `HostedEffectStandIn::bind`, and `hold_answer` keeps its
/// refusal back. The offer limit is `HOSTED_TIMEOUT_RUNTIME_MS_LIMIT`. The
/// create body is `hosted_text_create_request`. Off macOS the provider
/// refuses every hosted run before any socket, so the test prints one `SKIP`
/// line and returns.
#[test]
fn a_hosted_run_held_past_its_time_limit_fails_as_a_timeout() {
    if !cfg!(target_os = "macos") {
        eprintln!(
            "SKIP model-provider hosted run held past its time limit: off macOS the \
             provider refuses every hosted run before any socket"
        );
        return;
    }
    let root = test_support::temp_root_path("model-provider-process", "hosted-run-timeout");
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let stand_in = HostedEffectStandIn::bind("hosted-run-timeout");
    stand_in.hold_answer();
    let init = hosted_effect_init(
        &root,
        &stand_in,
        HOSTED_FIXTURE_MODEL,
        HOSTED_TIMEOUT_RUNTIME_MS_LIMIT,
    );
    let mut provider = ProviderProcess::start();
    let started = provider.request(init);
    assert_eq!(
        started["status"], "ok",
        "unexpected init response: {started}"
    );

    let create_a = hosted_text_create_request(
        &test_support::fixture_model_request_id("request:hosted-run-timeout-a"),
        "grant:test",
        "a hosted run held past its time limit",
    );
    let mut create_c = create_a.clone();
    create_c["runtime_binding"]["request_id"] = json!(test_support::fixture_model_request_id(
        "request:hosted-run-timeout-c"
    ));
    let binding_a: RuntimeCreateBinding =
        serde_json::from_value(create_a["runtime_binding"].clone()).unwrap();
    let binding_c: RuntimeCreateBinding =
        serde_json::from_value(create_c["runtime_binding"].clone()).unwrap();
    let run_a = model_run_id(&binding_a);
    let run_c = model_run_id(&binding_c);
    assert_ne!(run_a, run_c, "each request id must name its own run");

    let opened_at = Instant::now();
    let created_a = provider.request(create_a.clone());
    assert_eq!(
        created_a["status"], "ok",
        "unexpected create response: {created_a}"
    );
    assert_eq!(
        created_a["data"]["run_id"], run_a,
        "runs_create must return the contract run id"
    );
    assert!(
        matches!(
            created_a["data"]["status"].as_str(),
            Some("prepared" | "running")
        ),
        "the held hosted run must report an open status: {created_a}"
    );
    stand_in.wait_for_connections(1);
    assert_eq!(
        stand_in.connection_count(),
        1,
        "the held hosted run must open exactly one connection to the Runtime socket"
    );

    let settle_budget =
        Duration::from_millis(HOSTED_TIMEOUT_RUNTIME_MS_LIMIT) + HOSTED_TIMEOUT_SETTLE_SLACK;
    let settled_a = wait_for_run_terminal_within(
        &mut provider,
        &run_a,
        &access_binding(&create_a),
        settle_budget,
    );
    let elapsed = opened_at.elapsed();
    assert!(
        elapsed >= Duration::from_millis(HOSTED_TIMEOUT_RUNTIME_MS_LIMIT - 100),
        "the run limit must be what ended the run: elapsed {elapsed:?}, limit {HOSTED_TIMEOUT_RUNTIME_MS_LIMIT} ms"
    );
    assert_eq!(
        settled_a["data"]["status"], "failed",
        "a run held past its time limit must fail: {settled_a}"
    );
    assert_eq!(
        settled_a["data"]["terminal"]["error"]["class"], "backend_timeout",
        "a time limit must record class backend_timeout: {settled_a}"
    );
    assert_eq!(
        settled_a["data"]["terminal"]["error"]["code"], "backend_timeout",
        "a time limit must record code backend_timeout: {settled_a}"
    );
    assert!(
        settled_a["data"]["terminal"]["output"].is_null(),
        "a timed-out run must carry no output: {settled_a}"
    );
    // `transition_timeout` passes no report (`src/state.rs:1421-1431`). A
    // hosted terminal with no report stores `BackendReport::unknown()`
    // (`src/state.rs:1354`). `unknown()` sets `usage` to `BackendFact::Unknown`
    // with no reason and no count (`src/contract.rs:212-218`).
    assert_eq!(
        settled_a["data"]["terminal"]["backend_report"],
        json!({
            "schema": BACKEND_REPORT_SCHEMA,
            "resolved_model": {"status": "unknown"},
            "usage": {"status": "unknown"},
            "cost": {"status": "unknown"},
        }),
        "a timed-out hosted run must record resolved_model, usage and cost as unknown, with no count: {settled_a}"
    );

    let events = read_hosted_run_events(&mut provider, &run_a, &access_binding(&create_a));
    assert!(
        events.iter().all(|event| event["kind"] != "text_delta"),
        "a timed-out run must carry no text deltas: {events:?}"
    );

    let again = provider.request(json!({
        "op": "runs_get",
        "run_id": run_a,
        "runtime_binding": access_binding(&create_a)
    }));
    assert_eq!(again["status"], "ok", "unexpected run response: {again}");
    assert_eq!(
        again["data"], settled_a["data"],
        "a second read must return the same terminal: {again}"
    );

    stand_in.release_answer();
    let created_c = provider.request(create_c.clone());
    assert_eq!(
        created_c["status"], "ok",
        "unexpected create response: {created_c}"
    );
    assert_eq!(
        created_c["data"]["run_id"], run_c,
        "runs_create must return the contract run id"
    );
    assert_ne!(
        created_c["data"]["terminal"]["error"]["code"], "model_busy",
        "the timed-out run must free the one slot: {created_c}"
    );
    let settled_c = wait_for_run_terminal(&mut provider, &run_c, &access_binding(&create_c));
    assert_eq!(
        settled_c["data"]["terminal"]["error"]["code"], "hosted_effect_refused",
        "the next run must be admitted and reach the Runtime socket: {settled_c}"
    );
    stand_in.wait_for_connections(2);

    let (connections, requests) = stand_in.observe();
    assert_eq!(
        connections, 2,
        "the timed-out run and the next run must open one connection each"
    );
    assert_eq!(
        requests.len(),
        2,
        "the timed-out run must send one request and no retry"
    );
    for recorded in &requests {
        assert_eq!(recorded.request_line, "POST /v1/hosted-effect HTTP/1.1");
        assert_eq!(
            recorded.value("authorization"),
            None,
            "a hosted run must carry no bearer key"
        );
    }

    provider.shutdown();
}

/// Which three-frame fact sequence the hosted backend-fact journey sends.
enum HostedBackendFactCase {
    Repeated,
    Conflict,
    Malformed,
}

/// One Chat Completions frame. `text` is the delta; `None` is an empty delta.
fn hosted_chat_fact_payload(model: Value, usage: &Value, text: Option<&str>) -> String {
    let delta = match text {
        Some(text) => json!({ "content": text }),
        None => json!({}),
    };
    serde_json::to_string(&json!({
        "model": model,
        "choices": [{ "delta": delta }],
        "usage": usage,
    }))
    .expect("a hosted fact frame is json")
}

fn hosted_fact_frames(model: Value, usage: &Value) -> [String; 3] {
    [
        hosted_chat_fact_payload(model.clone(), usage, Some("ready")),
        hosted_chat_fact_payload(model.clone(), usage, Some(" set")),
        hosted_chat_fact_payload(model, usage, None),
    ]
}

/// The report a completed hosted run stores when every fact is unknown.
/// Each fact is the bare `{"status":"unknown"}` object: usage has no reason
/// and no count (`src/contract.rs`, `BackendFact::Unknown`).
fn unknown_hosted_backend_report() -> Value {
    json!({
        "schema": BACKEND_REPORT_SCHEMA,
        "resolved_model": {"status": "unknown"},
        "usage": {"status": "unknown"},
        "cost": {"status": "unknown"},
    })
}

/// Fact set A, written once. Frames that repeat A share this object.
fn hosted_fact_set_a() -> (Value, Value) {
    (
        json!("resolved-a"),
        json!({
            "prompt_tokens": 7,
            "completion_tokens": 1,
            "total_tokens": 8,
            "cost": 0.1,
            "cost_unit": "backend-credit",
        }),
    )
}

/// A hosted run's backend facts stay as `CapturedBackendFact::observe`
/// recorded them (`src/adapters.rs`) through completion and a restart on the
/// same journal. The design sections are "Selection policy" and "Request
/// identity and session facts" in `docs/MODEL_PROVIDER.md`: the provider
/// records the resolved model, usage and cost the backend reports, and a
/// conflicting or malformed fact stays unknown through later frames.
/// `HostedBackendReport::observe_chat_completions` feeds that collector, and
/// `finish` reports it.
///
/// The run status is `completed`. The terminal event kind is `output`
/// (`src/state.rs`, `synthesize_terminal_event`). The answer text is
/// `ready set` for every fact sequence.
///
/// Off macOS the provider refuses every hosted run before any socket, so the
/// test prints one `SKIP` line and returns.
fn hosted_backend_facts_through_completion_and_restart(case: HostedBackendFactCase) {
    let (model_a, usage_a) = hosted_fact_set_a();
    let (label, payloads, expected_report) = match case {
        HostedBackendFactCase::Repeated => (
            "hosted-facts-repeated",
            hosted_fact_frames(model_a, &usage_a).to_vec(),
            json!({
                "schema": BACKEND_REPORT_SCHEMA,
                "resolved_model": {"status": "reported", "value": "resolved-a"},
                "usage": {
                    "status": "reported",
                    "value": {
                        "input_tokens": 7,
                        "output_tokens": 1,
                        "total_tokens": 8,
                    },
                },
                "cost": {
                    "status": "reported",
                    "value": {"value": "0.1", "unit": "backend-credit"},
                },
            }),
        ),
        HostedBackendFactCase::Conflict => {
            let usage_b = json!({
                "prompt_tokens": 8,
                "completion_tokens": 1,
                "total_tokens": 9,
                "cost": 0.2,
                "cost_unit": "backend-credit",
            });
            (
                "hosted-facts-conflict",
                vec![
                    hosted_chat_fact_payload(model_a.clone(), &usage_a, Some("ready")),
                    hosted_chat_fact_payload(json!("resolved-b"), &usage_b, Some(" set")),
                    hosted_chat_fact_payload(model_a, &usage_a, None),
                ],
                unknown_hosted_backend_report(),
            )
        }
        HostedBackendFactCase::Malformed => {
            let usage_malformed = json!({
                "prompt_tokens": "invalid",
                "completion_tokens": 1,
                "total_tokens": 8,
                "cost": -0.1,
                "cost_unit": "backend-credit",
            });
            (
                "hosted-facts-malformed",
                vec![
                    hosted_chat_fact_payload(model_a.clone(), &usage_a, Some("ready")),
                    hosted_chat_fact_payload(json!(17), &usage_malformed, Some(" set")),
                    hosted_chat_fact_payload(model_a, &usage_a, None),
                ],
                unknown_hosted_backend_report(),
            )
        }
    };
    if !cfg!(target_os = "macos") {
        eprintln!(
            "SKIP model-provider hosted backend facts ({label}): off macOS the provider \
             refuses every hosted run before any socket"
        );
        return;
    }

    let root = test_support::temp_root_path("model-provider-process", label);
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let stand_in = HostedEffectStandIn::bind_streaming_frames(
        label,
        runtime_hosted_chat_frames_answer(&payloads),
    );
    let init = hosted_effect_init(
        &root,
        &stand_in,
        HOSTED_FIXTURE_MODEL,
        HOSTED_FIXTURE_RUNTIME_MS_LIMIT,
    );
    let mut provider = ProviderProcess::start();
    let started = provider.request(init.clone());
    assert_eq!(
        started["status"], "ok",
        "unexpected init response: {started}"
    );

    let create_request = hosted_text_create_request(
        &test_support::fixture_model_request_id(&format!("request:{label}")),
        "grant:test",
        "hosted backend facts",
    );
    let binding: RuntimeCreateBinding =
        serde_json::from_value(create_request["runtime_binding"].clone()).unwrap();
    let expected_run_id = model_run_id(&binding);
    let create = provider.request(create_request.clone());
    assert_eq!(
        create["status"], "ok",
        "unexpected create response: {create}"
    );
    assert_eq!(
        create["data"]["run_id"], expected_run_id,
        "runs_create must return the contract run id"
    );

    let access = access_binding(&create_request);
    let settled = wait_for_run_terminal_within(
        &mut provider,
        &expected_run_id,
        &access,
        FIXTURE_EVENT_TIMEOUT,
    );
    assert_eq!(
        settled["data"]["status"], "completed",
        "the hosted fact run must complete: {settled}"
    );
    assert_eq!(
        settled["data"]["terminal"]["output"],
        json!({"schema": RUN_OUTPUT_TEXT_SCHEMA, "text": "ready set"}),
        "the answer text stays ready set: {settled}"
    );
    assert!(
        settled["data"]["terminal"].get("error").is_none(),
        "a completed fact run has no error: {settled}"
    );
    assert_eq!(
        settled["data"]["terminal"]["backend_report"], expected_report,
        "the backend report must stay the collector's record through completion: {settled}"
    );

    let events = read_hosted_run_events(&mut provider, &expected_run_id, &access);
    let mut joined = String::new();
    for event in &events {
        if event["kind"] == "text_delta" {
            joined.push_str(event["data"]["text"].as_str().unwrap_or(""));
        }
    }
    assert_eq!(
        joined, "ready set",
        "joined text deltas must be exactly the answer: {events:?}"
    );
    let terminal_event = events.last().expect("the run keeps a terminal event");
    assert_eq!(
        terminal_event["kind"], "output",
        "the terminal event kind is output: {terminal_event}"
    );
    assert_eq!(
        terminal_event["backend_report"], settled["data"]["terminal"]["backend_report"],
        "the terminal event carries the same backend report: {terminal_event}"
    );

    let saved_terminal = settled["data"]["terminal"].clone();
    let saved_events = events;
    provider.shutdown();

    let mut provider = ProviderProcess::start();
    let restarted = provider.request(init);
    assert_eq!(
        restarted["status"], "ok",
        "unexpected restart init response: {restarted}"
    );
    let replayed = wait_for_run_terminal_within(
        &mut provider,
        &expected_run_id,
        &access,
        FIXTURE_EVENT_TIMEOUT,
    );
    assert_eq!(
        replayed["data"]["status"], "completed",
        "the restarted provider must still show the completed run: {replayed}"
    );
    assert_eq!(
        replayed["data"]["terminal"], saved_terminal,
        "the restarted provider must replay the same terminal: {replayed}"
    );
    let replayed_events = read_hosted_run_events(&mut provider, &expected_run_id, &access);
    assert_eq!(
        replayed_events, saved_events,
        "the restarted provider must replay the same event sequence"
    );
    provider.shutdown();

    let (connections, requests) = stand_in.observe();
    assert_eq!(
        connections, 1,
        "the journey must open exactly one connection to the Runtime socket"
    );
    assert_eq!(
        requests.len(),
        1,
        "the journey must send exactly one request"
    );
    assert_eq!(requests[0].request_line, "POST /v1/hosted-effect HTTP/1.1");
    assert_eq!(
        requests[0].value("authorization"),
        None,
        "a hosted run must carry no bearer key"
    );
}

#[test]
fn hosted_backend_facts_repeated_values_stay_reported_after_restart() {
    hosted_backend_facts_through_completion_and_restart(HostedBackendFactCase::Repeated);
}

#[test]
fn hosted_backend_facts_conflicts_stay_unknown_after_restart() {
    hosted_backend_facts_through_completion_and_restart(HostedBackendFactCase::Conflict);
}

#[test]
fn hosted_backend_facts_malformed_values_stay_unknown_after_restart() {
    hosted_backend_facts_through_completion_and_restart(HostedBackendFactCase::Malformed);
}

/// What an accepted retry of one hosted request must return.
#[derive(Clone, Copy)]
enum HostedIdentityReplay<'a> {
    /// The answer is still held: the run is `prepared` or `running`.
    Open,
    /// The run has completed: the retry returns this saved `data`.
    Saved(&'a Value),
}

/// The prompt the identity journey sends once. Conflict rows use another prompt.
const HOSTED_IDENTITY_PROMPT: &str = "hosted request identity";

/// The refusal `handle_runs_create` returns when a retained run's fingerprint
/// differs (`src/state.rs`).
const HOSTED_REQUEST_CONFLICT_MESSAGE: &str = "request_id conflicts with an existing model run";

/// Reported model, usage and cost for 073's fact set A. The frames are
/// `hosted_fact_frames` of `hosted_fact_set_a`, so every fact stays `reported`.
fn reported_hosted_identity_facts() -> Value {
    json!({
        "schema": BACKEND_REPORT_SCHEMA,
        "resolved_model": {"status": "reported", "value": "resolved-a"},
        "usage": {
            "status": "reported",
            "value": {
                "input_tokens": 7,
                "output_tokens": 1,
                "total_tokens": 8,
            },
        },
        "cost": {
            "status": "reported",
            "value": {"value": "0.1", "unit": "backend-credit"},
        },
    })
}

fn hosted_request_with_audit(
    request: &Value,
    session_id: Option<&str>,
    grant_id: Option<&str>,
) -> Value {
    let mut request = request.clone();
    if let Some(session_id) = session_id {
        request["runtime_binding"]["session_id"] = json!(session_id);
    }
    if let Some(grant_id) = grant_id {
        request["runtime_binding"]["grant_id"] = json!(grant_id);
    }
    request
}

fn hosted_request_with_prompt(request: &Value, prompt: &str) -> Value {
    let mut request = request.clone();
    let input = json!({
        "schema": elastos_model_contract::TEXT_INPUT_V1_SCHEMA,
        "prompt": prompt
    });
    request["input"] = input.clone();
    request["runtime_binding"]["input_hash"] = json!(model_input_hash(&input).unwrap());
    request
}

fn hosted_request_with_field(request: &Value, field: &str, value: &str) -> Value {
    let mut request = request.clone();
    request[field] = json!(value);
    request["runtime_binding"][field] = json!(value);
    request
}

fn hosted_identity_rotations(original: &Value) -> Vec<(&'static str, Value)> {
    vec![
        ("unchanged binding", original.clone()),
        (
            "changed session only",
            hosted_request_with_audit(original, Some("session:rotated"), None),
        ),
        (
            "changed grant only",
            hosted_request_with_audit(original, None, Some("grant:rotated")),
        ),
        (
            "changed session and grant",
            hosted_request_with_audit(original, Some("session:rotated"), Some("grant:rotated")),
        ),
    ]
}

fn hosted_identity_conflicts(original: &Value) -> Vec<(&'static str, Value)> {
    vec![
        (
            "changed prompt",
            hosted_request_with_prompt(original, "hosted request identity changed"),
        ),
        (
            "changed offer id",
            hosted_request_with_field(original, "offer_id", "other-offer"),
        ),
        (
            "changed operation",
            hosted_request_with_field(original, "operation", "image.generate"),
        ),
    ]
}

/// Sends one retry only after `RuntimeCreateBinding::validate` accepts it for
/// its own request. Principal, capsule and request id stay the original values.
fn send_hosted_identity_retry(
    provider: &mut ProviderProcess,
    stage: &str,
    row: &str,
    original: &Value,
    request: &Value,
) -> Value {
    for field in ["principal_id", "capsule_id", "request_id"] {
        assert_eq!(
            request["runtime_binding"][field], original["runtime_binding"][field],
            "{stage} / {row}: {field} stays the original value"
        );
    }
    let binding: RuntimeCreateBinding = serde_json::from_value(request["runtime_binding"].clone())
        .unwrap_or_else(|error| {
            panic!("{stage} / {row}: the runtime binding is not JSON: {error}")
        });
    let offer_id = request["offer_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{stage} / {row}: offer_id must be a string"));
    let operation = request["operation"]
        .as_str()
        .unwrap_or_else(|| panic!("{stage} / {row}: operation must be a string"));
    binding
        .validate(offer_id, operation, &request["input"])
        .unwrap_or_else(|error| {
            panic!(
                "{stage} / {row}: RuntimeCreateBinding::validate must accept this \
                 request before the provider sees it: {error}"
            )
        });
    provider.request(request.clone())
}

fn assert_hosted_identity_retry(
    stage: &str,
    row: &str,
    response: &Value,
    run_id: &str,
    expected: HostedIdentityReplay<'_>,
) {
    assert_eq!(
        response["status"], "ok",
        "{stage} / {row}: the retained request must be accepted: {response}"
    );
    assert_eq!(
        response["data"]["run_id"], run_id,
        "{stage} / {row}: the retained request must return the original run id: {response}"
    );
    match expected {
        HostedIdentityReplay::Open => {
            assert!(
                response["data"]["terminal"].is_null(),
                "{stage} / {row}: the run must stay open: {response}"
            );
            assert!(
                matches!(
                    response["data"]["status"].as_str(),
                    Some("prepared" | "running")
                ),
                "{stage} / {row}: the run must report an open status: {response}"
            );
        }
        HostedIdentityReplay::Saved(data) => {
            assert_eq!(
                &response["data"], data,
                "{stage} / {row}: the retained request must return the saved run data: {response}"
            );
        }
    }
}

/// One refusal check for every conflict row. The stage and the row name the failure.
fn assert_hosted_request_conflict(stage: &str, row: &str, response: &Value) {
    assert_eq!(
        response,
        &json!({
            "status": "error",
            "code": "invalid_request",
            "message": HOSTED_REQUEST_CONFLICT_MESSAGE,
        }),
        "{stage} / {row}: a changed request fact must be refused: {response}"
    );
}

fn replay_hosted_request_identity(
    provider: &mut ProviderProcess,
    stage: &str,
    original: &Value,
    run_id: &str,
    expected: HostedIdentityReplay<'_>,
) {
    for (row, request) in hosted_identity_rotations(original) {
        let response = send_hosted_identity_retry(provider, stage, row, original, &request);
        assert_hosted_identity_retry(stage, row, &response, run_id, expected);
    }
    for (row, request) in hosted_identity_conflicts(original) {
        let response = send_hosted_identity_retry(provider, stage, row, original, &request);
        assert_hosted_request_conflict(stage, row, &response);
    }
}

fn assert_hosted_identity_record(
    provider: &mut ProviderProcess,
    stage: &str,
    run_id: &str,
    access: &Value,
    saved_data: &Value,
    saved_events: &[Value],
) {
    let owner = provider.request(json!({
        "op": "runs_get",
        "run_id": run_id,
        "runtime_binding": access,
    }));
    assert_eq!(
        owner["status"], "ok",
        "{stage}: the owner read must succeed: {owner}"
    );
    assert_eq!(
        &owner["data"], saved_data,
        "{stage}: the owner run must stay the saved result: {owner}"
    );
    assert_eq!(
        owner["data"]["status"], "completed",
        "{stage}: the run status stays completed: {owner}"
    );
    let events = read_hosted_run_events(provider, run_id, access);
    assert_eq!(
        events, saved_events,
        "{stage}: the event sequence must stay the saved sequence"
    );
    let terminal = events.last().expect("the run keeps a terminal event");
    assert_eq!(
        terminal["kind"], "output",
        "{stage}: the final terminal event kind is output: {terminal}"
    );
}

fn assert_one_hosted_identity_effect(
    stand_in: HostedEffectStandIn,
    request_id: &str,
    run_id: &str,
    prompt: &str,
) {
    let (connections, requests) = stand_in.observe();
    assert_eq!(
        connections, 1,
        "the journey must open exactly one connection to the Runtime socket"
    );
    assert_eq!(
        requests.len(),
        1,
        "the journey must send exactly one request"
    );
    let recorded = &requests[0];
    assert_eq!(recorded.request_line, "POST /v1/hosted-effect HTTP/1.1");
    assert!(
        recorded.colonless.is_empty(),
        "the Runtime refuses a header line with no colon: {:?}",
        recorded.colonless
    );
    let mut names: Vec<String> = Vec::new();
    for (name, _) in &recorded.headers {
        let name = name.to_ascii_lowercase();
        assert!(
            RUNTIME_HOSTED_HEADER_NAMES.contains(&name.as_str()),
            "the Runtime refuses every other header name: {name}"
        );
        assert!(
            !names.contains(&name),
            "the Runtime refuses a repeated header name: {name}"
        );
        names.push(name);
    }
    assert_eq!(recorded.value("host"), Some("runtime.invalid"));
    assert_eq!(recorded.value("x-elastos-effect"), Some("text"));
    assert_eq!(
        recorded.value("x-elastos-offer-id"),
        Some(HOSTED_EFFECT_OFFER)
    );
    assert_eq!(recorded.value("x-elastos-request-id"), Some(request_id));
    assert_eq!(recorded.value("x-elastos-run-id"), Some(run_id));
    assert_eq!(
        recorded.value("authorization"),
        None,
        "a hosted run must carry no bearer key"
    );
    assert_eq!(
        recorded.value("x-elastos-job-id"),
        None,
        "a text effect carries no job id"
    );
    assert!(
        !recorded.head().contains("fixture-key"),
        "the offer's key must appear nowhere in the recorded request head: {}",
        recorded.head()
    );
    let body: Value = serde_json::from_slice(&recorded.body)
        .expect("the hosted effect body is the JSON text request");
    assert_eq!(
        body["messages"][0]["content"], prompt,
        "the hosted effect body must carry the original prompt: {body}"
    );
}

/// A hosted model request keeps one result through session and grant rotation,
/// and refuses a retry that changes the prompt, the offer or the operation.
/// The run id is `model_run_id` (principal, capsule, request). The fingerprint
/// in `request_fingerprint` binds principal, capsule, request, offer, operation
/// and the input hash. Session and grant stay invocation audit facts
/// (`docs/MODEL_PROVIDER.md`, "Request identity and session facts";
/// `docs/AGENT_ARCHITECTURE.md`, "Session and interaction contract").
/// The terminal event kind is `output` when the run status is `completed`
/// (`synthesize_terminal_event`). This is the Runtime-socket lab proof for the
/// provider side of the M1 A4/A7 unblock.
///
/// Off macOS the provider refuses every hosted run before any socket, so the
/// test prints one `SKIP` line and returns.
#[test]
fn hosted_request_identity_survives_rotation_and_refuses_conflicts() {
    if !cfg!(target_os = "macos") {
        eprintln!(
            "SKIP model-provider hosted request identity: off macOS the provider \
             refuses every hosted run before any socket"
        );
        return;
    }
    let root = test_support::temp_root_path("model-provider-process", "hosted-request-identity");
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (model, usage) = hosted_fact_set_a();
    let stand_in = HostedEffectStandIn::bind_streaming_frames(
        "hosted-request-identity",
        runtime_hosted_chat_frames_answer(&hosted_fact_frames(model, &usage)),
    );
    stand_in.hold_answer();
    let init = hosted_effect_init(
        &root,
        &stand_in,
        HOSTED_FIXTURE_MODEL,
        HOSTED_FIXTURE_RUNTIME_MS_LIMIT,
    );
    let mut provider = ProviderProcess::start();
    let started = provider.request(init.clone());
    assert_eq!(
        started["status"], "ok",
        "unexpected init response: {started}"
    );

    let request_id = test_support::fixture_model_request_id("request:hosted-request-identity");
    let create_request =
        hosted_text_create_request(&request_id, "grant:test", HOSTED_IDENTITY_PROMPT);
    let binding: RuntimeCreateBinding =
        serde_json::from_value(create_request["runtime_binding"].clone()).unwrap();
    let expected_run_id = model_run_id(&binding);
    let create = send_hosted_identity_retry(
        &mut provider,
        "create",
        "original request",
        &create_request,
        &create_request,
    );
    assert_hosted_identity_retry(
        "create",
        "original request",
        &create,
        &expected_run_id,
        HostedIdentityReplay::Open,
    );
    stand_in.wait_for_connections(1);
    assert_eq!(
        stand_in.connection_count(),
        1,
        "the hosted run must open exactly one connection to the Runtime socket"
    );

    replay_hosted_request_identity(
        &mut provider,
        "while the answer is held",
        &create_request,
        &expected_run_id,
        HostedIdentityReplay::Open,
    );
    assert_eq!(
        stand_in.connection_count(),
        1,
        "while the answer is held: a replay must not open another connection"
    );

    stand_in.release_answer();
    let access = access_binding(&create_request);
    let settled = wait_for_run_terminal_within(
        &mut provider,
        &expected_run_id,
        &access,
        FIXTURE_EVENT_TIMEOUT,
    );
    assert_eq!(
        settled["data"]["status"], "completed",
        "the hosted identity run must complete: {settled}"
    );
    assert_eq!(
        settled["data"]["terminal"]["output"],
        json!({"schema": RUN_OUTPUT_TEXT_SCHEMA, "text": "ready set"}),
        "the answer text stays ready set: {settled}"
    );
    assert!(
        settled["data"]["terminal"].get("error").is_none(),
        "a completed identity run has no error: {settled}"
    );
    assert_eq!(
        settled["data"]["terminal"]["backend_report"],
        reported_hosted_identity_facts(),
        "the backend facts stay reported: {settled}"
    );
    let saved_data = settled["data"].clone();
    let saved_events = read_hosted_run_events(&mut provider, &expected_run_id, &access);
    let mut joined = String::new();
    for event in &saved_events {
        if event["kind"] == "text_delta" {
            joined.push_str(event["data"]["text"].as_str().unwrap_or(""));
        }
    }
    assert_eq!(
        joined, "ready set",
        "joined text deltas must be exactly the answer: {saved_events:?}"
    );
    let terminal = saved_events.last().expect("the run keeps a terminal event");
    assert_eq!(
        terminal["kind"], "output",
        "the final terminal event kind is output: {terminal}"
    );
    assert_eq!(
        terminal["data"],
        json!({"schema": RUN_OUTPUT_TEXT_SCHEMA, "text": "ready set"}),
        "the terminal output is ready set: {terminal}"
    );
    assert_eq!(
        terminal["backend_report"], saved_data["terminal"]["backend_report"],
        "the terminal event carries the same backend report: {terminal}"
    );

    replay_hosted_request_identity(
        &mut provider,
        "after completion",
        &create_request,
        &expected_run_id,
        HostedIdentityReplay::Saved(&saved_data),
    );
    assert_hosted_identity_record(
        &mut provider,
        "after completion",
        &expected_run_id,
        &access,
        &saved_data,
        &saved_events,
    );
    provider.shutdown();

    let mut provider = ProviderProcess::start();
    let restarted = provider.request(init);
    assert_eq!(
        restarted["status"], "ok",
        "unexpected restart init response: {restarted}"
    );
    replay_hosted_request_identity(
        &mut provider,
        "after restart",
        &create_request,
        &expected_run_id,
        HostedIdentityReplay::Saved(&saved_data),
    );
    assert_hosted_identity_record(
        &mut provider,
        "after restart",
        &expected_run_id,
        &access,
        &saved_data,
        &saved_events,
    );
    assert_eq!(
        stand_in.connection_count(),
        1,
        "after restart: a replay must not open another connection"
    );
    provider.shutdown();

    assert_one_hosted_identity_effect(
        stand_in,
        &request_id,
        &expected_run_id,
        HOSTED_IDENTITY_PROMPT,
    );
}
