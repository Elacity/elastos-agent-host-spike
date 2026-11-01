#[cfg(any(target_os = "macos", target_os = "linux"))]
mod authenticator;
/// No key store here yet: Home's passkey requests are refused.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod authenticator {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;

    pub fn answer(request: &str) -> (String, Option<String>) {
        let id = B64
            .decode(request)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|value| value["id"].as_str().map(str::to_owned))
            .unwrap_or_default();
        let body = serde_json::json!({ "v": 1, "id": id, "ok": false, "name": "NotSupportedError" });
        (B64.encode(body.to_string()), None)
    }

    pub fn settle(_id: &str, _delivered: bool) {}

    pub fn cancel() {}
}
mod checks;
mod firstrun;
mod passkey;
mod runtime;
#[cfg(target_os = "linux")]
mod tpm;

use std::thread;
use std::time::{Duration, Instant};

use tao::dpi::LogicalSize;
use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy, EventLoopWindowTarget};
use tao::window::{Window, WindowBuilder};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};
use wry::{WebView, WebViewBuilder};

const POLL: Duration = Duration::from_secs(1);
const STARTING: &str = "<!doctype html><meta charset=\"utf-8\"><style>html{height:100%;display:grid;place-items:center;font:15px -apple-system,system-ui;color-scheme:light dark}</style><p>Starting ElastOS…</p>";

enum UserEvent {
    Menu(MenuEvent),
    Home(bool),
    Installed(Result<(), String>),
    PasskeyAsk(String, String),
    /// Page generation, request id, answer, and the id of a new passkey still pending.
    PasskeyAnswer(u64, String, String, Option<String>),
    PageStarted,
}

fn main() {
    let started = Instant::now();
    if let Some(reason) = checks::refusal() {
        alert(&reason);
        return;
    }
    let lab_home = runtime::lab_home();
    let release = firstrun::payload();
    // Only experiments with the lab Runtime packed inside the app start Home.
    let lab_start = lab_home.clone().zip(release);
    let mut first_run = lab_start.clone().filter(|_| !runtime::installed());
    if !runtime::installed() && first_run.is_none() {
        alert(&checks::not_installed());
        return;
    }
    let mut ready = first_run.is_none();

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();

    let menu_proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |event| {
        let _ = menu_proxy.send_event(UserEvent::Menu(event));
    }));

    let status = MenuItem::new("Checking Home…", false, None);
    let open = MenuItem::new("Open Home", true, None);
    let stop = MenuItem::new(
        "Stop Home (needs the 0.8.1 background service)",
        false,
        None,
    );
    let updates = MenuItem::new("Check for Updates…", true, None);
    let quit = MenuItem::new("Quit ElastOS Lab", true, None);
    let menu = Menu::new();
    menu.append_items(&[
        &status,
        &PredefinedMenuItem::separator(),
        &open,
        &stop,
        &updates,
        &PredefinedMenuItem::separator(),
        &quit,
    ])
    .expect("tray menu");

    // The menu bar at the top of the screen; Home's text fields need the Edit menu
    // for copy and paste on macOS.
    let app_menu = Menu::new();
    app_menu
        .append_items(&[
            &Submenu::with_items(
                "ElastOS Lab",
                true,
                &[
                    &PredefinedMenuItem::hide(None),
                    &PredefinedMenuItem::separator(),
                    &PredefinedMenuItem::quit(None),
                ],
            )
            .expect("app menu"),
            &Submenu::with_items(
                "Edit",
                true,
                &[
                    &PredefinedMenuItem::undo(None),
                    &PredefinedMenuItem::redo(None),
                    &PredefinedMenuItem::separator(),
                    &PredefinedMenuItem::cut(None),
                    &PredefinedMenuItem::copy(None),
                    &PredefinedMenuItem::paste(None),
                    &PredefinedMenuItem::select_all(None),
                ],
            )
            .expect("edit menu"),
            &Submenu::with_items(
                "Window",
                true,
                &[
                    &PredefinedMenuItem::minimize(None),
                    &PredefinedMenuItem::close_window(None),
                ],
            )
            .expect("window menu"),
        ])
        .expect("app menu");

    let mut menu = Some(menu);
    let mut tray: Option<TrayIcon> = None;
    let mut home_up: Option<bool> = None;
    let mut home_started = false;
    let mut launch_open = true;
    let mut home: Option<(Window, WebView)> = None;
    let mut home_loaded = false;
    let home_proxy = event_loop.create_proxy();
    let install_proxy = event_loop.create_proxy();
    let passkey_proxy = event_loop.create_proxy();
    let mut page: u64 = 0;
    let mut asking: Option<(u64, String)> = None;
    event_loop.run(move |event, target, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            // macOS needs the event loop running before the tray icon exists.
            Event::NewEvents(StartCause::Init) => {
                #[cfg(target_os = "macos")]
                app_menu.init_for_nsapp();
                let Some(menu) = menu.take() else {
                    return;
                };
                let builder = TrayIconBuilder::new()
                    .with_menu(Box::new(menu))
                    .with_tooltip("ElastOS Lab");
                #[cfg(target_os = "macos")]
                let builder = builder.with_icon_templated(icon());
                #[cfg(not(target_os = "macos"))]
                let builder = builder.with_icon(icon());
                tray = Some(builder.build().expect("tray icon"));
                if lab_start.is_some() {
                    show_home(&mut home, target, &passkey_proxy);
                }
                if let Some((lab, release)) = first_run.take() {
                    let proxy = install_proxy.clone();
                    thread::spawn(move || {
                        let result = firstrun::install(&release, &lab).map_err(|e| e.to_string());
                        let _ = proxy.send_event(UserEvent::Installed(result));
                    });
                }
                let proxy = home_proxy.clone();
                thread::spawn(move || loop {
                    if proxy
                        .send_event(UserEvent::Home(runtime::home_answers()))
                        .is_err()
                    {
                        break;
                    }
                    thread::sleep(POLL);
                });
            }
            Event::UserEvent(UserEvent::Installed(result)) => match result {
                Ok(()) => {
                    ready = true;
                    if let Some(lab) = &lab_home {
                        firstrun::note(lab, started, "installed from the release inside the app");
                    }
                }
                Err(error) => {
                    alert(&format!("Could not set up ElastOS from this app: {error}"));
                    *control_flow = ControlFlow::Exit;
                }
            },
            Event::UserEvent(UserEvent::Home(up)) => {
                if let (false, false, true, Some((lab, _))) = (up, home_started, ready, &lab_start)
                {
                    home_started = true;
                    match runtime::start_home(lab) {
                        Ok(()) => firstrun::note(lab, started, "asked the Runtime to start Home"),
                        Err(error) => alert(&format!("Could not start Home: {error}")),
                    }
                }
                // Opening the app opens Home once, like any app opens its window.
                if up && launch_open {
                    launch_open = false;
                    show_home(&mut home, target, &passkey_proxy);
                    if let Some(lab) = &lab_home {
                        firstrun::note(lab, started, "Home answered; Home loaded in the window");
                    }
                } else if !up && !home_started && lab_start.is_none() {
                    launch_open = false;
                }
                if up && !home_loaded {
                    if let Some((_, webview)) = &home {
                        home_loaded = webview.load_url(runtime::HOME_URL).is_ok();
                    }
                }
                home_up = Some(up);
                status.set_text(if up {
                    "Home is running"
                } else {
                    "Home is not running"
                });
            }
            // One passkey request at a time; a second is refused, as WebKit does.
            Event::UserEvent(UserEvent::PasskeyAsk(id, request)) => {
                let Some((_, webview)) = &home else {
                    return;
                };
                if asking.is_some() {
                    let _ = webview.evaluate_script(&passkey::finish_script(&id, None));
                    return;
                }
                asking = Some((page, id.clone()));
                let proxy = passkey_proxy.clone();
                let generation = page;
                thread::spawn(move || {
                    let (answer, created) =
                        std::panic::catch_unwind(|| authenticator::answer(&request))
                            .unwrap_or_default();
                    let _ =
                        proxy.send_event(UserEvent::PasskeyAnswer(generation, id, answer, created));
                });
            }
            // An answer goes only to the page that asked; a new passkey is kept only
            // when that page took it.
            Event::UserEvent(UserEvent::PasskeyAnswer(generation, id, answer, created)) => {
                let current = asking.as_ref() == Some(&(generation, id.clone()));
                if current {
                    asking = None;
                }
                let sent = match (&home, current && generation == page) {
                    (Some((_, webview)), true) => {
                        let settle = created.clone();
                        webview
                            .evaluate_script_with_callback(
                                &passkey::finish_script(&id, Some(&answer)),
                                move |taken| {
                                    if let Some(created) = &settle {
                                        authenticator::settle(created, taken == "true");
                                    }
                                },
                            )
                            .is_ok()
                    }
                    _ => false,
                };
                if let (false, Some(created)) = (sent, &created) {
                    authenticator::settle(created, false);
                }
            }
            // A new document: the old one's Touch ID ends and its answer is dropped.
            Event::UserEvent(UserEvent::PageStarted) => {
                page += 1;
                if asking.is_some() {
                    authenticator::cancel();
                }
            }
            // Double-clicking the app, or clicking its Dock icon, while it runs.
            Event::Reopen { .. } => {
                open_home(home_up, &mut home, &mut home_loaded, target, &passkey_proxy)
            }
            // Closing the window hides it; the app keeps running in the menu bar.
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                if let Some((window, _)) = &home {
                    window.set_visible(false);
                }
            }
            Event::UserEvent(UserEvent::Menu(event)) => {
                if event.id == *open.id() || event.id == *updates.id() {
                    open_home(home_up, &mut home, &mut home_loaded, target, &passkey_proxy);
                } else if event.id == *quit.id() {
                    home.take();
                    tray.take();
                    *control_flow = ControlFlow::Exit;
                }
            }
            _ => {}
        }
    });
}

fn open_home(
    home_up: Option<bool>,
    home: &mut Option<(Window, WebView)>,
    home_loaded: &mut bool,
    target: &EventLoopWindowTarget<UserEvent>,
    proxy: &EventLoopProxy<UserEvent>,
) {
    if home_up != Some(true) {
        alert("Home is not running, so there is nothing to open yet.");
        return;
    }
    show_home(home, target, proxy);
    if let (false, Some((_, webview))) = (*home_loaded, &*home) {
        *home_loaded = webview.load_url(runtime::HOME_URL).is_ok();
    }
}

/// Shows the one Home window, creating it on a local "Starting" page the first time.
fn show_home(
    home: &mut Option<(Window, WebView)>,
    target: &EventLoopWindowTarget<UserEvent>,
    proxy: &EventLoopProxy<UserEvent>,
) {
    if home.is_none() {
        match new_home_window(target, proxy.clone()) {
            Ok(created) => *home = Some(created),
            Err(error) => {
                alert(&format!("Could not open Home: {error}"));
                return;
            }
        }
    }
    if let Some((window, _)) = home {
        window.set_visible(true);
        window.set_focus();
    }
}

/// Lab builds only: page errors and a summary of what Home shows go to
/// `window-diag.log` in the lab home. Paths only; queries can carry launch tokens.
#[cfg(feature = "lab-diag")]
const DIAG_SCRIPT: &str = r#"(() => {
  if (window.location.host !== "localhost:8090") return;
  const channel = window.ipc || (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.ipc);
  if (!channel) return;
  const t0 = Date.now();
  const frame = window.top === window ? "top" : window.location.pathname;
  const send = (kind, text) => {
    try { channel.postMessage(`diag:${frame} ${((Date.now() - t0) / 1000).toFixed(1)}s ${kind} ${String(text).slice(0, 1500)}`); } catch (_) {}
  };
  const path = (url) => { try { return new URL(url, window.location.href).pathname; } catch (_) { return "?"; } };
  send("load", window.location.pathname);
  window.addEventListener("error", (e) => {
    const el = e.target;
    if (el && el !== window && el.tagName) {
      send("load-failed", `${el.tagName} ${path(el.src || el.href || "")}`);
    } else {
      send("error", `${e.message} at ${path(e.filename || "")}:${e.lineno}:${e.colno}`);
    }
  }, true);
  document.addEventListener("securitypolicyviolation", (e) =>
    send("csp", `${e.effectiveDirective} blocked ${path(e.blockedURI || "") || e.blockedURI} at ${path(e.sourceFile || "")}:${e.lineNumber}`));
  window.addEventListener("unhandledrejection", (e) => send("rejection", (e.reason && (e.reason.stack || e.reason.message)) || e.reason));
  for (const level of ["error", "warn"]) {
    const original = console[level].bind(console);
    console[level] = (...args) => { send(level, args.map((a) => (a && a.stack) || String(a)).join(" ")); original(...args); };
  }
  let last = "";
  setInterval(() => {
    if (!document.body) return;
    const shown = [...document.body.querySelectorAll("[id]")]
      .filter((el) => el.getClientRects().length && getComputedStyle(el).visibility !== "hidden" && el.parentElement === document.body)
      .map((el) => el.id);
    const frames = [...document.querySelectorAll("iframe")]
      .map((f) => `${f.id || "iframe"}=${path(f.getAttribute("src") || "")}${f.hidden ? "(hidden)" : ""}`);
    const state = `ready=${document.readyState} nodes=${document.body.getElementsByTagName("*").length} shown=[${shown.join(",")}] frames=[${frames.join(",")}]`;
    if (state !== last) { last = state; send("state", state); }
  }, 1000);
})();"#;

fn new_home_window(
    target: &EventLoopWindowTarget<UserEvent>,
    proxy: EventLoopProxy<UserEvent>,
) -> Result<(Window, WebView), Box<dyn std::error::Error>> {
    let window = WindowBuilder::new()
        .with_title("ElastOS")
        .with_inner_size(LogicalSize::new(1280.0, 820.0))
        .with_min_inner_size(LogicalSize::new(720.0, 480.0))
        .build(target)?;
    #[cfg(feature = "lab-diag")]
    let diag = runtime::lab_home().map(|home| home.join("window-diag.log"));
    #[cfg(not(feature = "lab-diag"))]
    let diag: Option<std::path::PathBuf> = None;
    #[allow(unused_mut)]
    let mut builder = WebViewBuilder::new()
        .with_initialization_script_for_main_only(passkey::WINDOW_SCRIPT, true)
        .with_devtools(diag.is_some());
    #[cfg(feature = "lab-diag")]
    if diag.is_some() {
        builder = builder.with_initialization_script_for_main_only(DIAG_SCRIPT, false);
    }
    let lab_downloads = runtime::lab_home().map(|home| home.join("Downloads"));
    let page_proxy = proxy.clone();
    let builder = builder
        .with_on_page_load_handler(move |event, _url| {
            if let wry::PageLoadEvent::Started = event {
                let _ = page_proxy.send_event(UserEvent::PageStarted);
            }
        })
        .with_download_started_handler(move |_url, path| {
            let mut dialog = rfd::FileDialog::new().set_title("Save");
            if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                dialog = dialog.set_file_name(name);
            }
            if let Some(dir) = &lab_downloads {
                let _ = std::fs::create_dir_all(dir);
                dialog = dialog.set_directory(dir);
            } else if let Some(dir) = path.parent() {
                dialog = dialog.set_directory(dir);
            }
            match dialog.save_file() {
                Some(chosen) => {
                    *path = chosen;
                    true
                }
                None => false,
            }
        })
        .with_ipc_handler(move |message| {
            if let (Some(text), Some(path)) = (message.body().strip_prefix("diag:"), &diag) {
                use std::io::Write;
                if text.len() > 2048 {
                    return;
                }
                if let Ok(mut log) = std::fs::File::options()
                    .create(true)
                    .append(true)
                    .open(path)
                {
                    let _ = writeln!(log, "{text}");
                }
                return;
            }
            if let Some((id, request)) =
                passkey::request(&message.uri().to_string(), message.body())
            {
                let _ = proxy.send_event(UserEvent::PasskeyAsk(id, request));
            }
        })
        .with_html(STARTING);
    #[cfg(target_os = "linux")]
    let webview = {
        use tao::platform::unix::WindowExtUnix;
        use wry::WebViewBuilderExtUnix;
        builder.build_gtk(window.default_vbox().ok_or("the window has no GTK box")?)?
    };
    #[cfg(not(target_os = "linux"))]
    let webview = builder.build(&window)?;
    Ok((window, webview))
}

fn alert(message: &str) {
    rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Warning)
        .set_title("ElastOS Lab")
        .set_description(message)
        .set_buttons(rfd::MessageButtons::Ok)
        .show();
}

/// A ring with a centre dot, drawn as a template so macOS tints it for light and dark menu bars.
fn icon() -> Icon {
    const SIZE: u32 = 32;
    let centre = (SIZE as f32 - 1.0) / 2.0;
    let mut rgba = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for y in 0..SIZE {
        for x in 0..SIZE {
            let distance = ((x as f32 - centre).powi(2) + (y as f32 - centre).powi(2)).sqrt();
            let alpha = if (10.0..=14.5).contains(&distance) || distance <= 4.5 {
                255
            } else {
                0
            };
            // Linux panels are dark and do not tint tray icons.
            let shade = if cfg!(target_os = "macos") { 0 } else { 255 };
            rgba.extend_from_slice(&[shade, shade, shade, alpha]);
        }
    }
    Icon::from_rgba(rgba, SIZE, SIZE).expect("tray icon image")
}
