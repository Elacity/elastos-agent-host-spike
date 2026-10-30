mod checks;
mod runtime;

use std::thread;
use std::time::Duration;

use tao::dpi::LogicalSize;
use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopWindowTarget};
use tao::window::{Window, WindowBuilder};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};
use wry::{WebView, WebViewBuilder};

const POLL: Duration = Duration::from_secs(3);

enum UserEvent {
    Menu(MenuEvent),
    Home(bool),
}

fn main() {
    if let Some(reason) = checks::refusal() {
        alert(&reason);
        return;
    }
    if !runtime::installed() {
        alert(&checks::not_installed());
        return;
    }

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
    let mut home: Option<(Window, WebView)> = None;
    let home_proxy = event_loop.create_proxy();
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
                tray = Some(
                    TrayIconBuilder::new()
                        .with_menu(Box::new(menu))
                        .with_tooltip("ElastOS Lab")
                        .with_icon_templated(icon())
                        .build()
                        .expect("tray icon"),
                );
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
            Event::UserEvent(UserEvent::Home(up)) => {
                // Opening the app opens Home, like any app opens its window.
                if home_up.is_none() && up {
                    show_home(&mut home, target);
                }
                home_up = Some(up);
                status.set_text(if up {
                    "Home is running"
                } else {
                    "Home is not running"
                });
            }
            // Double-clicking the app, or clicking its Dock icon, while it runs.
            Event::Reopen { .. } => open_home(home_up, &mut home, target),
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
                    open_home(home_up, &mut home, target);
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
    target: &EventLoopWindowTarget<UserEvent>,
) {
    if home_up == Some(true) {
        show_home(home, target);
    } else {
        alert("Home is not running, so there is nothing to open yet.");
    }
}

/// Shows the one Home window, creating it the first time.
fn show_home(home: &mut Option<(Window, WebView)>, target: &EventLoopWindowTarget<UserEvent>) {
    if home.is_none() {
        match new_home_window(target) {
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

fn new_home_window(
    target: &EventLoopWindowTarget<UserEvent>,
) -> Result<(Window, WebView), Box<dyn std::error::Error>> {
    let window = WindowBuilder::new()
        .with_title("ElastOS")
        .with_inner_size(LogicalSize::new(1280.0, 820.0))
        .with_min_inner_size(LogicalSize::new(720.0, 480.0))
        .build(target)?;
    let webview = WebViewBuilder::new()
        .with_url(runtime::HOME_URL)
        .build(&window)?;
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
            rgba.extend_from_slice(&[0, 0, 0, alpha]);
        }
    }
    Icon::from_rgba(rgba, SIZE, SIZE).expect("tray icon image")
}
