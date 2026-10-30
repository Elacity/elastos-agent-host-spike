mod checks;
mod runtime;

use std::thread;
use std::time::Duration;

use tao::event::{Event, StartCause};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

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

    #[allow(unused_mut)]
    let mut event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    #[cfg(target_os = "macos")]
    {
        use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
        event_loop.set_activation_policy(ActivationPolicy::Accessory);
    }

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

    let mut menu = Some(menu);
    let mut tray: Option<TrayIcon> = None;
    let home_proxy = event_loop.create_proxy();
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            // macOS needs the event loop running before the tray icon exists.
            Event::NewEvents(StartCause::Init) => {
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
                status.set_text(if up {
                    "Home is running"
                } else {
                    "Home is not running"
                });
            }
            Event::UserEvent(UserEvent::Menu(event)) => {
                if event.id == *open.id() || event.id == *updates.id() {
                    if let Err(error) = runtime::open_home() {
                        alert(&format!("Could not open {}: {error}", runtime::HOME_URL));
                    }
                } else if event.id == *quit.id() {
                    tray.take();
                    *control_flow = ControlFlow::Exit;
                }
            }
            _ => {}
        }
    });
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
