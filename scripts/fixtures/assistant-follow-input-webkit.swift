// System WKWebView plus a real CGEvent scrollbar drag, matching the review method.
import ApplicationServices
import Cocoa
import WebKit

final class Probe: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
  var web: WKWebView!
  var window: NSWindow!

  func start(url: String) {
    let config = WKWebViewConfiguration()
    config.websiteDataStore = .nonPersistent()
    config.userContentController.add(self, name: "probe")
    web = WKWebView(frame: NSRect(x: 0, y: 0, width: 800, height: 600), configuration: config)
    web.navigationDelegate = self
    window = NSWindow(
      contentRect: NSRect(x: 60, y: 80, width: 800, height: 600),
      styleMask: [.titled, .closable],
      backing: .buffered,
      defer: false)
    window.contentView = web
    window.title = "Assistant follow input regression"
    NSApp.setActivationPolicy(.regular)
    window.makeKeyAndOrderFront(nil)
    NSApp.activate(ignoringOtherApps: true)
    let url = URL(string: url)!
    web.load(URLRequest(url: url))
    DispatchQueue.main.asyncAfter(deadline: .now() + 25) {
      fputs("timeout\n", stderr)
      exit(2)
    }
  }

  func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
    fputs("navigation failed: \(error.localizedDescription)\n", stderr)
    exit(1)
  }

  func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
    fputs("provisional failed: \(error.localizedDescription)\n", stderr)
    exit(1)
  }

  func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
    let text = message.body as? String ?? ""
    guard let data = text.data(using: .utf8),
          let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let phase = obj["phase"] as? String else {
      print(text)
      fflush(stdout)
      exit(0)
    }
    if phase == "done" {
      print(text)
      fflush(stdout)
      exit(0)
    }
    let trusted = AXIsProcessTrusted()
    let rect = obj["rect"] as? [String: Double] ?? [:]
    if phase == "drag" && trusted {
      drag(rect)
      pump(0.7)
    }
    let flag = trusted ? "true" : "false"
    web.evaluateJavaScript("window.__continue(\(flag)); 0") { _, error in
      if let error {
        fputs("continue \(phase): \(error.localizedDescription)\n", stderr)
      }
    }
  }

  func cgPoint(viewX: CGFloat, viewY: CGFloat) -> CGPoint {
    let viewPoint = NSPoint(x: viewX, y: web.isFlipped ? viewY : web.bounds.height - viewY)
    let windowPoint = web.convert(viewPoint, to: nil)
    let screenPoint = window.convertToScreen(NSRect(x: windowPoint.x, y: windowPoint.y, width: 0, height: 0)).origin
    let primaryHeight = NSScreen.screens.first?.frame.height ?? 0
    return CGPoint(x: screenPoint.x, y: primaryHeight - screenPoint.y)
  }

  func post(_ point: CGPoint, _ type: CGEventType) {
    CGEvent(mouseEventSource: nil, mouseType: type, mouseCursorPosition: point, mouseButton: .left)?
      .post(tap: .cghidEventTap)
  }

  func pump(_ seconds: Double) {
    RunLoop.current.run(until: Date().addingTimeInterval(seconds))
  }

  func drag(_ rect: [String: Double]) {
    let x = CGFloat(rect["x"] ?? 0) + CGFloat(rect["width"] ?? 0) - 3
    let top = CGFloat(rect["y"] ?? 0)
    let height = CGFloat(rect["height"] ?? 0)
    let start = cgPoint(viewX: x, viewY: top + height - 14)
    let end = cgPoint(viewX: x, viewY: top + 36)
    post(start, .mouseMoved)
    pump(0.08)
    post(start, .leftMouseDown)
    pump(0.05)
    for step in 1...16 {
      let y = start.y + (end.y - start.y) * CGFloat(step) / 16
      post(CGPoint(x: start.x, y: y), .leftMouseDragged)
      pump(0.02)
    }
    post(end, .leftMouseUp)
  }
}

let app = NSApplication.shared
let probe = Probe()
probe.start(url: CommandLine.arguments[1])
app.run()
