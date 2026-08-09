import SwiftUI
import AppKit

@main
struct TsukubaVPNApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup("つくばVPN") {
            ContentView()
                .environmentObject(model)
                .onAppear {
                    delegate.model = model
                    NSApp.setActivationPolicy(.regular)
                    NSApp.activate(ignoringOtherApps: true)
                }
        }
        .windowResizability(.contentMinSize)
        .commands { CommandGroup(replacing: .newItem) {} }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var model: AppModel?

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard VPNController.shared.isRunning() else { return .terminateNow }

        // つながっていない（待機中の常駐プロセスが残っているだけ）なら、黙って片付ける。
        // ここを放置すると root の openvpn が居座り続けてしまう。
        guard model?.phase.isConnected == true else {
            Task { @MainActor in
                await self.model?.shutdown()
                NSApp.reply(toApplicationShouldTerminate: true)
            }
            return .terminateLater
        }

        let alert = NSAlert()
        alert.messageText = "VPN につながったままです"
        alert.informativeText = "終了する前に VPN を切りますか？\n「つないだまま終了」を選ぶと、アプリを閉じても通信は日本を経由したままになります。"
        alert.addButton(withTitle: "切って終了")
        alert.addButton(withTitle: "つないだまま終了")
        alert.addButton(withTitle: "やめる")
        let r = alert.runModal()
        if r == .alertThirdButtonReturn { return .terminateCancel }
        if r == .alertFirstButtonReturn {
            Task { @MainActor in
                let stopped = await self.model?.shutdown() ?? false
                NSApp.reply(toApplicationShouldTerminate: stopped)
            }
            return .terminateLater
        }
        return .terminateNow
    }
}
