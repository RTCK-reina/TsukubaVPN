import SwiftUI
import Combine

struct ContentView: View {
    @EnvironmentObject var m: AppModel

    var body: some View {
        VStack(spacing: 0) {
            StatusHeader()
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if m.openvpnPath == nil { OpenVPNMissingCard() }
                    if m.dnsNeedsRestore { DNSRestoreCard() }
                    if let issue = m.dnsIssue, !m.dnsNeedsRestore { DNSIssueCard(reason: issue) }
                    if let msg = m.phase.failMessage { FailCard(message: msg) }
                    CountryChips()
                    TargetCard()
                    if m.showList { ServerList() }
                    AdvancedSection()
                }
                .padding(20)
            }
            Divider()
            BottomBar()
        }
        .frame(minWidth: 760, minHeight: 680)
        .task { await m.bootstrap() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            Task { await m.refreshIfStale() }
        }
        .sheet(isPresented: $m.showLog) { LogSheet() }
    }
}

// MARK: - ヘッダ

struct StatusHeader: View {
    @EnvironmentObject var m: AppModel
    var body: some View {
        HStack(spacing: 18) {
            ZStack {
                Circle().fill(m.phase.color.opacity(0.16)).frame(width: 68, height: 68)
                if m.phase.isBusy {
                    ProgressView().controlSize(.large)
                } else {
                    Image(systemName: m.phase.icon)
                        .font(.system(size: 30, weight: .bold))
                        .foregroundStyle(m.phase.color)
                }
            }
            VStack(alignment: .leading, spacing: 5) {
                Text(m.phase.title).font(.system(size: 30, weight: .heavy))
                Text(detail)
                    .font(.system(size: 14))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 12)
            VStack(alignment: .trailing, spacing: 3) {
                Text("いまの見た目のIP").font(.caption).foregroundStyle(.secondary)
                HStack(spacing: 6) {
                    if m.checkingIP { ProgressView().controlSize(.small).scaleEffect(0.7) }
                    Text(m.myIP.isEmpty ? "確認中…" : m.myIP)
                        .font(.system(size: 16, weight: .semibold, design: .monospaced))
                        .textSelection(.enabled)
                }
                if !m.myCountryText.isEmpty {
                    Text(m.myCountryText).font(.system(size: 13)).foregroundStyle(.secondary)
                }
            }
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 20)
        .background(m.phase.color.opacity(0.09))
    }

    private var detail: String {
        if !m.progressText.isEmpty { return m.progressText }
        switch m.phase {
        case .connected:
            if let s = m.connectedServer {
                return "\(s.flag) \(s.countryJa) のサーバー（\(s.ip)）を通ってインターネットに出ています"
            }
            return "VPN を通ってインターネットに出ています"
        case .idle:
            return "いつものインターネット回線をそのまま使っています"
        case .failed:
            return "下のボタンでもう一度お試しください"
        default:
            return ""
        }
    }
}

// MARK: - カード類

struct CardBox<Content: View>: View {
    var tint: Color = .secondary
    @ViewBuilder var content: Content
    var body: some View {
        content
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 12).fill(tint.opacity(0.10)))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(tint.opacity(0.30), lineWidth: 1))
    }
}

struct OpenVPNMissingCard: View {
    @EnvironmentObject var m: AppModel
    var body: some View {
        CardBox(tint: .orange) {
            HStack(spacing: 12) {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange).font(.title2)
                VStack(alignment: .leading, spacing: 3) {
                    Text("OpenVPN がまだ入っていません").font(.headline)
                    Text("接続に必要な部品です。ボタンを押すと自動で入ります。").font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                Button(m.installing ? "入れています…" : "OpenVPN を入れる") {
                    Task { await m.installOpenVPN() }
                }
                .disabled(m.installing)
                .controlSize(.large)
            }
        }
    }
}

struct DNSRestoreCard: View {
    @EnvironmentObject var m: AppModel
    var body: some View {
        CardBox(tint: .yellow) {
            HStack(spacing: 12) {
                Image(systemName: "wifi.exclamationmark").foregroundStyle(.yellow).font(.title2)
                VStack(alignment: .leading, spacing: 3) {
                    Text("DNS設定が VPN 用のままです").font(.headline)
                    Text("ネットがつながりにくいときは、ここを押すと元に戻ります。").font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                Button("元に戻す") { Task { await m.restoreDNS() } }.controlSize(.large)
            }
        }
    }
}

/// 接続はできているが DNS の切り替えに失敗した、という状態を伝えるカード。
/// 接続を巻き添えにしない代わりに、気づけるようにここで必ず知らせる。
struct DNSIssueCard: View {
    let reason: String
    @EnvironmentObject var m: AppModel
    var body: some View {
        CardBox(tint: .yellow) {
            HStack(spacing: 12) {
                Image(systemName: "exclamationmark.circle.fill").foregroundStyle(.yellow).font(.title2)
                VStack(alignment: .leading, spacing: 3) {
                    Text("つながっていますが、DNSは元のままです").font(.headline)
                    Text("\(reason)。見ているサイトの名前だけは、いつもの回線側に残ります。")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                Button("ログを見る") { m.loadLog() }
            }
        }
    }
}

struct FailCard: View {
    let message: String
    @EnvironmentObject var m: AppModel
    var body: some View {
        CardBox(tint: .red) {
            HStack(spacing: 12) {
                Image(systemName: "xmark.octagon.fill").foregroundStyle(.red).font(.title2)
                Text(message).font(.callout).fixedSize(horizontal: false, vertical: true)
                Spacer()
                Button("ログを見る") { m.loadLog() }
            }
        }
    }
}

// MARK: - 国えらび

struct CountryChips: View {
    @EnvironmentObject var m: AppModel
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("① どこの国のサーバーを使う？").font(.system(size: 17, weight: .bold))
            HStack(spacing: 10) {
                ForEach(m.topCountries, id: \.self) { code in
                    chip(title: "\(Country.flag(code)) \(Country.ja(code) ?? code)",
                         sub: "\(m.servers.filter { $0.countryShort == code }.count)台",
                         selected: m.country == code) {
                        m.country = code; m.manualPick = nil
                    }
                }
                chip(title: "🌏 ぜんぶ", sub: "\(m.servers.count)台", selected: m.country == "ALL") {
                    m.country = "ALL"; m.manualPick = nil
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 2) {
                    Button {
                        Task { await m.refresh() }
                    } label: {
                        Label(m.loading ? "更新中…" : "一覧を更新", systemImage: "arrow.clockwise")
                    }
                    .disabled(m.loading)
                    Text(m.listAgeText)
                        .font(.system(size: 10))
                        .foregroundStyle(m.listIsStale ? Color.orange : Color.secondary)
                }
            }
            if let e = m.loadError {
                Text(e).font(.callout).foregroundStyle(.red)
            }
        }
    }

    @ViewBuilder
    private func chip(title: String, sub: String, selected: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(spacing: 2) {
                Text(title).font(.system(size: 16, weight: .semibold))
                Text(sub).font(.system(size: 11)).foregroundStyle(selected ? .white.opacity(0.85) : .secondary)
            }
            .frame(minWidth: 104)
            .padding(.vertical, 9)
            .background(RoundedRectangle(cornerRadius: 10).fill(selected ? Color.accentColor : Color.gray.opacity(0.16)))
            .foregroundStyle(selected ? Color.white : Color.primary)
        }
        .buttonStyle(.plain)
    }
}

// MARK: - つなぎ先

struct TargetCard: View {
    @EnvironmentObject var m: AppModel
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("② これにつなぎます").font(.system(size: 17, weight: .bold))
            CardBox(tint: m.manualPick == nil ? .green : .blue) {
                HStack(spacing: 14) {
                    if let s = m.plannedServer {
                        Text(s.flag).font(.system(size: 34))
                        VStack(alignment: .leading, spacing: 4) {
                            HStack(spacing: 8) {
                                Text(s.countryJa).font(.system(size: 19, weight: .bold))
                                Stars(count: s.stars)
                                if m.manualPick == nil {
                                    Text("おすすめ").font(.caption2).padding(.horizontal, 7).padding(.vertical, 2)
                                        .background(Capsule().fill(Color.green.opacity(0.25)))
                                }
                            }
                            Text("速さ \(s.speedText)（\(s.speedWord)） ・ 反応 \(s.pingText) ・ \(s.crowdWord) ・ \(s.ip)")
                                .font(.system(size: 13)).foregroundStyle(.secondary)
                            if m.candidates.count > 1 {
                                Text("うまくいかない時は自動で他の\(m.candidates.count - 1)台も順に試します")
                                    .font(.system(size: 12)).foregroundStyle(.secondary)
                            }
                        }
                        Spacer()
                        VStack(spacing: 6) {
                            Button(m.showList ? "閉じる" : "自分でえらぶ") { m.showList.toggle() }
                                .controlSize(.large)
                            if m.manualPick != nil {
                                Button("おすすめに戻す") { m.manualPick = nil }.font(.caption)
                            }
                        }
                    } else if m.loading {
                        ProgressView()
                        Text("サーバー一覧を読み込んでいます…").foregroundStyle(.secondary)
                    } else {
                        Text("使えるサーバーが見つかりません。「一覧を更新」を押してください。").foregroundStyle(.secondary)
                    }
                }
            }
        }
    }
}

struct Stars: View {
    let count: Int
    var body: some View {
        HStack(spacing: 1) {
            ForEach(0..<5, id: \.self) { i in
                Image(systemName: i < count ? "star.fill" : "star")
                    .font(.system(size: 11))
                    .foregroundStyle(i < count ? Color.orange : Color.secondary.opacity(0.4))
            }
        }
    }
}

// MARK: - サーバー一覧

struct ServerList: View {
    @EnvironmentObject var m: AppModel
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("上にあるほど速くて安定しています").font(.caption).foregroundStyle(.secondary)
            ScrollView {
                LazyVStack(spacing: 4) {
                    ForEach(m.filtered.prefix(60)) { s in
                        Button {
                            m.manualPick = s
                            m.showList = false
                        } label: {
                            HStack(spacing: 12) {
                                Text(s.flag).font(.system(size: 22))
                                Text(s.countryJa).font(.system(size: 14, weight: .semibold)).frame(width: 92, alignment: .leading)
                                Stars(count: s.stars).frame(width: 74, alignment: .leading)
                                Text(s.speedText).font(.system(size: 13, design: .monospaced)).frame(width: 92, alignment: .trailing)
                                Text(s.pingText).font(.system(size: 13, design: .monospaced)).frame(width: 62, alignment: .trailing)
                                Text(s.crowdWord).font(.system(size: 12)).frame(width: 64, alignment: .trailing)
                                    .foregroundStyle(s.sessions <= 45 ? Color.secondary : Color.orange)
                                Text(s.ip).font(.system(size: 12, design: .monospaced)).foregroundStyle(.secondary)
                                Spacer()
                                if m.manualPick?.id == s.id {
                                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.blue)
                                }
                            }
                            .padding(.horizontal, 10).padding(.vertical, 7)
                            .background(RoundedRectangle(cornerRadius: 8)
                                .fill(m.manualPick?.id == s.id ? Color.accentColor.opacity(0.18) : Color.gray.opacity(0.08)))
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.trailing, 4)
            }
            .frame(height: 260)
        }
    }
}

// MARK: - くわしい設定

struct AdvancedSection: View {
    @EnvironmentObject var m: AppModel
    var body: some View {
        DisclosureGroup(isExpanded: $m.showAdvanced) {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 10) {
                    Button("接続ログを見る") { m.loadLog() }
                    Button("DNS設定を元に戻す") { Task { await m.restoreDNS() } }
                    Button("作業フォルダを開く") {
                        NSWorkspace.shared.open(URL(fileURLWithPath: m.supportDirPath))
                    }
                }
                Divider().padding(.vertical, 2)
                HStack(spacing: 10) {
                    Button(m.selfTestRunning ? "テスト中…" : "接続テスト（通信は切り替えません）") {
                        Task { await m.runSelfTest() }
                    }
                    .disabled(m.selfTestRunning || m.phase.isBusy || m.phase.isConnected)
                    Text("トンネルが張れるかだけを確認します。今の通信経路もDNSも変えないので、リモート作業中でも安全です。")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if !m.selfTestResult.isEmpty {
                    Text(m.selfTestResult)
                        .font(.system(size: 12, design: .monospaced))
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(RoundedRectangle(cornerRadius: 8)
                            .fill((m.selfTestOK == true ? Color.green : (m.selfTestOK == false ? Color.red : Color.gray)).opacity(0.12)))
                }
                Text("OpenVPN: \(m.openvpnPath ?? "未検出")")
                    .font(.system(size: 12, design: .monospaced)).foregroundStyle(.secondary)
                Text("接続先は VPN Gate（筑波大学の学術実験プロジェクト）が公開しているボランティア運営の公開VPNサーバーです。通信内容はサーバー運営者に記録される可能性があります。ログインやカード情報など重要な通信には使わないでください。")
                    .font(.system(size: 12)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.top, 8)
        } label: {
            Text("くわしい設定・注意事項").font(.system(size: 15, weight: .semibold))
        }
    }
}

struct LogSheet: View {
    @EnvironmentObject var m: AppModel
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("接続ログ").font(.title2.bold())
            ScrollView {
                Text(m.logText.isEmpty ? "（ログはまだありません）" : m.logText)
                    .font(.system(size: 11, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(width: 720, height: 420)
            .background(RoundedRectangle(cornerRadius: 8).fill(Color.gray.opacity(0.10)))
            HStack {
                Spacer()
                Button("閉じる") { m.showLog = false }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(18)
    }
}

// MARK: - 下部の巨大ボタン

struct BottomBar: View {
    @EnvironmentObject var m: AppModel
    var body: some View {
        VStack(spacing: 8) {
            Button {
                Task {
                    if m.phase.isConnected { _ = await m.disconnect() } else { await m.connect() }
                }
            } label: {
                Text(buttonTitle)
                    .font(.system(size: 27, weight: .heavy))
                    .frame(maxWidth: .infinity, minHeight: 60)
            }
            .buttonStyle(.borderedProminent)
            .tint(m.phase.isConnected ? .red : .green)
            .controlSize(.large)
            .disabled(m.phase.isBusy || m.installing || (!m.phase.isConnected && m.plannedServer == nil))

            Text(note).font(.system(size: 12)).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 16)
    }

    private var buttonTitle: String {
        if m.phase.isBusy { return "しばらくお待ちください…" }
        return m.phase.isConnected ? "VPN を 切 る" : "V P N に つ な ぐ"
    }
    private var note: String {
        if m.phase.isConnected { return "切ると、いつものインターネット回線に戻ります。" }
        return "つなぐときに Mac のパスワードを1回だけ聞かれます。それだけで大丈夫です。"
    }
}
