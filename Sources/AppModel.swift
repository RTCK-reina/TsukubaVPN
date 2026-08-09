import Foundation
import Combine
import SwiftUI

@MainActor
final class AppModel: ObservableObject {

    @Published var servers: [VPNServer] = []
    @Published var loading = false
    @Published var loadError: String?
    @Published var country: String = "JP"
    @Published var manualPick: VPNServer?
    @Published var phase: VPNPhase = .idle
    @Published var progressText: String = ""
    @Published var myIP: String = ""
    @Published var myCountryCode: String = ""
    @Published var connectedServer: VPNServer?
    @Published var showList = false
    @Published var showAdvanced = false
    @Published var openvpnPath: String? = VPNController.findOpenVPN()
    @Published var installing = false
    @Published var dnsNeedsRestore = false
    @Published var logText: String = ""
    @Published var showLog = false
    @Published var checkingIP = false
    @Published var selfTestRunning = false
    @Published var selfTestResult = ""
    @Published var selfTestOK: Bool? = nil
    /// DNS の切り替え／復元に失敗したときの理由。接続自体は生きている。
    @Published var dnsIssue: String?
    /// サーバー一覧を最後に取得できた時刻
    @Published var lastFetched: Date?

    /// 直近に失敗したサーバー（10分間は後回しにする）。混雑・拒否されたサーバーを掴み続けないため。
    private var recentFailures: [String: Date] = [:]
    private let failureCooldown: TimeInterval = 600

    private let ctl = VPNController.shared
    private var pollTask: Task<Void, Never>?

    // MARK: - 起動時
    func bootstrap() async {
        dnsNeedsRestore = ctl.dnsNeedsRestore()
        dnsIssue = ctl.dnsIssue()
        if ctl.isRunning() {
            phase = .connected
            progressText = "前回の接続が続いています"
        }
        await refresh()
        await refreshIP()
    }

    // MARK: - サーバ一覧
    func refresh() async {
        guard !loading else { return }
        loading = true
        loadError = nil
        do {
            let list = try await VPNGateAPI.fetch()
            servers = list.sorted { $0.rank > $1.rank }
            if servers.first(where: { $0.countryShort == country }) == nil {
                country = topCountries.first ?? "ALL"
            }
            if let p = manualPick, !servers.contains(where: { $0.id == p.id }) { manualPick = nil }
            lastFetched = Date()
        } catch {
            loadError = "サーバー一覧を取得できませんでした。ネットワークを確認してもう一度お試しください。"
        }
        loading = false
    }

    /// 一覧が古いか（未取得なら古い扱い）
    var listIsStale: Bool {
        guard let t = lastFetched else { return true }
        return Date().timeIntervalSince(t) >= VPNPolicy.listStaleAfter
    }

    var listAgeText: String {
        guard let t = lastFetched else { return "サーバー一覧: 未取得" }
        let m = Int(Date().timeIntervalSince(t) / 60)
        if m <= 0 { return "サーバー一覧: さっき更新" }
        if m < 60 { return "サーバー一覧: \(m)分前" }
        return "サーバー一覧: \(m / 60)時間前"
    }

    /// 一覧が古いときだけ取り直す。接続中・取得中は何もしない。
    /// 公開VPNは住所が変わるので、古い一覧のまま接続すると「全台死んでいる」ように見える。
    func refreshIfStale() async {
        guard !loading, !phase.isBusy, !phase.isConnected, listIsStale else { return }
        await refresh()
    }

    var topCountries: [String] {
        var counts: [String: Int] = [:]
        for s in servers { counts[s.countryShort, default: 0] += 1 }
        var order = counts.sorted { $0.value > $1.value }.map { $0.key }
        if let i = order.firstIndex(of: "JP") { order.remove(at: i); order.insert("JP", at: 0) }
        return Array(order.prefix(3))
    }

    func isRecentlyFailed(_ s: VPNServer) -> Bool {
        guard let d = recentFailures[s.ip] else { return false }
        return Date().timeIntervalSince(d) < failureCooldown
    }

    var filtered: [VPNServer] {
        let list = country == "ALL" ? servers : servers.filter { $0.countryShort == country }
        return list.sorted { a, b in
            let fa = isRecentlyFailed(a), fb = isRecentlyFailed(b)
            if fa != fb { return !fa }
            return a.rank > b.rank
        }
    }

    /// 実際に使う候補（1番目 = メイン、以降は自動フォールバック用）。
    /// 公開VPNは個々のサーバーが落ちていることが珍しくないので、余裕をもって5台まで用意する。
    static let candidateCount = VPNPolicy.candidateCount

    var candidates: [VPNServer] {
        var out: [VPNServer] = []
        func add(_ s: VPNServer) {
            guard !out.contains(where: { $0.id == s.id }) else { return }
            out.append(s)
        }
        if let p = manualPick { add(p) }
        let pool = filtered
        // まず総合評価の上位から3台
        for s in pool {
            if out.count >= 3 { break }
            add(s)
        }
        // 次に「空いている」サーバーを混ぜる。混雑で断られたときの保険になる。
        let roomy = pool.filter { $0.speedMbps >= 8 && !isRecentlyFailed($0) }
            .sorted { $0.sessions < $1.sessions }
        for s in roomy {
            if out.count >= AppModel.candidateCount { break }
            add(s)
        }
        for s in pool {
            if out.count >= AppModel.candidateCount { break }
            add(s)
        }
        return out
    }

    var plannedServer: VPNServer? { candidates.first }

    // MARK: - 接続
    func connect() async {
        guard let ov = openvpnPath ?? VPNController.findOpenVPN() else {
            phase = .failed("OpenVPN が見つかりません。下の「OpenVPN を入れる」を押してください。")
            return
        }
        openvpnPath = ov
        // 古い一覧のまま接続すると存在しない住所へ発信してしまうので、先に取り直す
        if listIsStale {
            progressText = "サーバー一覧を最新にしています…"
            await refresh()
        }
        let picks = candidates
        guard !picks.isEmpty else {
            phase = .failed("使えるサーバーが見つかりませんでした。")
            return
        }
        phase = .preparing
        progressText = "準備しています…"
        connectedServer = nil

        var cands: [Candidate] = []
        for s in picks {
            if let cfg = VPNGateAPI.decodeConfig(s.configBase64) { cands.append(Candidate(server: s, config: cfg)) }
        }
        guard !cands.isEmpty else {
            phase = .failed("サーバー設定を読み取れませんでした。更新ボタンを押してやり直してください。")
            return
        }
        let accepted: [Candidate]
        do {
            accepted = try ctl.prepare(candidates: cands, openvpn: ov)
        } catch {
            phase = .failed("準備に失敗しました: \(error.localizedDescription)")
            progressText = ""
            return
        }

        phase = .connecting
        progressText = "Mac のパスワードを入力してください（1回だけ）"

        let scriptPath = ctl.runURL.path
        let elevateTask = Task.detached(priority: .userInitiated) { () -> (Bool, String) in
            VPNController.elevate(script: scriptPath)
        }
        startPolling(candidates: accepted.map { $0.server })
        let (ok, msg) = await elevateTask.value
        pollTask?.cancel()
        pollTask = nil

        if !ok && msg == "CANCELLED" {
            phase = .failed("パスワードの入力がキャンセルされました。")
            progressText = ""
            return
        }

        let (_, success, idx) = ctl.readResult()
        if success && ctl.isRunning() {
            let s = (idx >= 1 && idx <= accepted.count) ? accepted[idx - 1].server : accepted[0].server
            connectedServer = s
            recentFailures[s.ip] = nil
            // 採用されたものより前の候補は失敗しているので記録する
            if idx >= 2 {
                for k in 0..<(idx - 1) where k < accepted.count { recentFailures[accepted[k].server.ip] = Date() }
            }
            phase = .connected
            progressText = ""
            dnsIssue = ctl.dnsIssue()
            await refreshIP()
            dnsNeedsRestore = false
        } else {
            let raw = ctl.recentLog()
            let (_, _, _) = ctl.readResult()
            for c in accepted { recentFailures[c.server.ip] = Date() }
            let portBusy = raw.contains("Socket bind failed")
                || (try? String(contentsOf: ctl.resultURL, encoding: .utf8))?.contains("PORT_BUSY") == true
            let refused = raw.contains("auth-failure") || raw.contains("AUTH_FAILED")
            let scriptFailed = raw.contains("--up/--down command failed") || raw.contains("Failed running command (--up)")
            let busy = (try? String(contentsOf: ctl.resultURL, encoding: .utf8))?.contains("BUSY") == true
            let msg: String
            if scriptFailed {
                msg = "DNS設定の切り替えに失敗したため接続を中断しました。「くわしい設定 → DNS設定を元に戻す」を押してからやり直してください。"
            } else if busy {
                msg = "前回の接続処理がまだ動いています。少し待ってからもう一度お試しください。"
            } else if portBusy {
                msg = "通信用のポートがふさがっていました。もう一度ボタンを押してください（自動で別のポートを使います）。"
            } else if refused {
                msg = "サーバーが混んでいて断られました。少し待つか、上の国を変えてもう一度お試しください。"
            } else {
                msg = "\(accepted.count)台試しましたが、どれもつながりませんでした。「一覧を更新」を押してからもう一度お試しください。"
            }
            phase = .failed(msg)
            progressText = ""
            logText = raw
            dnsNeedsRestore = ctl.dnsNeedsRestore()
        }
    }

    private func startPolling(candidates: [VPNServer]) {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 600_000_000)
                guard let self else { return }
                let n = self.ctl.currentAttempt()
                if n >= 1 && n <= candidates.count {
                    let s = candidates[n - 1]
                    self.progressText = "\(candidates.count)件中 \(n)件目を試しています… （\(s.flag) \(s.countryJa) / \(s.ip)）"
                }
            }
        }
    }

    // MARK: - 切断
    @discardableResult
    func disconnect() async -> Bool {
        phase = .disconnecting
        progressText = "切断しています…"
        let c = ctl
        let (stopped, detail) = await Task.detached(priority: .userInitiated) { () -> (Bool, String) in
            _ = c.managementSignalTerm()
            for _ in 0..<20 {
                if !c.isRunning() { break }
                usleep(300_000)
            }
            if c.isRunning() {
                let (ok, message) = VPNController.elevate(script: c.stopURL.path)
                return (!c.isRunning(), ok ? message : "強制停止に失敗しました: \(message)")
            }
            return (true, "")
        }.value
        guard stopped else {
            phase = .failed("VPN を切断できませんでした。接続ログを確認して、もう一度お試しください。")
            progressText = ""
            logText = detail.isEmpty ? ctl.recentLog() : detail + "\n" + ctl.recentLog()
            dnsNeedsRestore = ctl.dnsNeedsRestore()
            return false
        }
        connectedServer = nil
        phase = .idle
        progressText = ""
        dnsNeedsRestore = ctl.dnsNeedsRestore()
        dnsIssue = ctl.dnsIssue()
        await refreshIP()
        if dnsNeedsRestore {
            phase = .failed("VPN は切れましたが、DNS 設定を元に戻せませんでした。「元に戻す」を押してください。")
            return false
        }
        return true
    }

    // MARK: - その他
    func refreshIP() async {
        checkingIP = true
        defer { checkingIP = false }
        if let (ip, code) = await ctl.publicIP() {
            myIP = ip
            myCountryCode = code
        } else if myIP.isEmpty {
            myIP = "わかりません"
            myCountryCode = ""
        }
    }

    var myCountryText: String {
        let c = myCountryCode
        guard !c.isEmpty else { return "" }
        if c.count == 2, let ja = Country.ja(c) { return "\(Country.flag(c)) \(ja)" }
        return c
    }

    func installOpenVPN() async {
        guard let brew = VPNController.brewPath() else {
            phase = .failed("Homebrew が見つかりません。https://brew.sh を先にインストールしてください。")
            return
        }
        installing = true
        progressText = "OpenVPN をインストールしています…（数分かかります）"
        let result = await Task.detached(priority: .userInitiated) { () -> String in
            let (_, out) = VPNController.run(brew, ["install", "openvpn"])
            return out
        }.value
        installing = false
        progressText = ""
        openvpnPath = VPNController.findOpenVPN()
        if openvpnPath == nil {
            phase = .failed("OpenVPN のインストールに失敗しました。")
            logText = result
        } else {
            phase = .idle
        }
    }

    func restoreDNS() async {
        progressText = "DNS設定を元に戻しています…"
        let path = ctl.downURL.path
        let (ok, message) = await Task.detached(priority: .userInitiated) {
            VPNController.elevate(script: path)
        }.value
        dnsNeedsRestore = ctl.dnsNeedsRestore()
        dnsIssue = ctl.dnsIssue()
        progressText = ""
        if !ok || dnsNeedsRestore {
            phase = .failed("DNS 設定を元に戻せませんでした。接続ログを確認してください。")
            logText = message
        } else if !ctl.isRunning() {
            phase = .idle
        }
    }

    /// セーフモード接続テスト。経路もDNSも変えずに、トンネルが張れるかだけを確かめる。
    func runSelfTest() async {
        guard let ov = openvpnPath ?? VPNController.findOpenVPN() else {
            selfTestResult = "OpenVPN が見つかりません。"
            selfTestOK = false
            return
        }
        let testCandidates = candidates.compactMap { server -> Candidate? in
            guard let config = VPNGateAPI.decodeConfig(server.configBase64) else { return nil }
            return Candidate(server: server, config: config)
        }
        guard !testCandidates.isEmpty else {
            selfTestResult = "テストに使えるサーバーがありません。「一覧を更新」を押してください。"
            selfTestOK = false
            return
        }
        selfTestRunning = true
        selfTestOK = nil
        selfTestResult = "テスト中… Mac のパスワードを入力してください"
        defer { selfTestRunning = false }
        let accepted: [Candidate]
        do { accepted = try ctl.prepareSelfTest(candidates: testCandidates, openvpn: ov) }
        catch {
            selfTestResult = "準備に失敗しました: \(error.localizedDescription)"
            selfTestOK = false
            return
        }
        let path = ctl.selfTestURL.path
        let (ok, msg) = await Task.detached(priority: .userInitiated) {
            VPNController.elevate(script: path)
        }.value
        if !ok && msg == "CANCELLED" {
            selfTestResult = "パスワード入力がキャンセルされました。"
            selfTestOK = false
            return
        }
        let r = ctl.selfTestReport()
        let passed = r["result"] == "OK"
        let index = Int(r["index"] ?? "") ?? 1
        let testedServer = accepted.indices.contains(index - 1) ? accepted[index - 1].server : accepted[0].server
        let routeKept = !((r["default_before"] ?? "-").isEmpty) && r["default_before"] == r["default_during"]
        let cleanedUp = r["utun_after"] == r["utun_before"]
        selfTestOK = passed && routeKept && cleanedUp
        var lines: [String] = []
        lines.append(passed
            ? "✅ トンネルを張れました（\(testedServer.flag) \(testedServer.countryJa) / \(testedServer.ip)）"
            : "❌ \(accepted.count)台でトンネルを張れませんでした")
        if let d = r["dev"], !d.isEmpty { lines.append("・作られた仮想ネットワーク: \(d)  内部IP \(r["tunip"] ?? "?")") }
        lines.append(routeKept
            ? "・通信の出口は変更されていません（\(r["default_before"] ?? "?")）＝安全に確認できました"
            : "・注意: 通信の出口が変わりました（\(r["default_before"] ?? "?") → \(r["default_during"] ?? "?")）")
        lines.append(cleanedUp
            ? "・テスト後にきちんと後片付けされました"
            : "・注意: 仮想ネットワークが残っている可能性があります")
        if !passed { lines.append("・詳しくは「接続ログを見る」を確認してください") }
        selfTestResult = lines.joined(separator: "\n")
        if !passed { logText = (try? String(contentsOf: ctl.selfTestLogURL, encoding: .utf8)) ?? ctl.recentLog() }
    }

    func loadLog() {
        logText = ctl.recentLog()
        showLog = true
    }

    var supportDirPath: String { ctl.dir.path }
}

// MARK: - 表示用
extension VPNPhase {
    var title: String {
        switch self {
        case .idle: return "つながっていません"
        case .preparing: return "じゅんび中…"
        case .connecting: return "つないでいます…"
        case .connected: return "つながりました！"
        case .disconnecting: return "切っています…"
        case .failed: return "つながりませんでした"
        }
    }
    var color: Color {
        switch self {
        case .connected: return .green
        case .failed: return .red
        case .idle: return .secondary
        default: return .orange
        }
    }
    var icon: String {
        switch self {
        case .connected: return "lock.shield.fill"
        case .failed: return "exclamationmark.triangle.fill"
        case .idle: return "shield.slash"
        default: return "hourglass"
        }
    }
    var failMessage: String? {
        if case .failed(let m) = self { return m }
        return nil
    }
}
