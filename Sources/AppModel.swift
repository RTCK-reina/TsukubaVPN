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
    /// 「このサーバーで実際に見られた／弾かれた」の記録。
    /// 配信サービスにブロックされているかは接続の成否では分からないので、人間に教えてもらうしかない。
    @Published private(set) var watchedOK: Set<String> = []
    @Published private(set) var watchedNG: Set<String> = []
    private let okKey = "watchedOK", ngKey = "watchedNG"

    private var recentFailures: [String: Date] = [:]
    private let failureCooldown: TimeInterval = 600

    private let ctl = VPNController.shared
    /// 常駐 openvpn を管理ソケット越しに操作する係。root 権限は要らない。
    private let session = VPNSession()
    /// 常駐 openvpn が生きていて、管理ソケットもつながっているか
    @Published var daemonReady = false

    private func loadWatched() {
        watchedOK = Set(UserDefaults.standard.stringArray(forKey: okKey) ?? [])
        watchedNG = Set(UserDefaults.standard.stringArray(forKey: ngKey) ?? [])
    }
    private func saveWatched() {
        UserDefaults.standard.set(Array(watchedOK), forKey: okKey)
        UserDefaults.standard.set(Array(watchedNG), forKey: ngKey)
    }
    func markWatchable(_ s: VPNServer, ok: Bool) {
        if ok { watchedOK.insert(s.hostName); watchedNG.remove(s.hostName) }
        else { watchedNG.insert(s.hostName); watchedOK.remove(s.hostName) }
        saveWatched()
    }
    func watchMark(_ s: VPNServer) -> String? {
        if watchedOK.contains(s.hostName) { return "見られた" }
        if watchedNG.contains(s.hostName) { return "ダメだった" }
        return nil
    }

    /// 並び順の最終スコア。素の rank に、人間が教えてくれた実績を強く足し引きする。
    func score(_ s: VPNServer) -> Double {
        var v = s.rank
        if watchedOK.contains(s.hostName) { v += 400 }
        if watchedNG.contains(s.hostName) { v -= 600 }
        if isRecentlyFailed(s) { v -= 300 }
        return v
    }

    // MARK: - 起動時
    func bootstrap() async {
        loadWatched()
        dnsIssue = ctl.dnsIssue()
        session.onDropped = { [weak self] in
            Task { @MainActor in
                guard let self, self.phase.isConnected else { return }
                self.connectedServer = nil
                self.phase = .failed("サーバー側から切断されました。もう一度「つなぐ」を押してください。")
            }
        }
        // 前回の openvpn がまだ常駐していれば、パスワードなしでつなぎ直す
        if ctl.isRunning(), session.attach(port: ctl.currentMgmtPort(), password: ctl.mgmtPassword) {
            daemonReady = true
            if ctl.dnsBackupExists() {
                phase = .connected
                progressText = "前回の接続が続いています"
            }
        }
        dnsNeedsRestore = ctl.dnsBackupExists() && !phase.isConnected
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
            servers = list
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
        return list.sorted { score($0) > score($1) }
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
        // 保険枠も、ブロックされにくい個人サーバーの空いているものから採る
        let roomy = pool.filter { $0.speedMbps >= 8 && !$0.isOfficial && !isRecentlyFailed($0) && !watchedNG.contains($0.hostName) }
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

    /// 接続。root（管理者パスワード）が要るのは openvpn を常駐させる最初の一度だけで、
    /// 以後の乗り換え・切断・再接続は管理インターフェース経由なので何も聞かれない。
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

        if !(ctl.isRunning() && session.isAttached) {
            guard await startDaemon(openvpn: ov, using: picks) else { return }
        }

        phase = .connecting
        progressText = "つないでいます…"
        let total = picks.count
        session.onProgress = { [weak self] n, s in
            Task { @MainActor in
                guard let self else { return }
                self.progressText = "\(total)件中 \(n)件目を試しています… （\(s.flag) \(s.countryJa) / \(s.ip) / \(s.protoWord)）"
            }
        }
        let outcome = await session.connect(candidates: picks)
        session.onProgress = nil

        switch outcome {
        case .connected(let s):
            connectedServer = s
            recentFailures[s.ip] = nil
            // 採用されたものより前の候補は失敗しているので記録する
            if let i = picks.firstIndex(where: { $0.id == s.id }), i >= 1 {
                for k in 0..<i { recentFailures[picks[k].ip] = Date() }
            }
            phase = .connected
            progressText = ""
            dnsIssue = ctl.dnsIssue()
            await refreshIP()
            dnsNeedsRestore = false
        case .exhausted:
            for s in picks { recentFailures[s.ip] = Date() }
            let raw = ctl.recentLog()
            logText = raw
            phase = .failed(connectFailureMessage(log: raw, tried: picks.count))
            progressText = ""
            dnsNeedsRestore = ctl.dnsBackupExists()
        case .error(let m):
            logText = ctl.recentLog()
            daemonReady = ctl.isRunning() && session.isAttached
            phase = .failed("\(m)。もう一度「つなぐ」を押してください。")
            progressText = ""
            dnsNeedsRestore = ctl.dnsBackupExists() && !phase.isConnected
        }
    }

    /// openvpn を常駐起動する。ここでだけ管理者パスワードを求める。
    private func startDaemon(openvpn ov: String, using picks: [VPNServer]) async -> Bool {
        guard let sample = picks.compactMap({ VPNGateAPI.decodeConfig($0.configBase64) }).first else {
            phase = .failed("サーバー設定を読み取れませんでした。「一覧を更新」を押してやり直してください。")
            progressText = ""
            return false
        }
        session.detach()
        daemonReady = false
        do {
            try ctl.prepareDaemon(sampleConfig: sample, openvpn: ov)
        } catch {
            phase = .failed("準備に失敗しました: \(error.localizedDescription)")
            progressText = ""
            return false
        }
        phase = .connecting
        progressText = "Mac のパスワードを1回だけ入力してください（次からは聞かれません）"
        let script = ctl.daemonURL.path
        let (ok, msg) = await Task.detached(priority: .userInitiated) { () -> (Bool, String) in
            VPNController.elevate(script: script)
        }.value
        if !ok && msg == "CANCELLED" {
            phase = .failed("パスワードの入力がキャンセルされました。")
            progressText = ""
            return false
        }
        guard ctl.isRunning() else {
            let r = ctl.daemonResult()
            logText = ctl.recentLog()
            phase = .failed(r == "BAD_PROFILE"
                ? "接続用の設定を作れませんでした。「一覧を更新」を押してからやり直してください。"
                : "OpenVPN を起動できませんでした。「接続ログを見る」で内容を確認してください。")
            progressText = ""
            return false
        }
        guard session.attach(port: ctl.currentMgmtPort(), password: ctl.mgmtPassword) else {
            phase = .failed("OpenVPN の管理接続に失敗しました。もう一度お試しください。")
            progressText = ""
            return false
        }
        daemonReady = true
        return true
    }

    private func connectFailureMessage(log raw: String, tried: Int) -> String {
        if raw.contains("--up/--down command failed") || raw.contains("Failed running command (--up)") {
            return "DNS設定の切り替えに失敗したため接続を中断しました。「くわしい設定 → DNS設定を元に戻す」を押してからやり直してください。"
        }
        if raw.contains("auth-failure") || raw.contains("AUTH_FAILED") {
            return "サーバーが混んでいて断られました。少し待つか、上の国を変えてもう一度お試しください。"
        }
        if raw.contains("Cannot allocate TUN") {
            return "仮想ネットワークを作れませんでした。Mac を再起動してからもう一度お試しください。"
        }
        return "\(tried)台試しましたが、どれもつながりませんでした。「一覧を更新」を押してからもう一度お試しください。"
    }

    // MARK: - 切断

    /// 切断する。openvpn は待機状態で常駐させたままにするので、次につなぐときも
    /// パスワードは聞かれない。DNS は down.sh が元に戻す。
    @discardableResult
    func disconnect() async -> Bool {
        phase = .disconnecting
        progressText = "切断しています…"
        var ok = await session.hold()
        if !ok {
            // 管理ソケットが効かないときの最後の手段（ここはパスワードが要る）
            let c = ctl
            ok = await Task.detached(priority: .userInitiated) { () -> Bool in
                _ = c.managementSignalTerm()
                for _ in 0..<20 {
                    if !c.isRunning() { break }
                    usleep(300_000)
                }
                if c.isRunning() { _ = VPNController.elevate(script: c.stopURL.path) }
                return !c.isRunning()
            }.value
            if ok {
                session.detach()
                daemonReady = false
            }
        }
        guard ok else {
            phase = .failed("VPN を切断できませんでした。接続ログを確認して、もう一度お試しください。")
            progressText = ""
            logText = ctl.recentLog()
            dnsNeedsRestore = ctl.dnsBackupExists()
            return false
        }
        connectedServer = nil
        phase = .idle
        progressText = ""
        dnsIssue = ctl.dnsIssue()
        dnsNeedsRestore = ctl.dnsBackupExists()
        await refreshIP()
        if dnsNeedsRestore {
            phase = .failed("VPN は切れましたが、DNS 設定を元に戻せませんでした。「元に戻す」を押してください。")
            return false
        }
        return true
    }

    /// アプリ終了時に常駐 openvpn ごと片付ける。root は要らない。
    @discardableResult
    func shutdown() async -> Bool {
        session.terminate()
        for _ in 0..<25 {
            if !ctl.isRunning() { break }
            try? await Task.sleep(nanoseconds: 200_000_000)
        }
        daemonReady = false
        if ctl.isRunning() {
            let c = ctl
            return await Task.detached(priority: .userInitiated) { () -> Bool in
                _ = VPNController.elevate(script: c.stopURL.path)
                return !c.isRunning()
            }.value
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
        dnsNeedsRestore = ctl.dnsBackupExists() && !phase.isConnected
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
