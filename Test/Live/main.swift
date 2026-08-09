import Foundation

// ルート権限なしで到達できる限界まで、実サーバー相手に本番と同じ経路を通す統合テスト。
//
// dev null を使うことで utun 作成（＝root が必要な唯一の工程）だけを回避し、
// 常駐起動（daemon.sh）→ 管理IFで接続先を指定 → TLS確立 → PUSH_REPLY →
// up スクリプトで DNS 切替 → 別サーバーへ乗り換え → 切断（down で DNS 復元）→
// 待機状態からの再接続 → 完全終了 までを、本番と同一のコード・同一のシェルで検証する。
//
// networksetup はモックに差し替えてあるので、実機の DNS 設定は一切変更しない。

setvbuf(stdout, nil, _IOLBF, 0)
let LIVE = "/tmp/tvpn/live"
let ctl = VPNController.shared
var fail = 0

func check(_ label: String, _ ok: Bool, _ detail: String = "") {
    print("  \(ok ? "OK " : "NG ") \(label)\(detail.isEmpty ? "" : "  → " + detail)")
    if !ok { fail += 1 }
}

func sh(_ cmd: String) -> (Int32, String) { VPNController.run("/bin/sh", ["-c", cmd]) }
func read(_ p: String) -> String { (try? String(contentsOfFile: p, encoding: .utf8)) ?? "" }
func exists(_ p: String) -> Bool { FileManager.default.fileExists(atPath: p) }
func calls() -> String { read(LIVE + "/calls.txt") }
/// Outcome をそのまま文字列化すると証明書ごと出てしまうので、短くまとめる
func desc(_ o: VPNSession.Outcome) -> String {
    switch o {
    case .connected(let s): return "connected(\(s.hostName) \(s.ip):\(s.port)/\(s.protoWord))"
    case .exhausted: return "exhausted"
    case .error(let m): return "error(\(m))"
    }
}
func clearCalls() { try? FileManager.default.removeItem(atPath: LIVE + "/calls.txt") }

/// 失敗時に openvpn が何を言ったかを1行で要約する
func lastErrors() -> String {
    let body = read(ctl.logURL.path)
    let ls = body.normalizedLines.filter { !$0.isEmpty }
    let hit = ls.last { $0.contains("rror") || $0.contains("ailed") || $0.contains("Exiting")
        || $0.contains("AUTH") || $0.contains("reset") }
    return "[" + (hit ?? ls.suffix(1).first ?? "") + "]"
}

/// networksetup を偽物に差し替える。実機の DNS には触れない。
func installMocks() {
    let fake = LIVE + "/fakens"
    let body = """
    #!/bin/sh
    echo "$@" >> \(LIVE)/calls.txt
    case "$1" in
      -listallnetworkservices) printf 'An asterisk (*) denotes...\\nWi-Fi\\niPhone USB\\n';;
      -getdnsservers) if [ "$2" = "Wi-Fi" ]; then echo "192.168.11.1"; else echo "There aren't any DNS Servers set on iPhone USB."; fi;;
      -setdnsservers) if [ -f \(LIVE)/dnsfail ]; then exit 1; fi;;
    esac
    exit 0
    """
    try? body.write(toFile: fake, atomically: true, encoding: .utf8)
    try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: fake)
    for f in ["up.sh", "down.sh"] {
        let p = ctl.dir.appendingPathComponent(f).path
        var s = read(p)
        s = s.replacingOccurrences(of: "NS=/usr/sbin/networksetup", with: "NS=\(fake)")
        s = s.replacingOccurrences(of: "/usr/bin/dscacheutil -flushcache 2>/dev/null", with: "true")
        s = s.replacingOccurrences(of: "/usr/bin/killall -HUP mDNSResponder 2>/dev/null", with: "true")
        try? s.write(toFile: p, atomically: true, encoding: .utf8)
        try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: p)
    }
}

/// 共通プロファイルを dev null 化する。utun を作らないので root が要らなくなる。
/// 経路も引かないので、このテストは実行中の通信にまったく影響しない。
func devNullProfile() {
    let p = ctl.sharedURL.path
    var s = read(p)
    guard VPNController.sharedProfileIsValid(s) else {
        print("  !! shared.ovpn を読めなかった（\(s.utf8.count) bytes）。テスト条件が壊れている")
        fail += 1
        return
    }
    s = s.replacingOccurrences(of: "\ndev tun\n", with: "\ndev null\n")
    s += "route-nopull\n"
    try? s.write(toFile: p, atomically: true, encoding: .utf8)
    if !read(p).contains("dev null") {
        print("  !! shared.ovpn の書き戻しに失敗")
        fail += 1
    }
}

let sem = DispatchSemaphore(value: 0)
Task {
    defer { sem.signal() }
    try? FileManager.default.removeItem(atPath: LIVE)
    try? FileManager.default.createDirectory(atPath: LIVE, withIntermediateDirectories: true)

    guard let ov = VPNController.findOpenVPN() else { print("openvpn なし"); fail += 1; return }
    let cc = CommandLine.arguments.dropFirst().first ?? "JP"
    let all = (try? await VPNGateAPI.fetch()) ?? []
    let servers = all.filter { $0.countryShort == cc }.sorted { $0.rank > $1.rank }
    guard servers.count >= 3 else { print("サーバー不足"); fail += 1; return }
    var picks: [VPNServer] = Array(servers.prefix(3))
    for s in servers.filter({ $0.speedMbps >= 8 }).sorted(by: { $0.sessions < $1.sessions }) {
        if picks.count >= VPNPolicy.candidateCount { break }
        if !picks.contains(where: { $0.id == s.id }) { picks.append(s) }
    }
    guard let sample = VPNGateAPI.decodeConfig(picks[0].configBase64) else {
        print("設定を復号できない"); fail += 1; return
    }
    print("  候補: " + picks.map { "\($0.ip):\($0.port)/\($0.protoWord)(\($0.sessions)人)" }.joined(separator: " "))

    print("\n== A. 常駐起動（daemon.sh・本番と同一スクリプト） ==")
    do { try ctl.prepareDaemon(sampleConfig: sample, openvpn: ov) }
    catch { print("  NG prepareDaemon: \(error)"); fail += 1; return }
    devNullProfile()
    installMocks()
    let (rcD, outD) = sh("'\(ctl.daemonURL.path)'")
    check("daemon.sh 正常終了", rcD == 0, "exit=\(rcD) \(outD)")
    check("result.txt が DAEMON_OK", ctl.daemonResult() == "DAEMON_OK", ctl.daemonResult())
    check("openvpn が常駐している", ctl.isRunning())
    check("この時点ではまだ接続していない（待機）", !exists(ctl.dnsBackupURL.path))

    let session = VPNSession()
    var attached = false
    for _ in 0..<40 {
        if session.attach(port: ctl.currentMgmtPort(), password: ctl.mgmtPassword) { attached = true; break }
        usleep(250_000)
    }
    check("管理IFに接続（root 不要）", attached)
    guard attached else { _ = sh("'\(ctl.stopURL.path)'"); return }

    print("\n== B. 死んだ候補からの自動フォールバックと接続確立 ==")
    let dead = VPNServer(id: "dead", hostName: "DEAD-TEST-NET", ip: "192.0.2.1", score: 0, ping: 0,
                         speedBps: 0, countryLong: "Test", countryShort: cc, sessions: 0, uptimeMs: 0,
                         configBase64: "", proto: "udp", port: 1194, isOfficial: false)
    var tried: [Int] = []
    session.onProgress = { n, _ in if tried.last != n { tried.append(n) } }
    let t0 = Date()
    let first = await session.connect(candidates: [dead] + picks)
    session.onProgress = nil
    var connected: VPNServer? = nil
    if case .connected(let s) = first { connected = s }
    check("接続が成立した", connected != nil, "\(desc(first)) \(String(format: "%.1f秒", Date().timeIntervalSince(t0))) \(connected == nil ? lastErrors() : "")")
    check("死んだ候補を飛ばして次へ移った", connected != nil && connected?.id != dead.id, "試した順=\(tried)")
    let log = read(ctl.logURL.path)
    check("PUSH_REPLY を受信", log.contains("PUSH: Received control message"))
    check("Initialization Sequence Completed", log.contains("Initialization Sequence Completed"))
    check("証明書の用途検証（VERIFY EKU OK）", log.contains("VERIFY EKU OK"))

    print("\n== C. up スクリプトが openvpn から実際に呼ばれ、DNS を切り替えたか ==")
    check("networksetup が呼ばれた", !calls().isEmpty, "\(calls().normalizedLines.filter { !$0.isEmpty }.count) 回")
    check("DNSバックアップ作成", read(ctl.dnsBackupURL.path).contains("Wi-Fi"),
          read(ctl.dnsBackupURL.path).normalizedLines.filter { !$0.isEmpty }.joined(separator: " / "))
    let applied = calls().normalizedLines.first(where: { $0.hasPrefix("-setdnsservers Wi-Fi") }) ?? ""
    check("pushされたDNSを適用", applied.contains("10.") || applied.contains("8.8.8.8"), applied)
    check("DNS切替の警告は出ていない", ctl.dnsIssue() == nil, ctl.dnsIssue() ?? "")

    print("\n== D. 管理IFだけでサーバーを乗り換える（パスワードなし・root なし） ==")
    clearCalls()
    let before = connected
    let others = picks.filter { $0.id != before?.id }
    let pidBefore = read(ctl.pidURL.path).trimmingCharacters(in: .whitespacesAndNewlines)
    let second = await session.connect(candidates: others)
    var switched: VPNServer? = nil
    if case .connected(let s) = second { switched = s }
    let pidAfter = read(ctl.pidURL.path).trimmingCharacters(in: .whitespacesAndNewlines)
    check("別サーバーへ乗り換えられた", switched != nil && switched?.id != before?.id, desc(second))
    check("openvpn は同じプロセスのまま", !pidBefore.isEmpty && pidBefore == pidAfter, "\(pidBefore) → \(pidAfter)")
    check("乗り換え時に down→up が走った", calls().contains("-setdnsservers"), "\(calls().normalizedLines.filter { !$0.isEmpty }.count) 回")
    check("控えが「VPNのDNS」で上書きされていない",
          read(ctl.dnsBackupURL.path).contains("192.168.11.1"),
          read(ctl.dnsBackupURL.path).normalizedLines.filter { !$0.isEmpty }.joined(separator: " / "))

    print("\n== E. 切断（プロセスは待機で残す） ==")
    clearCalls()
    let held = await session.hold()
    check("管理IFだけで切断できた", held)
    check("openvpn は生きたまま", ctl.isRunning())
    check("down が呼ばれて元のDNSに復元", calls().contains("-setdnsservers Wi-Fi 192.168.11.1"),
          calls().normalizedLines.filter { !$0.isEmpty }.joined(separator: " | "))
    check("未設定だったサービスは Empty に戻す", calls().contains("-setdnsservers iPhone USB Empty"))
    check("dns-backup.txt 削除", !exists(ctl.dnsBackupURL.path))
    check("DNS復元の警告は出ていない", ctl.dnsIssue() == nil, ctl.dnsIssue() ?? "")

    print("\n== F. 待機状態からの再接続（ここでパスワードを聞かれないのが本題） ==")
    clearCalls()
    let third = await session.connect(candidates: picks)
    var again: VPNServer? = nil
    if case .connected(let s) = third { again = s }
    check("待機状態から再接続できた", again != nil, desc(third))
    check("再接続でも DNS を切り替えた", calls().contains("-setdnsservers Wi-Fi"))
    let pidFinal = read(ctl.pidURL.path).trimmingCharacters(in: .whitespacesAndNewlines)
    check("最初から最後まで openvpn は1プロセス", pidFinal == pidBefore, "\(pidBefore) → \(pidFinal)")

    print("\n== G. アプリが落ちても常駐は残り、つなぎ直せる ==")
    session.detach()
    check("管理IFを切っても openvpn は生存", ctl.isRunning())
    let session2 = VPNSession()
    var reattached = false
    for _ in 0..<20 {
        if session2.attach(port: ctl.currentMgmtPort(), password: ctl.mgmtPassword) { reattached = true; break }
        usleep(250_000)
    }
    check("別インスタンスから再接続（＝アプリ再起動相当）", reattached)

    print("\n== H. 全候補が失敗する場合 ==")
    clearCalls()
    let deadOnly = (1...3).map { i in
        VPNServer(id: "dead\(i)", hostName: "DEAD\(i)", ip: "192.0.2.\(i)", score: 0, ping: 0,
                  speedBps: 0, countryLong: "Test", countryShort: cc, sessions: 0, uptimeMs: 0,
                  configBase64: "", proto: i % 2 == 0 ? "tcp" : "udp", port: 1194, isOfficial: false)
    }
    let t1 = Date()
    let none = await session2.connect(candidates: deadOnly)
    check("全滅したら exhausted を返す", none == .exhausted,
          "\(desc(none)) \(String(format: "%.1f秒", Date().timeIntervalSince(t1)))")
    check("失敗しても openvpn は待機で残る", ctl.isRunning())
    let recovered = await session2.connect(candidates: picks)
    var recoveredServer: VPNServer? = nil
    if case .connected(let s) = recovered { recoveredServer = s }
    check("全滅のあとでも普通につなぎ直せる", recoveredServer != nil, desc(recovered))

    print("\n== I. 完全終了 ==")
    clearCalls()
    session2.terminate()
    var gone = false
    for _ in 0..<40 { if !ctl.isRunning() { gone = true; break }; usleep(300_000) }
    check("管理IFだけで openvpn を終了できた", gone)
    usleep(700_000)
    check("終了時にも DNS を復元", calls().contains("-setdnsservers Wi-Fi 192.168.11.1"),
          calls().normalizedLines.filter { !$0.isEmpty }.joined(separator: " | "))
    check("dns-backup.txt 削除", !exists(ctl.dnsBackupURL.path))

    print("\n== J. stop.sh による強制停止（管理IFが死んだときの保険） ==")
    clearCalls()
    do { try ctl.prepareDaemon(sampleConfig: sample, openvpn: ov) } catch { fail += 1 }
    devNullProfile()
    installMocks()
    let (rcD2, _) = sh("'\(ctl.daemonURL.path)'")
    let session3 = VPNSession()
    for _ in 0..<40 {
        if session3.attach(port: ctl.currentMgmtPort(), password: ctl.mgmtPassword) { break }
        usleep(250_000)
    }
    let back = await session3.connect(candidates: picks)
    var backOK = false
    if case .connected = back { backOK = true }
    check("再度つなげる", rcD2 == 0 && backOK, desc(back))
    clearCalls()
    let (rcS, outS) = sh("'\(ctl.stopURL.path)'")
    var gone2 = false
    for _ in 0..<40 { if !ctl.isRunning() { gone2 = true; break }; usleep(300_000) }
    check("stop.sh で停止できる", rcS == 0 && gone2, outS)
    usleep(500_000)
    check("stop.sh 経由でも DNS 復元", calls().contains("-setdnsservers Wi-Fi 192.168.11.1"),
          calls().normalizedLines.filter { !$0.isEmpty }.joined(separator: " | "))
    check("dns-backup.txt 削除", !exists(ctl.dnsBackupURL.path))
    session3.detach()

    print("\n== K. 後片付け ==")
    let (_, psOut) = VPNController.run("/bin/sh", ["-c", "pgrep -x -l openvpn | cat"])
    check("openvpn の残骸なし", psOut.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, psOut)
    check("テスト中の networksetup はすべて偽物だった（実機のDNSは無傷）",
          read(ctl.upURL.path).contains(LIVE + "/fakens") && read(ctl.downURL.path).contains(LIVE + "/fakens"))
    // モックのままアプリに使われないよう、本物のスクリプトへ戻しておく
    try? Scripts.up.write(to: ctl.upURL, atomically: true, encoding: .utf8)
    try? Scripts.down.write(to: ctl.downURL, atomically: true, encoding: .utf8)
    for u in [ctl.upURL, ctl.downURL] {
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: u.path)
    }
    check("本物の up.sh / down.sh に戻した",
          !read(ctl.upURL.path).contains("fakens") && !read(ctl.downURL.path).contains("fakens"))
}
sem.wait()
print("\n=== \(fail == 0 ? "ALL OK" : "FAIL \(fail)") ===")
exit(fail == 0 ? 0 : 1)
