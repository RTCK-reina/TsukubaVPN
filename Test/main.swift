import Foundation

let sem = DispatchSemaphore(value: 0)
var exitCode: Int32 = 0

func freePort(from lo: Int = 41200, to hi: Int = 41900) -> Int {
    for _ in 0..<200 {
        let p = Int.random(in: lo...hi)
        if VPNController.portIsFree(p) { return p }
    }
    return lo
}

Task {
    defer { sem.signal() }
    print("== 1. VPN Gate API 取得 ==")
    let servers: [VPNServer]
    do { servers = try await VPNGateAPI.fetch() }
    catch { print("FAIL fetch: \(error)"); exitCode = 1; return }
    print("取得: \(servers.count) 台")
    guard servers.count > 10 else { print("FAIL: 少なすぎる"); exitCode = 1; return }

    var counts: [String: Int] = [:]
    for s in servers { counts[s.countryShort, default: 0] += 1 }
    print("国別: " + counts.sorted { $0.value > $1.value }.prefix(6).map { "\($0.key)=\($0.value)" }.joined(separator: " "))
    let portsOK = servers.allSatisfy { $0.port > 0 && $0.port < 65536 }
    let protosOK = servers.allSatisfy { $0.proto == "udp" || $0.proto == "tcp" }
    print("接続先ポートを全件読めた: \(portsOK ? "OK" : "NG") / proto が udp|tcp のみ: \(protosOK ? "OK" : "NG")")
    if !portsOK || !protosOK { exitCode = 1 }

    let cc = CommandLine.arguments.dropFirst().first ?? "JP"
    let jp = servers.filter { $0.countryShort == cc }.sorted { $0.rank > $1.rank }
    guard !jp.isEmpty else { print("FAIL: \(cc) のサーバーなし"); exitCode = 1; return }
    print("\n== 2. ランキング上位（\(cc)） ==")
    for s in jp.prefix(3) {
        print("  \(s.flag) \(s.countryJa) \(s.ip):\(s.port) \(s.protoWord) \(s.originWord) ★\(s.stars) \(s.speedText) \(s.pingText) 同時\(s.sessions)人")
    }

    print("\n== 3. 共通プロファイル（1枚で全サーバーに届くか） ==")
    // 全サーバーの ca / cert / key が本当に同一かを毎回確かめる。
    // ここが崩れたら共通プロファイル方式そのものが成立しないので、必ず落とす。
    func inlineBlock(_ tag: String, _ cfg: String) -> String? {
        guard let a = cfg.range(of: "<\(tag)>"), let b = cfg.range(of: "</\(tag)>"),
              a.upperBound <= b.lowerBound else { return nil }
        return String(cfg[a.upperBound..<b.lowerBound]).replacingOccurrences(of: "\r", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }
    var caSet = Set<String>(), certSet = Set<String>(), keySet = Set<String>()
    var decoded = 0
    for s in servers {
        guard let c = VPNGateAPI.decodeConfig(s.configBase64) else { continue }
        guard let ca = inlineBlock("ca", c), let ce = inlineBlock("cert", c), let k = inlineBlock("key", c) else { continue }
        decoded += 1
        caSet.insert(ca); certSet.insert(ce); keySet.insert(k)
    }
    print("  復号できた設定: \(decoded) 台 / ca の種類: \(caSet.count) / cert: \(certSet.count) / key: \(keySet.count)")
    let identical = decoded > 10 && caSet.count == 1 && certSet.count == 1 && keySet.count == 1
    print("  全サーバーで証明書が同一: \(identical ? "OK" : "NG")")
    if !identical { exitCode = 1 }

    guard let raw = VPNGateAPI.decodeConfig(jp[0].configBase64) else {
        print("FAIL: base64 復号失敗"); exitCode = 1; return
    }
    guard let profile = VPNController.buildSharedProfile(from: raw) else {
        print("FAIL: 共通プロファイルを組み立てられない"); exitCode = 1; return
    }
    let mustHave = ["client", "dev tun", "<connection>", "remote 127.0.0.1 1 udp", "remote 127.0.0.1 1 tcp",
                    "remote-cert-tls server", "data-ciphers-fallback", "persist-tun", "<ca>", "<cert>", "<key>"]
    for k in mustHave where !profile.contains(k) { print("FAIL: プロファイルに \(k) がない"); exitCode = 1 }
    print("  プロファイル \(profile.normalizedLines.count) 行 / \(profile.count) 文字 / 妥当性: \(VPNController.sharedProfileIsValid(profile) ? "OK" : "NG")")
    if !VPNController.sharedProfileIsValid(profile) { exitCode = 1 }

    // プロファイル本体は自前の固定文なので、サーバー由来の文字列は ca/cert/key の中身だけ。
    // 悪意ある設定が混ざっていても取り込まれないことを確認する。
    let hostileCfg = raw + "\nplugin /tmp/evil.so\nroute-up /tmp/evil\nscript-security 2\nup /tmp/evil.sh\n"
    let hostileProfile = VPNController.buildSharedProfile(from: hostileCfg) ?? ""
    var leaked: [String] = []
    for k in ["plugin ", "route-up ", "script-security", "up /tmp"] where hostileProfile.contains(k) { leaked.append(k) }
    print("  外部由来の危険な指定が混入しない: \(leaked.isEmpty ? "OK" : "NG \(leaked)")")
    if !leaked.isEmpty { exitCode = 1 }
    let brokenProfile = VPNController.buildSharedProfile(from: "client\ndev tun\nremote 1.2.3.4 1194\n")
    print("  証明書のない設定を拒否: \(brokenProfile == nil ? "OK" : "NG")")
    if brokenProfile != nil { exitCode = 1 }

    // セルフテスト用の整形（こちらはサーバー個別の設定を使うので従来どおり許可制）
    let san = VPNController.sanitize(raw)
    for k in ["dev tun", "remote ", "<ca>", "remote-cert-tls server"] where !san.contains(k) {
        print("FAIL: 整形後に \(k) がない"); exitCode = 1
    }
    let hardened = VPNController.sanitize(raw + "\nplugin /tmp/evil.so\nroute-up /tmp/evil\nauth-user-pass /etc/master.passwd\n")
    for k in ["plugin ", "route-up ", "auth-user-pass "] where hardened.contains(k) {
        print("FAIL: sanitize に危険な設定が残っている: \(k)"); exitCode = 1
    }
    print("  セルフテスト用 sanitize: OK")

    print("\n== 4. 常駐用ファイルの生成 ==")
    guard let ov = VPNController.findOpenVPN() else { print("FAIL: openvpn 未検出"); exitCode = 1; return }
    print("openvpn: \(ov)")
    do { try VPNController.shared.prepareDaemon(sampleConfig: raw, openvpn: ov) }
    catch { print("FAIL prepareDaemon: \(error)"); exitCode = 1; return }
    let d = VPNController.shared.dir.path
    print("作業フォルダ: \(d)")
    for f in ["daemon.sh", "stop.sh", "up.sh", "down.sh", "mgmt.pass", "shared.ovpn"] {
        let p = d + "/" + f
        let ok = FileManager.default.fileExists(atPath: p)
        print("  \(ok ? "OK " : "NG ") \(f)")
        if !ok { exitCode = 1 }
    }
    print("mgmt port: \(VPNController.shared.mgmtPort)")
    let managementPasswordOK = VPNController.shared.mgmtPassword.count >= 32
        && VPNController.shared.mgmtPassword != "tsukuba-vpn-local"
    print("管理IFパスワード: \(managementPasswordOK ? "ランダム値 OK" : "NG")")
    if !managementPasswordOK { exitCode = 1 }

    print("\n== 5. シェル構文チェック ==")
    for f in ["daemon.sh", "stop.sh", "up.sh", "down.sh"] {
        let (rc, out) = VPNController.run("/bin/sh", ["-n", d + "/" + f])
        print("  \(rc == 0 ? "OK " : "NG ") sh -n \(f) \(out)")
        if rc != 0 { exitCode = 1 }
    }
    for f in ["up.sh", "down.sh"] {
        let (rc, out) = VPNController.run("/bin/bash", ["-n", d + "/" + f])
        print("  \(rc == 0 ? "OK " : "NG ") bash -n \(f) \(out)")
        if rc != 0 { exitCode = 1 }
    }

    print("\n== 6. daemon.sh の挙動（openvpn をスタブに差し替えて確認） ==")
    let dt = "/tmp/tvpn/dt"
    try? FileManager.default.removeItem(atPath: dt)
    try? FileManager.default.createDirectory(atPath: dt, withIntermediateDirectories: true)
    let stub = dt + "/fakeopenvpn"
    let stubBody = """
    #!/bin/sh
    PIDF=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --writepid) PIDF="$2"; shift 2;;
        *) shift;;
      esac
    done
    ( sleep 90 ) &
    echo $! > "$PIDF"
    exit 0
    """
    try? stubBody.write(toFile: stub, atomically: true, encoding: .utf8)
    try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: stub)
    let dummyProfile = "client\ndev tun\nremote 203.0.113.9 1194\n<ca>\n" + String(repeating: "A", count: 1200) + "\n</ca>\n"
    try? dummyProfile.write(toFile: dt + "/shared.ovpn", atomically: true, encoding: .utf8)
    try? "pw".write(toFile: dt + "/mgmt.pass", atomically: true, encoding: .utf8)
    func renderDaemon(_ dir: String) -> String {
        Scripts.daemon
            .replacingOccurrences(of: "__DIR__", with: dir)
            .replacingOccurrences(of: "__OV__", with: stub)
            .replacingOccurrences(of: "__PORT__", with: "41999")
    }
    try? renderDaemon(dt).write(toFile: dt + "/daemon.sh", atomically: true, encoding: .utf8)
    let (drc, dout) = VPNController.run("/bin/sh", [dt + "/daemon.sh"])
    let dres = ((try? String(contentsOfFile: dt + "/result.txt", encoding: .utf8)) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    let dpid = ((try? String(contentsOfFile: dt + "/openvpn.pid", encoding: .utf8)) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    print("  起動: rc=\(drc) result=[\(dres)] pid=[\(dpid)] \(dout)")
    let launchOK = drc == 0 && dres == "DAEMON_OK" && !dpid.isEmpty
    print("  常駐起動: \(launchOK ? "OK" : "NG")")
    if !launchOK { exitCode = 1 }
    // 2回目は二重起動しない（＝パスワードを再入力させても openvpn は増えない）
    let (drc2, _) = VPNController.run("/bin/sh", [dt + "/daemon.sh"])
    let dpid2 = ((try? String(contentsOfFile: dt + "/openvpn.pid", encoding: .utf8)) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    print("  二重起動しない: \(drc2 == 0 && dpid2 == dpid ? "OK" : "NG (\(dpid2))")")
    if drc2 != 0 || dpid2 != dpid { exitCode = 1 }
    if let pid = Int32(dpid) { kill(pid, SIGKILL) }
    // 壊れたプロファイルは起動前に弾く
    let dt2 = "/tmp/tvpn/dt2"
    try? FileManager.default.removeItem(atPath: dt2)
    try? FileManager.default.createDirectory(atPath: dt2, withIntermediateDirectories: true)
    try? "client\n".write(toFile: dt2 + "/shared.ovpn", atomically: true, encoding: .utf8)
    try? renderDaemon(dt2).write(toFile: dt2 + "/daemon.sh", atomically: true, encoding: .utf8)
    let (brc, _) = VPNController.run("/bin/sh", [dt2 + "/daemon.sh"])
    let bres = ((try? String(contentsOfFile: dt2 + "/result.txt", encoding: .utf8)) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    print("  壊れたプロファイルを起動前に拒否: \(brc == 2 && bres == "BAD_PROFILE" ? "OK" : "NG rc=\(brc) [\(bres)]")")
    if brc != 2 || bres != "BAD_PROFILE" { exitCode = 1 }

    print("\n== 7. 管理IF越しの接続・自動フォールバック・切断・再接続（実サーバー） ==")
    // dev null / route-nopull なので、経路も DNS も一切変更しない。
    // 検証するのはアプリ本体のコード（ManagementClient と VPNSession）そのもの。
    let live = "/tmp/tvpn/live"
    try? FileManager.default.removeItem(atPath: live)
    try? FileManager.default.createDirectory(atPath: live, withIntermediateDirectories: true)
    let testProfile = profile.replacingOccurrences(of: "\ndev tun\n", with: "\ndev null\n") + "route-nopull\n"
    try? testProfile.write(toFile: live + "/shared.ovpn", atomically: true, encoding: .utf8)
    for f in ["up.sh", "down.sh"] {
        try? "#!/bin/sh\necho \"$script_type $*\" >> \(live)/hooks.log\nexit 0\n"
            .write(toFile: live + "/" + f, atomically: true, encoding: .utf8)
        try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: live + "/" + f)
    }
    let livePassword = "verify-" + UUID().uuidString + UUID().uuidString
    try? livePassword.write(toFile: live + "/mgmt.pass", atomically: true, encoding: .utf8)
    try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: live + "/mgmt.pass")
    let livePort = freePort()
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: ov)
    proc.arguments = ["--config", live + "/shared.ovpn", "--cd", live,
                      "--log-append", live + "/openvpn.log", "--verb", "3", "--mute-replay-warnings",
                      "--management", "127.0.0.1", "\(livePort)", live + "/mgmt.pass",
                      "--management-query-remote", "--management-hold",
                      "--writepid", live + "/openvpn.pid",
                      "--script-security", "2",
                      "--up", live + "/up.sh", "--down", live + "/down.sh", "--down-pre", "--up-restart"]
    proc.standardOutput = FileHandle.nullDevice
    proc.standardError = FileHandle.nullDevice
    do { try proc.run() } catch { print("FAIL: openvpn を起動できない: \(error)"); exitCode = 1; return }

    let session = VPNSession()
    var attached = false
    for _ in 0..<60 {
        if session.attach(port: livePort, password: livePassword) { attached = true; break }
        usleep(250_000)
    }
    print("  管理IFへ接続: \(attached ? "OK" : "NG")")
    if !attached { exitCode = 1; proc.terminate() }

    if attached {
        // 1台目は必ず落ちる住所（TEST-NET-3）。2台目以降の実サーバーへ自動で移れるかを見る。
        let dead = VPNServer(id: "dead", hostName: "DEAD-TEST-NET", ip: "192.0.2.1", score: 0, ping: 0,
                             speedBps: 0, countryLong: "Test", countryShort: cc, sessions: 0, uptimeMs: 0,
                             configBase64: "", proto: "udp", port: 1194, isOfficial: false)
        let realPicks = Array(jp.sorted { $0.sessions < $1.sessions }.prefix(3))
        let picks = [dead] + realPicks
        var seen: [Int] = []
        session.onProgress = { n, _ in if seen.last != n { seen.append(n) } }
        let t0 = Date()
        let outcome = await session.connect(candidates: picks)
        session.onProgress = nil
        let elapsed = Int(Date().timeIntervalSince(t0))
        switch outcome {
        case .connected(let s):
            let fellBack = s.id != dead.id
            print("  接続成立: \(s.hostName) \(s.ip):\(s.port) \(s.protoWord)  \(elapsed)秒")
            print("  死んだ候補から自動フォールバック: \(fellBack ? "OK" : "NG")  試した順=\(seen)")
            if !fellBack { exitCode = 1 }
        case .exhausted:
            print("  NG: 候補を使い切った（\(elapsed)秒）— 公開サーバー側の不調の可能性")
            exitCode = 1
        case .error(let m):
            print("  NG: \(m)（\(elapsed)秒）")
            exitCode = 1
        }
        let hooks = (try? String(contentsOfFile: live + "/hooks.log", encoding: .utf8)) ?? ""
        print("  接続時に up が呼ばれた: \(hooks.contains("up ") ? "OK" : "NG")")
        if !hooks.contains("up ") { exitCode = 1 }

        // 切断（root なし）。openvpn は待機状態で残り、down が呼ばれる。
        let held = await session.hold()
        let stillAlive = proc.isRunning
        let hooks2 = (try? String(contentsOfFile: live + "/hooks.log", encoding: .utf8)) ?? ""
        print("  管理IFだけで切断: \(held ? "OK" : "NG") / プロセスは待機で残る: \(stillAlive ? "OK" : "NG") / down が呼ばれた: \(hooks2.contains("down ") ? "OK" : "NG")")
        if !held || !stillAlive || !hooks2.contains("down ") { exitCode = 1 }

        // 待機状態からの再接続（ここでパスワードを求められないことが本題）
        let again = await session.connect(candidates: realPicks)
        if case .connected(let s2) = again {
            print("  待機状態から再接続: OK (\(s2.hostName))")
        } else {
            print("  待機状態から再接続: NG (\(again))")
            exitCode = 1
        }

        session.terminate()
        var exited = false
        for _ in 0..<50 {
            if !proc.isRunning { exited = true; break }
            usleep(200_000)
        }
        print("  管理IFだけで完全終了: \(exited ? "OK" : "NG")")
        if !exited { exitCode = 1; proc.terminate() }
    }
    proc.waitUntilExit()

    print("\n== 8. DNS切替スクリプトの動作（networksetup をモックして検証） ==")
    let mockDir = "/tmp/tvpn/dns"
    try? FileManager.default.removeItem(atPath: mockDir)
    try? FileManager.default.createDirectory(atPath: mockDir, withIntermediateDirectories: true)
    let fakeNS = mockDir + "/fakens"
    let fakeBody = """
    #!/bin/sh
    echo "$@" >> /tmp/tvpn/dns/calls.txt
    if [ "$1" = "-setdnsservers" ] && [ -f /tmp/tvpn/dns/fail-restore ]; then exit 9; fi
    case "$1" in
      -listallnetworkservices) printf 'An asterisk...\\nWi-Fi\\niPhone USB\\n';;
      -getdnsservers) if [ "$2" = "Wi-Fi" ]; then echo "192.168.1.1"; else echo "There aren't any DNS Servers set on iPhone USB."; fi;;
    esac
    exit 0
    """
    try? fakeBody.write(toFile: fakeNS, atomically: true, encoding: .utf8)
    try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: fakeNS)
    let upBody = Scripts.up
        .replacingOccurrences(of: "NS=/usr/sbin/networksetup", with: "NS=\(fakeNS)")
        .replacingOccurrences(of: "/usr/bin/dscacheutil -flushcache 2>/dev/null", with: "true")
        .replacingOccurrences(of: "/usr/bin/killall -HUP mDNSResponder 2>/dev/null", with: "true")
    let downBody = Scripts.down
        .replacingOccurrences(of: "NS=/usr/sbin/networksetup", with: "NS=\(fakeNS)")
        .replacingOccurrences(of: "/usr/bin/dscacheutil -flushcache 2>/dev/null", with: "true")
        .replacingOccurrences(of: "/usr/bin/killall -HUP mDNSResponder 2>/dev/null", with: "true")
    try? upBody.write(toFile: mockDir + "/up.sh", atomically: true, encoding: .utf8)
    try? downBody.write(toFile: mockDir + "/down.sh", atomically: true, encoding: .utf8)
    for f in ["up.sh", "down.sh"] { try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: mockDir + "/" + f) }
    let env = "foreign_option_1='dhcp-option DNS 10.211.254.254' foreign_option_2='dhcp-option DNS 8.8.8.8' foreign_option_3='route 10.0.0.0 255.0.0.0'"
    _ = VPNController.run("/bin/sh", ["-c", "\(env) '\(mockDir)/up.sh' utun4 1500 1553 10.211.1.5 10.211.1.6 init"])
    let calls1 = (try? String(contentsOfFile: mockDir + "/calls.txt", encoding: .utf8)) ?? ""
    let backup = (try? String(contentsOfFile: mockDir + "/dns-backup.txt", encoding: .utf8)) ?? ""
    let setOK = calls1.contains("-setdnsservers Wi-Fi 10.211.254.254 8.8.8.8")
    print("  pushされたDNSを適用: \(setOK ? "OK" : "NG")")
    print("  バックアップ内容: \(backup.normalizedLines.filter { !$0.isEmpty }.joined(separator: " / "))")
    try? FileManager.default.removeItem(atPath: mockDir + "/calls.txt")
    // 乗り換え時は down → up が続けて走る。控えを二重取りして「VPNのDNS」を
    // 元の設定として覚えてしまわないことを確認する。
    _ = VPNController.run("/bin/sh", ["-c", "'\(mockDir)/down.sh'"])
    let calls2 = (try? String(contentsOfFile: mockDir + "/calls.txt", encoding: .utf8)) ?? ""
    let restoreOK = calls2.contains("-setdnsservers Wi-Fi 192.168.1.1")
    let emptyOK = calls2.contains("-setdnsservers iPhone USB Empty")
    let removed = !FileManager.default.fileExists(atPath: mockDir + "/dns-backup.txt")
    print("  元のDNSに復元    : \(restoreOK ? "OK" : "NG")")
    print("  未設定だったものはEmptyに戻す: \(emptyOK ? "OK" : "NG")")
    print("  バックアップ削除 : \(removed ? "OK" : "NG")")
    _ = VPNController.run("/bin/sh", ["-c", "\(env) '\(mockDir)/up.sh' utun4 1500 1553 10.211.1.5 10.211.1.6 init"])
    try? "fail".write(toFile: mockDir + "/fail-restore", atomically: true, encoding: .utf8)
    let (failedRestoreRC, _) = VPNController.run("/bin/sh", [mockDir + "/down.sh"])
    let backupPreserved = FileManager.default.fileExists(atPath: mockDir + "/dns-backup.txt")
    // 契約: down.sh は openvpn の後始末を巻き添えにしないよう常に 0 で終わり、
    // 失敗は dns-status.txt に残してアプリが警告する。バックアップは再試行のため保持する。
    let statusText = (try? String(contentsOfFile: mockDir + "/dns-status.txt", encoding: .utf8)) ?? ""
    let failReported = statusText.contains("failed:")
    print("  復元失敗でも終了コードは0（openvpnの後始末を壊さない）: \(failedRestoreRC == 0 ? "OK" : "NG")")
    print("  復元失敗を dns-status.txt で通知: \(failReported ? "OK" : "NG")  \(statusText.trimmingCharacters(in: .whitespacesAndNewlines))")
    print("  復元失敗時にバックアップ保持: \(backupPreserved ? "OK" : "NG")")
    try? FileManager.default.removeItem(atPath: mockDir + "/fail-restore")
    let (retryRestoreRC, _) = VPNController.run("/bin/sh", [mockDir + "/down.sh"])
    let retryCleaned = retryRestoreRC == 0 && !FileManager.default.fileExists(atPath: mockDir + "/dns-backup.txt")
    print("  復元の再試行      : \(retryCleaned ? "OK" : "NG")")
    let statusCleared = !FileManager.default.fileExists(atPath: mockDir + "/dns-status.txt")
    print("  再試行成功で警告も消える: \(statusCleared ? "OK" : "NG")")
    if !(setOK && restoreOK && emptyOK && removed && failedRestoreRC == 0 && failReported && backupPreserved && retryCleaned && statusCleared) {
        exitCode = 1
        print("  calls1: \(calls1)")
        print("  calls2: \(calls2)")
    }

    print("\n== 9. 現在の状態 ==")
    if let (ip, code) = await VPNController.shared.publicIP() { print("  グローバルIP: \(ip) (\(code))") }
    else { print("  グローバルIP: 取得できず（致命的ではない）") }
    print("  openvpn 常駐中: \(VPNController.shared.isRunning())")
    print("  DNSの控えが残っている: \(VPNController.shared.dnsBackupExists())")
}
sem.wait()
print("\n=== EXIT \(exitCode) ===")
exit(exitCode)
