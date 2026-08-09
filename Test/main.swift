import Foundation

let sem = DispatchSemaphore(value: 0)
var exitCode: Int32 = 0

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

    let cc = CommandLine.arguments.dropFirst().first ?? "JP"
    let jp = servers.filter { $0.countryShort == cc }.sorted { $0.rank > $1.rank }
    guard !jp.isEmpty else { print("FAIL: \(cc) のサーバーなし"); exitCode = 1; return }
    print("\n== 2. ランキング上位（\(cc)） ==")
    for s in jp.prefix(3) {
        print("  \(s.flag) \(s.countryJa) \(s.ip) ★\(s.stars) \(s.speedText) \(s.pingText) uptime=\(s.uptimeDays)日")
    }

    print("\n== 3. 設定の復号と整形 ==")
    guard let raw = VPNGateAPI.decodeConfig(jp[0].configBase64) else {
        print("FAIL: base64 復号失敗"); exitCode = 1; return
    }
    let san = VPNController.sanitize(raw)
    let must = ["dev tun", "remote ", "<ca>", "<cert>", "<key>", "data-ciphers-fallback", "remote-cert-tls server"]
    for k in must where !san.contains(k) { print("FAIL: 整形後に \(k) がない"); exitCode = 1 }
    for k in ["cipher AES", "persist-key"] where san.contains(k) { print("FAIL: \(k) が残っている"); exitCode = 1 }
    let hostile = raw + "\nplugin /tmp/evil.so\nroute-up /tmp/evil\nauth-user-pass /etc/master.passwd\n<connection>\nplugin /tmp/nested.so\n</connection>\n"
    let hardened = VPNController.sanitize(hostile)
    for k in ["plugin ", "route-up ", "auth-user-pass ", "<connection>"] where hardened.contains(k) {
        print("FAIL: 危険な設定が残っている: \(k)"); exitCode = 1
    }
    print("整形後 \(san.split(separator: "\n").count) 行 / \(san.count) 文字  OK")
    try? san.write(toFile: "/tmp/tvpn/verify.ovpn", atomically: true, encoding: .utf8)

    print("\n== 4. スクリプト生成 ==")
    var picks = Array(jp.prefix(3))
    for server in jp.filter({ $0.speedMbps >= 8 }).sorted(by: { $0.sessions < $1.sessions }) {
        if picks.count >= VPNPolicy.candidateCount { break }
        if !picks.contains(where: { $0.id == server.id }) { picks.append(server) }
    }
    let cands = picks.compactMap { s -> Candidate? in
        guard let c = VPNGateAPI.decodeConfig(s.configBase64) else { return nil }
        return Candidate(server: s, config: c)
    }
    guard let ov = VPNController.findOpenVPN() else { print("FAIL: openvpn 未検出"); exitCode = 1; return }
    print("openvpn: \(ov)")
    do { try VPNController.shared.prepare(candidates: Array(cands), openvpn: ov) }
    catch { print("FAIL prepare: \(error)"); exitCode = 1; return }
    let d = VPNController.shared.dir.path
    print("作業フォルダ: \(d)")
    let generated = ["run.sh", "stop.sh", "up.sh", "down.sh", "mgmt.pass"] + (1...cands.count).map { "cand\($0).ovpn" }
    for f in generated {
        let p = d + "/" + f
        print("  \(FileManager.default.fileExists(atPath: p) ? "OK " : "NG ") \(f)")
        if !FileManager.default.fileExists(atPath: p) { exitCode = 1 }
    }
    print("mgmt port: \(VPNController.shared.mgmtPort)")
    let managementPasswordOK = VPNController.shared.mgmtPassword.count >= 32
        && VPNController.shared.mgmtPassword != "tsukuba-vpn-local"
    print("管理IFパスワード: \(managementPasswordOK ? "ランダム値 OK" : "NG")")
    if !managementPasswordOK { exitCode = 1 }

    print("\n== 5. シェル構文チェック ==")
    for f in ["run.sh", "stop.sh", "up.sh", "down.sh"] {
        let (rc, out) = VPNController.run("/bin/sh", ["-n", d + "/" + f])
        print("  \(rc == 0 ? "OK " : "NG ") \(f) \(out)")
        if rc != 0 { exitCode = 1 }
    }
    let (rcb, outb) = VPNController.run("/bin/bash", ["-n", d + "/up.sh"])
    print("  bash -n up.sh: \(rcb == 0 ? "OK" : "NG \(outb)")")
    let (rcb2, outb2) = VPNController.run("/bin/bash", ["-n", d + "/down.sh"])
    print("  bash -n down.sh: \(rcb2 == 0 ? "OK" : "NG \(outb2)")")
    if rcb != 0 || rcb2 != 0 { exitCode = 1 }

    print("\n== 6. 現在のグローバルIP ==")
    if let (ip, cc) = await VPNController.shared.publicIP() { print("  \(ip) (\(cc))") }
    else { print("  取得できず（致命的ではない）") }


    print("\n== 8. 本番と同じ全オプションで実サーバー疎通（非rootなのでTUN作成のみ失敗するのが正解） ==")
    // 公開サーバーは頻繁に落ちるため、アプリと同じ候補構成で試す。サーバー負荷を避け、全確認を1接続へ統合する。
    var probeOK = false
    var probeDetail: [String] = []
    for k in 1...cands.count {
        let cfgPath = VPNController.shared.dir.appendingPathComponent("cand\(k).ovpn").path
        guard FileManager.default.fileExists(atPath: cfgPath) else { continue }
        let probeLog = "/tmp/tvpn/probe\(k).log"
        let probePID = "/tmp/tvpn/probe\(k).pid"
        try? FileManager.default.removeItem(atPath: probeLog)
        try? FileManager.default.removeItem(atPath: probePID)
        let port = 42100 + k
        _ = VPNController.run("/bin/sh", ["-c",
            "'\(ov)' --config '\(cfgPath)' --cd '\(d)' --log-append '\(probeLog)' --verb 3 --mute-replay-warnings --management 127.0.0.1 \(port) '\(d)/mgmt.pass' --writepid '\(probePID)' --script-security 2 --up '\(d)/up.sh' --down '\(d)/down.sh' --down-pre --connect-retry-max 1 --connect-timeout 12 --resolv-retry 8 >/dev/null 2>&1"])
        let plog = (try? String(contentsOfFile: probeLog, encoding: .utf8)) ?? ""
        let gotTLS = plog.contains("Peer Connection Initiated") || plog.contains("Control Channel:")
        let gotPush = plog.contains("PUSH: Received control message")
        let tunOnly = plog.contains("Cannot allocate TUN") || plog.contains("Operation not permitted")
        let optionsOK = !plog.contains("Options error") && !plog.contains("Unrecognized option")
        let managementOK = plog.contains("MANAGEMENT: TCP Socket listening")
        let certificateOK = plog.contains("VERIFY EKU OK")
        let ip = plog.normalizedLines.first(where: { $0.contains("link remote") })?
            .components(separatedBy: "]").last ?? "cand\(k)"
        if optionsOK && managementOK && gotTLS && certificateOK && gotPush && tunOnly {
            probeOK = true
            probeDetail.append("\(k)台目 OK (\(ip))")
            print("  全オプション: OK / 管理IF: OK / 証明書用途: OK / TLS: OK / PUSH_REPLY: OK / TUN権限のみ失敗: OK  (\(k)台目)")
            if let l = plog.normalizedLines.first(where: { $0.contains("PUSH: Received") }) {
                print("  → " + l.trimmingCharacters(in: .whitespaces))
            }
            break
        } else {
            let why = plog.normalizedLines.last(where: { $0.contains("rror") || $0.contains("timeout") || $0.contains("Exiting") }) ?? ""
            probeDetail.append("\(k)台目 NG: \(why.trimmingCharacters(in: .whitespaces))")
        }
    }
    if !probeOK {
        print("  \(cands.count)台とも疎通できず（公開サーバー側の不調・短時間の接続制限の可能性が高い）")
        for d in probeDetail { print("    - " + d) }
        exitCode = 1
    } else if probeDetail.count > 1 {
        print("  ※ 途中で落ちていたサーバー: " + probeDetail.dropLast().joined(separator: " / "))
    }

    print("\n== 9. 自動フェイルオーバー（run.sh）のロジック検証 ==")
    let rt = "/tmp/tvpn/rt"
    try? FileManager.default.removeItem(atPath: rt)
    try? FileManager.default.createDirectory(atPath: rt, withIntermediateDirectories: true)
    let stub = rt + "/fakeopenvpn"
    let stubBody = """
    #!/bin/sh
    LOG=""; PIDF=""; CFG=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --log-append) LOG="$2"; shift 2;;
        --writepid) PIDF="$2"; shift 2;;
        --config) CFG="$2"; shift 2;;
        *) shift;;
      esac
    done
    case "$CFG" in
      *cand1*) echo "TLS handshake" >> "$LOG"; echo "Exiting due to fatal error" >> "$LOG"; exit 1;;
      *cand2*) ( sleep 120 ) & echo $! > "$PIDF"; sleep 1; echo "Initialization Sequence Completed" >> "$LOG"; exit 0;;
      *) exit 1;;
    esac
    """
    try? stubBody.write(toFile: stub, atomically: true, encoding: .utf8)
    try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: stub)
    // run.sh は 1000バイト未満／<ca> なしの設定を「壊れている」と見なして起動しないので、
    // ダミーもその条件を満たす体裁にする
    let dummy = "client\ndev tun\nremote 203.0.113.9 1194\n<ca>\n" + String(repeating: "A", count: 1200) + "\n</ca>\n"
    for n in 1...3 { try? dummy.write(toFile: rt + "/cand\(n).ovpn", atomically: true, encoding: .utf8) }
    try? "pw".write(toFile: rt + "/mgmt.pass", atomically: true, encoding: .utf8)
    for f in ["up.sh", "down.sh"] { try? "#!/bin/sh\nexit 0\n".write(toFile: rt + "/" + f, atomically: true, encoding: .utf8) }
    let runScript = Scripts.run
        .replacingOccurrences(of: "__DIR__", with: rt)
        .replacingOccurrences(of: "__OV__", with: stub)
        .replacingOccurrences(of: "__N__", with: "3")
        .replacingOccurrences(of: "__PORT__", with: "41999")
    try? runScript.write(toFile: rt + "/run.sh", atomically: true, encoding: .utf8)
    let (rrc, rout) = VPNController.run("/bin/sh", [rt + "/run.sh"])
    let res = ((try? String(contentsOfFile: rt + "/result.txt", encoding: .utf8)) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    print("  終了コード: \(rrc)  result.txt: [\(res)]  \(rout)")
    print("  1台目失敗→2台目採用: \(res == "OK 2" && rrc == 0 ? "OK" : "NG")")
    if res != "OK 2" || rrc != 0 { exitCode = 1 }
    let alog = ((try? String(contentsOfFile: rt + "/activelog.txt", encoding: .utf8)) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    print("  activelog: \(alog.hasSuffix("try2.log") ? "OK" : "NG (\(alog))")")
    if let p = try? String(contentsOfFile: rt + "/openvpn.pid", encoding: .utf8), let pid = Int32(p.trimmingCharacters(in: .whitespacesAndNewlines)) {
        kill(pid, SIGKILL)
    }

    print("\n== 11. DNS切替スクリプトの動作（networksetup をモックして検証） ==")
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
    // 新しい契約: down.sh は openvpn の後始末を巻き添えにしないよう常に 0 で終わり、
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

    print("\n== 7. 実行状態 ==")
    print("  openvpn 稼働中: \(VPNController.shared.isRunning())")
    print("  DNS要復元: \(VPNController.shared.dnsNeedsRestore())")
}
sem.wait()
print("\n=== EXIT \(exitCode) ===")
exit(exitCode)
