import Darwin
import Foundation

// ルート権限なしで到達できる限界まで、実サーバー相手に本番と同じ経路を通す統合テスト。
// dev null を使うことで utun 作成（＝rootが必要な唯一の工程）だけを回避し、
// TLS確立 → PUSH_REPLY → up スクリプト実行 → 接続完了検出 → 管理IFで切断 → down スクリプト実行
// までを本番と同一のコード・同一のシェルで検証する。

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

/// 失敗時に openvpn が何を言ったかを1行で要約する
func lastErrors() -> String {
    var out: [String] = []
    for i in 1...VPNPolicy.candidateCount {
        let body = read(ctl.dir.appendingPathComponent("try\(i).log").path)
        if body.isEmpty { continue }
        let ls = body.normalizedLines.filter { !$0.isEmpty }
        let hit = ls.last { $0.contains("rror") || $0.contains("ailed") || $0.contains("Exiting")
            || $0.contains("AUTH") || $0.contains("reset") || $0.contains("SIGTERM") || $0.contains("SIGUSR1") }
        out.append("try\(i)=[\(hit ?? ls.last ?? "")]")
    }
    let sk = read(ctl.dir.appendingPathComponent("skipped.txt").path)
    if !sk.isEmpty { out.append("skipped=[\(sk.normalizedLines.filter { !$0.isEmpty }.joined(separator: ","))]") }
    return out.joined(separator: " ")
}

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
        s = s.replacingOccurrences(of: "echo \"$@\"", with: "echo \"$@\"")
        try? s.write(toFile: p, atomically: true, encoding: .utf8)
        try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: p)
    }
}

func devNull(_ candIndex: Int) {
    let p = ctl.candURL(candIndex).path
    var s = read(p)
    guard VPNController.looksValid(s) else {
        print("  !! devNull: cand\(candIndex) を読めなかった（\(s.utf8.count) bytes）。テスト条件が壊れている")
        fail += 1
        return
    }
    s = s.normalizedLines.filter { !$0.trimmingCharacters(in: .whitespaces).lowercased().hasPrefix("dev ") }
        .joined(separator: "\n")
    s += "\ndev null\n"
    try? s.write(toFile: p, atomically: true, encoding: .utf8)
    if !VPNController.looksValid(read(p)) {
        print("  !! devNull: cand\(candIndex) の書き戻しに失敗")
        fail += 1
    }
}

let sem = DispatchSemaphore(value: 0)
Task {
    defer { sem.signal() }
    try? FileManager.default.removeItem(atPath: LIVE)
    try? FileManager.default.createDirectory(atPath: LIVE, withIntermediateDirectories: true)

    guard let ov = VPNController.findOpenVPN() else { print("openvpn なし"); fail += 1; return }

    print("== A. dev null で openvpn 単体が接続完了まで到達するか（非root） ==")
    let servers = (try? await VPNGateAPI.fetch())?.filter { $0.countryShort == (CommandLine.arguments.dropFirst().first ?? "JP") }.sorted { $0.rank > $1.rank } ?? []
    guard servers.count >= VPNPolicy.candidateCount else { print("サーバー不足"); fail += 1; return }
    var picks: [VPNServer] = Array(servers.prefix(3))
    for s in servers.filter({ $0.speedMbps >= 8 }).sorted(by: { $0.sessions < $1.sessions }) {
        if picks.count >= VPNPolicy.candidateCount { break }
        if !picks.contains(where: { $0.id == s.id }) { picks.append(s) }
    }
    let cands = picks.compactMap { s -> Candidate? in
        guard let c = VPNGateAPI.decodeConfig(s.configBase64) else { return nil }
        return Candidate(server: s, config: c)
    }
    print("  混み具合: " + picks.map { "\($0.ip)(\($0.sessions)人/\($0.crowdWord))" }.joined(separator: " "))
    try? ctl.prepare(candidates: Array(cands), openvpn: ov)
    for k in 1...VPNPolicy.candidateCount { devNull(k) }
    installMocks()
    print("  候補: " + cands.map { "\($0.server.ip)" }.joined(separator: ", "))

    print("\n== B. run.sh 完全チェーン（本番と同一スクリプト） ==")
    let t0 = Date()
    let (rc, out) = sh("'\(ctl.runURL.path)'")
    let dt = String(format: "%.1f秒", Date().timeIntervalSince(t0))
    let result = read(ctl.resultURL.path).trimmingCharacters(in: .whitespacesAndNewlines)
    check("run.sh 正常終了", rc == 0, "exit=\(rc) result=[\(result)] \(dt) \(out) \(rc == 0 ? "" : lastErrors())")
    check("result.txt が OK", result.hasPrefix("OK"), result)
    let (done, ok, idx) = ctl.readResult()
    check("readResult() が成功を返す", done && ok && idx >= 1, "idx=\(idx)")
    check("openvpn が生存している", ctl.isRunning())
    let log = read(read(ctl.activeLogURL.path).trimmingCharacters(in: .whitespacesAndNewlines))
    check("PUSH_REPLY を受信", log.contains("PUSH: Received control message"))
    check("Initialization Sequence Completed", log.contains("Initialization Sequence Completed"))
    check("管理インターフェース起動", log.contains("MANAGEMENT: TCP Socket listening"))
    if let l = log.normalizedLines.first(where: { $0.contains("PUSH: Received") }) {
        print("      " + l.trimmingCharacters(in: .whitespaces))
    }

    print("\n== C. up スクリプトが openvpn から実際に呼ばれたか ==")
    let calls = read(LIVE + "/calls.txt")
    let backup = read(ctl.dnsBackupURL.path)
    check("networksetup が呼ばれた", !calls.isEmpty, "\(calls.normalizedLines.filter { !$0.isEmpty }.count) 回")
    check("DNSバックアップ作成", backup.contains("Wi-Fi"), backup.normalizedLines.filter { !$0.isEmpty }.joined(separator: " / "))
    let applied = calls.normalizedLines.first(where: { $0.hasPrefix("-setdnsservers Wi-Fi") }) ?? ""
    check("pushされたDNSを適用", applied.contains("10.211.") || applied.contains("8.8.8.8"), applied)
    check("dnsNeedsRestore は false（接続中なので）", ctl.dnsNeedsRestore() == false)

    print("\n== D. 管理インターフェース経由の切断（パスワードなし・権限なし） ==")
    try? FileManager.default.removeItem(atPath: LIVE + "/calls.txt")
    let sent = ctl.managementSignalTerm()
    check("管理IFに接続してSIGTERM送信", sent)
    var gone = false
    for _ in 0..<30 { if !ctl.isRunning() { gone = true; break }; usleep(300_000) }
    check("openvpn が終了した", gone)
    usleep(700_000)
    let calls2 = read(LIVE + "/calls.txt")
    check("down スクリプトが呼ばれた", !calls2.isEmpty, calls2.normalizedLines.filter { !$0.isEmpty }.joined(separator: " | "))
    check("元のDNSに復元", calls2.contains("-setdnsservers Wi-Fi 192.168.11.1"))
    check("未設定だったサービスは Empty に戻す", calls2.contains("-setdnsservers iPhone USB Empty"))
    check("dns-backup.txt 削除", !exists(ctl.dnsBackupURL.path))
    check("dnsNeedsRestore は false", ctl.dnsNeedsRestore() == false)

    print("\n== E. stop.sh による強制停止 ==")
    try? FileManager.default.removeItem(atPath: LIVE + "/calls.txt")
    // 本番と同じく prepare を挟んでから再接続する
    try? ctl.prepare(candidates: Array(cands), openvpn: ov)
    for k in 1...VPNPolicy.candidateCount { devNull(k) }
    installMocks()
    let (rc2, out2) = sh("'\(ctl.runURL.path)'")
    check("再接続できる", rc2 == 0 && ctl.isRunning(), out2 + " " + lastErrors())
    let (rc3, out3) = sh("'\(ctl.stopURL.path)'")
    var gone2 = false
    for _ in 0..<30 { if !ctl.isRunning() { gone2 = true; break }; usleep(300_000) }
    check("stop.sh で停止できる", rc3 == 0 && gone2, out3)
    usleep(500_000)
    check("stop.sh 経由でも DNS 復元", read(LIVE + "/calls.txt").contains("-setdnsservers Wi-Fi 192.168.11.1"))
    check("dns-backup.txt 削除", !exists(ctl.dnsBackupURL.path))

    print("\n== F. 全候補が失敗する場合 ==")
    try? FileManager.default.removeItem(atPath: LIVE + "/calls.txt")
    for i in 1...VPNPolicy.candidateCount {
        let bad = "client\ndev null\nproto tcp\nremote 127.0.0.1 9\nresolv-retry 0\nnobind\n"
        try? bad.write(toFile: ctl.candURL(i).path, atomically: true, encoding: .utf8)
    }
    let t1 = Date()
    let (rc4, _) = sh("'\(ctl.runURL.path)'")
    let res4 = read(ctl.resultURL.path).trimmingCharacters(in: .whitespacesAndNewlines)
    check("全候補が失敗したら NG を返す", rc4 != 0 && res4 == "NG", "exit=\(rc4) [\(res4)] \(String(format: "%.1f秒", Date().timeIntervalSince(t1)))")
    check("プロセスが残らない", !ctl.isRunning())
    let (_, psOut) = VPNController.run("/bin/sh", ["-c", "pgrep -x -l openvpn | cat"])
    check("openvpn の残骸なし", psOut.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, psOut)

    print("\n== H. 壊れた設定を渡された場合の防御 ==")
    let brokenSrv = VPNServer(id: "broken", hostName: "broken", ip: "203.0.113.1", score: 0, ping: 10,
                              speedBps: 1_000_000, countryLong: "Japan", countryShort: "JP",
                              sessions: 0, uptimeMs: 0, configBase64: "!!!not-base64!!!", proto: "tcp", isOfficial: false)
    let brokenCand = Candidate(server: brokenSrv, config: "dev tun\nclient\n")
    var threw = false
    var threwMsg = ""
    do { try ctl.prepare(candidates: [brokenCand], openvpn: ov) } catch { threw = true; threwMsg = error.localizedDescription }
    check("prepare が復旧不能な壊れた設定を拒否する", threw, threwMsg)
    let recoverable = Candidate(server: servers[0], config: "dev tun\nclient\n")
    var recovered = false
    do {
        try ctl.prepare(candidates: [recoverable], openvpn: ov)
        recovered = VPNController.looksValid(read(ctl.candURL(1).path))
    } catch { recovered = false }
    check("壊れた本文は base64 から作り直して復旧する", recovered)
    for k in 1...VPNPolicy.candidateCount { try? "dev null\n".write(toFile: ctl.candURL(k).path, atomically: true, encoding: .utf8) }
    let (rcB, _) = sh("'\(ctl.runURL.path)'")
    let skipped = read(ctl.dir.appendingPathComponent("skipped.txt").path)
    check("run.sh が壊れた設定を起動せずスキップ", rcB != 0 && skipped.contains("broken config"), skipped.normalizedLines.filter { !$0.isEmpty }.joined(separator: " | "))
    check("壊れた設定でも openvpn を起動しない", !exists(ctl.dir.appendingPathComponent("try1.log").path))
    check("looksValid: 正常な設定は通す", VPNController.looksValid(VPNController.sanitize(cands[0].config)))
    check("looksValid: 空文字は弾く", !VPNController.looksValid(""))
    check("looksValid: CAなしは弾く", !VPNController.looksValid(String(repeating: "x", count: 2000) + "\nclient\ndev tun\nremote 1.2.3.4 1\n"))

    print("\n== J. 管理ポート衝突への耐性（今回見つかった不具合の再発防止） ==")
    // 現在保存されているポートをわざと占有し、prepare が別のポートを選ぶか確認する
    let occupied = ctl.currentMgmtPort()
    let holdFD = socket(AF_INET, SOCK_STREAM, 0)
    var ha = sockaddr_in()
    ha.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    ha.sin_family = sa_family_t(AF_INET)
    ha.sin_port = UInt16(occupied).bigEndian
    ha.sin_addr.s_addr = inet_addr("127.0.0.1")
    let held = withUnsafePointer(to: &ha) { ptr -> Bool in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
            Darwin.bind(holdFD, sa, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0 && listen(holdFD, 1) == 0
        }
    }
    check("テスト用にポート \(occupied) を占有できた", held)
    check("portIsFree が占有中を検出", !VPNController.portIsFree(occupied))
    try? ctl.prepare(candidates: Array(cands), openvpn: ov)
    let newPort = ctl.currentMgmtPort()
    check("prepare が別の空きポートを選ぶ", newPort != occupied, "\(occupied) → \(newPort)")
    check("選ばれたポートは実際に空き", VPNController.portIsFree(newPort))
    check("run.sh に新ポートが書き込まれている", read(ctl.runURL.path).contains("PORT=\(newPort)"))
    for k in 1...VPNPolicy.candidateCount { devNull(k) }
    installMocks()
    let (rcJ, _) = sh("'\(ctl.runURL.path)'")
    check("ポート占有中でも接続できる", rcJ == 0 && ctl.isRunning(),
          read(ctl.resultURL.path).trimmingCharacters(in: .whitespacesAndNewlines) + " " + lastErrors())
    _ = ctl.managementSignalTerm()
    var goneJ = false
    for _ in 0..<30 { if !ctl.isRunning() { goneJ = true; break }; usleep(300_000) }
    check("新ポート経由で切断できる", goneJ)
    close(holdFD)

    print("\n== K. 切断直後の即再接続（TIME_WAIT 耐性） ==")
    var reconnectOK = true
    var detail = ""
    for round in 1...2 {
        // 2回目以降は prepare を呼ばず、run.sh 自身のポート再試行だけで再接続できるか見る
        if round == 1 {
            try? ctl.prepare(candidates: Array(cands), openvpn: ov)
            for k in 1...VPNPolicy.candidateCount { devNull(k) }
            installMocks()
        }
        let (rcK, _) = sh("'\(ctl.runURL.path)'")
        let res = read(ctl.resultURL.path).trimmingCharacters(in: .whitespacesAndNewlines)
        if rcK != 0 || !res.hasPrefix("OK") {
            reconnectOK = false
            detail += "round\(round)=\(res)(port \(ctl.currentMgmtPort())) \(lastErrors()) "
        } else {
            detail += "round\(round)=OK(port \(ctl.currentMgmtPort())) "
        }
        _ = ctl.managementSignalTerm()
        for _ in 0..<30 { if !ctl.isRunning() { break }; usleep(200_000) }
    }
    check("prepareなしでも連続2回の接続→即切断→再接続が成功", reconnectOK, detail)

    print("\n== I. セーフモード接続テスト用スクリプト（本番と同一・dev null で検証） ==")
    do { try ctl.prepareSelfTest(candidates: cands, openvpn: ov) }
    catch { check("prepareSelfTest", false, "\(error)") }
    check("selftest1.ovpn が妥当", VPNController.looksValid(read(ctl.selfTestConfURL.path)))
    for k in 1...cands.count {
        let url = ctl.selfTestConfURL(k)
        var sc = read(url.path).normalizedLines
            .filter { !$0.trimmingCharacters(in: .whitespaces).lowercased().hasPrefix("dev ") }
            .joined(separator: "\n")
        sc += "\ndev null\n"
        try? sc.write(toFile: url.path, atomically: true, encoding: .utf8)
    }
    let (rcS, outS) = sh("'\(ctl.selfTestURL.path)'")
    let rep = ctl.selfTestReport()
    check("selftest.sh 正常終了", rcS == 0, outS)
    check("トンネル確立を検出", rep["result"] == "OK", rep["result"] ?? "(なし)")
    check("デフォルト経路を記録できている", !(rep["default_before"] ?? "").isEmpty, rep["default_before"] ?? "")
    check("テスト中もデフォルト経路が不変", rep["default_before"] == rep["default_during"],
          "\(rep["default_before"] ?? "?") → \(rep["default_during"] ?? "?")")
    check("テスト後もデフォルト経路が不変", rep["default_before"] == rep["default_after"])
    check("utun 本数がテスト前後で同じ", rep["utun_before"] == rep["utun_after"],
          "before=\(rep["utun_before"] ?? "?") during=\(rep["utun_during"] ?? "?") after=\(rep["utun_after"] ?? "?")")
    check("プロセスを残さない", VPNController.run("/bin/sh", ["-c", "pgrep -x -l openvpn | cat"]).1
        .trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
    check("selftest.pid を掃除", !exists(ctl.dir.appendingPathComponent("selftest.pid").path))
    for k in 1...cands.count {
        try? "dev null\n".write(toFile: ctl.selfTestConfURL(k).path, atomically: true, encoding: .utf8)
    }
    _ = sh("'\(ctl.selfTestURL.path)'")
    let rep2 = ctl.selfTestReport()
    check("壊れた設定なら起動せず NG", rep2["result"] == "NG" && rep2["reason"] == "broken_config",
          "\(rep2["result"] ?? "?")/\(rep2["reason"] ?? "?")")

    print("\n== L. 壊れた候補が混ざっても残りで接続できるか（全滅しない） ==")
    let junk = VPNServer(id: "junk", hostName: "junk", ip: "203.0.113.9", score: 0, ping: 5,
                         speedBps: 1_000_000, countryLong: "Japan", countryShort: "JP",
                         sessions: 0, uptimeMs: 0, configBase64: "###broken###", proto: "tcp", isOfficial: false)
    let mixed = [Candidate(server: junk, config: "dev tun\nclient\n")] + cands
    var acceptedMixed: [Candidate] = []
    do { acceptedMixed = try ctl.prepare(candidates: mixed, openvpn: ov) }
    catch { check("壊れた候補入りでも prepare が通る", false, "\(error)") }
    check("壊れた1台だけ除外される", acceptedMixed.count == cands.count,
          "\(mixed.count)台中 \(acceptedMixed.count)台を採用")
    check("採用した先頭は正常なサーバー", acceptedMixed.first?.server.ip == cands.first?.server.ip,
          acceptedMixed.first?.server.ip ?? "-")
    check("cand1.ovpn が詰め直されている", read(ctl.candURL(1).path).contains(cands[0].server.ip),
          cands[0].server.ip)
    for k in 1...acceptedMixed.count { devNull(k) }
    installMocks()
    let (rcL, _) = sh("'\(ctl.runURL.path)'")
    let (_, okL, idxL) = ctl.readResult()
    check("その状態で接続できる", rcL == 0 && okL, read(ctl.resultURL.path).trimmingCharacters(in: .whitespacesAndNewlines))
    if okL {
        let mapped = acceptedMixed.indices.contains(idxL - 1) ? acceptedMixed[idxL - 1].server.ip : "?"
        let logged = read(read(ctl.activeLogURL.path).trimmingCharacters(in: .whitespacesAndNewlines))
        check("結果の番号と採用候補の対応が合っている", logged.contains(mapped), "idx=\(idxL) → \(mapped)")
    }

    print("\n== M. DNS切替が失敗しても接続は生き、警告だけ残るか（折衷案の要） ==")
    check("成功時は dnsIssue なし", ctl.dnsIssue() == nil, ctl.dnsIssue() ?? "-")
    check("dns-status に ok が記録されている", read(ctl.dnsStatusURL.path).contains("ok"),
          read(ctl.dnsStatusURL.path).trimmingCharacters(in: .whitespacesAndNewlines))
    _ = ctl.managementSignalTerm()
    for _ in 0..<30 { if !ctl.isRunning() { break }; usleep(300_000) }
    // ここから setdnsservers を失敗させる
    try? "1".write(toFile: LIVE + "/dnsfail", atomically: true, encoding: .utf8)
    try? ctl.prepare(candidates: Array(cands), openvpn: ov)
    for k in 1...5 { devNull(k) }
    installMocks()
    let (rcM, _) = sh("'\(ctl.runURL.path)'")
    let (_, okM, _) = ctl.readResult()
    check("DNS切替に失敗しても接続は成功する", rcM == 0 && okM && ctl.isRunning(),
          read(ctl.resultURL.path).trimmingCharacters(in: .whitespacesAndNewlines))
    let issue = ctl.dnsIssue()
    check("失敗理由が dnsIssue から読める", issue != nil, issue ?? "(なし)")
    _ = ctl.managementSignalTerm()
    for _ in 0..<30 { if !ctl.isRunning() { break }; usleep(300_000) }
    usleep(700_000)
    check("復元にも失敗するとバックアップが残る（再試行できる）", exists(ctl.dnsBackupURL.path))
    check("復元失敗も dnsIssue に出る", (ctl.dnsIssue() ?? "").contains("元に戻せません"), ctl.dnsIssue() ?? "-")
    try? FileManager.default.removeItem(atPath: LIVE + "/dnsfail")
    // モックを外した本番 down.sh では復元できないので、後始末はバックアップを直接消す
    try? FileManager.default.removeItem(at: ctl.dnsBackupURL)
    try? FileManager.default.removeItem(at: ctl.dnsStatusURL)
    check("後始末できた", !exists(ctl.dnsBackupURL.path) && ctl.dnsIssue() == nil)

    print("\n== G. 後片付け（本番用スクリプトに戻す） ==")
    try? ctl.prepare(candidates: Array(cands), openvpn: ov)
    let upBody = read(ctl.upURL.path)
    check("up.sh が本番版に戻った", upBody.contains("NS=/usr/sbin/networksetup"))
    check("cand1.ovpn が dev tun に戻った", read(ctl.candURL(1).path).contains("dev tun"))
    check("result.txt / attempt.txt クリア", !exists(ctl.resultURL.path) && !exists(ctl.attemptURL.path))
    for k in 1...cands.count { try? FileManager.default.removeItem(at: ctl.selfTestConfURL(k)) }
    try? FileManager.default.removeItem(at: ctl.selfTestResultURL)
}
sem.wait()
print("\n=== 失敗 \(fail) 件 / EXIT \(fail == 0 ? 0 : 1) ===")
exit(fail == 0 ? 0 : 1)
