import Foundation
import Darwin

enum VPNPhase: Equatable {
    case idle
    case preparing
    case connecting
    case connected
    case disconnecting
    case failed(String)

    var isBusy: Bool {
        switch self {
        case .preparing, .connecting, .disconnecting: return true
        default: return false
        }
    }
    var isConnected: Bool { self == .connected }
}

struct Candidate {
    let server: VPNServer
    let config: String
}

/// openvpn プロセスの起動・停止・状態監視をすべて担当する。
final class VPNController: @unchecked Sendable {
    static let shared = VPNController()

    let dir: URL
    private(set) var mgmtPort: Int
    let mgmtPassword: String

    private init() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        var d = home.appendingPathComponent("Library/TsukubaVPN", isDirectory: true)
        // root シェルへ埋め込むパスなので、空白や引用符などを含む場合は安全な固定形式へ退避する。
        let safePathCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-.")
        if d.path.rangeOfCharacter(from: safePathCharacters.inverted) != nil {
            d = URL(fileURLWithPath: "/tmp/TsukubaVPN-\(getuid())", isDirectory: true)
        }
        dir = d
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        let passwordFile = d.appendingPathComponent("mgmt.pass")
        let savedPassword = try? String(contentsOf: passwordFile, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if let savedPassword, savedPassword.count >= 32, savedPassword != "tsukuba-vpn-local" {
            mgmtPassword = savedPassword
        } else {
            mgmtPassword = UUID().uuidString + UUID().uuidString
        }
        let pf = d.appendingPathComponent("mgmt.port")
        if let s = try? String(contentsOf: pf, encoding: .utf8),
           let p = Int(s.trimmingCharacters(in: .whitespacesAndNewlines)), p > 1024, p < 65535 {
            mgmtPort = p
        } else {
            mgmtPort = 41300
        }
    }

    // MARK: - paths
    var daemonURL: URL { dir.appendingPathComponent("daemon.sh") }
    var sharedURL: URL { dir.appendingPathComponent("shared.ovpn") }
    var logURL: URL { dir.appendingPathComponent("openvpn.log") }
    var stopURL: URL { dir.appendingPathComponent("stop.sh") }
    var upURL: URL { dir.appendingPathComponent("up.sh") }
    var downURL: URL { dir.appendingPathComponent("down.sh") }
    var passURL: URL { dir.appendingPathComponent("mgmt.pass") }
    var pidURL: URL { dir.appendingPathComponent("openvpn.pid") }
    var resultURL: URL { dir.appendingPathComponent("result.txt") }
    var attemptURL: URL { dir.appendingPathComponent("attempt.txt") }
    var activeLogURL: URL { dir.appendingPathComponent("activelog.txt") }
    var dnsBackupURL: URL { dir.appendingPathComponent("dns-backup.txt") }
    var portURL: URL { dir.appendingPathComponent("mgmt.port") }
    var dnsStatusURL: URL { dir.appendingPathComponent("dns-status.txt") }
    func candURL(_ i: Int) -> URL { dir.appendingPathComponent("cand\(i).ovpn") }

    // MARK: - 管理ポート

    /// openvpn と同じ条件（SO_REUSEADDR なし）で bind を試し、本当に空いているポートだけを選ぶ。
    /// 直前の接続が TIME_WAIT で握っているポートもここで確実に除外される。
    /// 固定ポートにすると「切断直後の再接続」が Address already in use で全滅する。
    static func portIsFree(_ port: Int) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        if fd < 0 { return false }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(port).bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &addr) { ptr -> Bool in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.bind(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
            }
        }
        if !bound { return false }
        return listen(fd, 1) == 0
    }

    @discardableResult
    func allocateMgmtPort() throws -> Int {
        for _ in 0..<120 {
            let p = Int.random(in: 41200...41900)
            if VPNController.portIsFree(p) {
                mgmtPort = p
                try "\(p)".write(to: portURL, atomically: true, encoding: .utf8)
                return p
            }
        }
        throw PrepareError(message: "OpenVPN の管理ポートを確保できませんでした。少し待ってからやり直してください。")
    }

    /// 起動中の openvpn が実際に使っているポート（アプリ再起動後の切断でも効くようファイルから読む）
    func currentMgmtPort() -> Int {
        if let s = try? String(contentsOf: portURL, encoding: .utf8),
           let p = Int(s.trimmingCharacters(in: .whitespacesAndNewlines)), p > 1024, p < 65535 { return p }
        return mgmtPort
    }

    // MARK: - openvpn 探索
    static func findOpenVPN() -> String? {
        let cands = [
            "/opt/homebrew/sbin/openvpn",
            "/opt/homebrew/opt/openvpn/sbin/openvpn",
            "/usr/local/sbin/openvpn",
            "/usr/local/opt/openvpn/sbin/openvpn",
            "/usr/sbin/openvpn",
            "/usr/bin/openvpn"
        ]
        let fm = FileManager.default
        for c in cands where fm.isExecutableFile(atPath: c) { return c }
        return nil
    }

    static func brewPath() -> String? {
        for p in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
        where FileManager.default.isExecutableFile(atPath: p) { return p }
        return nil
    }

    // MARK: - 設定ファイルの整形
    static func sanitize(_ cfg: String) -> String {
        var keep: [String] = []
        var inlineBlock: String?
        var skippedBlock: String?
        let allowedDirectives: Set<String> = [
            "auth", "client", "dev", "nobind", "persist-tun", "proto", "remote",
            "remote-random", "resolv-retry", "tls-client"
        ]
        for line in cfg.normalizedLines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            let lower = trimmed.lowercased()

            if let block = inlineBlock {
                keep.append(line)
                if lower == "</\(block)>" { inlineBlock = nil }
                continue
            }
            if let block = skippedBlock {
                if lower == "</\(block)>" { skippedBlock = nil }
                continue
            }
            if ["<ca>", "<cert>", "<key>"].contains(lower) {
                inlineBlock = String(lower.dropFirst().dropLast())
                keep.append(line)
                continue
            }
            if lower.hasPrefix("<"), lower.hasSuffix(">"), !lower.hasPrefix("</") {
                skippedBlock = String(lower.dropFirst().dropLast())
                continue
            }
            if trimmed.isEmpty || lower.hasPrefix("#") || lower.hasPrefix(";") { continue }

            let directive = lower.split(whereSeparator: { $0 == " " || $0 == "\t" }).first.map(String.init) ?? ""
            guard allowedDirectives.contains(directive) else { continue }
            if directive == "dev", lower != "dev tun" { continue }
            keep.append(line)
        }
        keep.append(contentsOf: [
            "",
            "# ---- TsukubaVPN ----",
            "data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC",
            "data-ciphers-fallback AES-128-CBC",
            "remote-cert-tls server",
            "mute-replay-warnings",
            "pull",
            "nobind"
        ])
        return keep.joined(separator: "\n") + "\n"
    }

    /// 生成された .ovpn が openvpn に渡せる体裁になっているか。
    /// 1文字でも欠けると openvpn は意味不明なエラー（CA未定義など）を出すため、必ず事前に弾く。
    static func looksValid(_ cfg: String) -> Bool {
        guard cfg.utf8.count > 1000 else { return false }
        for tag in ["<ca>", "</ca>", "<cert>", "</cert>", "<key>", "</key>"] where !cfg.contains(tag) {
            return false
        }
        let lines = cfg.normalizedLines.map { $0.trimmingCharacters(in: .whitespaces) }
        guard lines.contains(where: { $0.hasPrefix("remote ") }) else { return false }
        guard lines.contains("client") else { return false }
        guard lines.contains(where: { $0.hasPrefix("dev ") }) else { return false }
        return true
    }

    struct PrepareError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    // MARK: - 共通プロファイル

    /// VPN Gate の全サーバーは ca / cert / key / cipher / auth が完全に同一で、
    /// サーバーごとに違うのは remote と proto の2行だけ（実測 94/94 台で一致）。
    /// したがってプロファイルは1枚で足り、接続先は起動後に管理インターフェースから
    /// 差し替えられる。proto の違いは <connection> を2つ置いて `remote SKIP` で吸収する。
    static func buildSharedProfile(from cfg: String) -> String? {
        func block(_ tag: String) -> String? {
            let open = "<\(tag)>", close = "</\(tag)>"
            guard let a = cfg.range(of: open), let b = cfg.range(of: close),
                  a.upperBound <= b.lowerBound else { return nil }
            let body = String(cfg[a.upperBound..<b.lowerBound])
                .normalizedLines
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
                .joined(separator: "\n")
            guard body.contains("-----BEGIN"), body.contains("-----END") else { return nil }
            return open + "\n" + body + "\n" + close
        }
        guard let ca = block("ca"), let cert = block("cert"), let key = block("key") else { return nil }
        let head = """
        # つくばVPN 共通プロファイル
        # 接続先は起動後に管理インターフェースから指定する（--management-query-remote）
        client
        dev tun
        nobind
        persist-tun
        resolv-retry infinite
        remote-cert-tls server
        auth SHA1
        data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC
        data-ciphers-fallback AES-128-CBC
        mute-replay-warnings
        pull
        connect-retry 1
        server-poll-timeout 12
        <connection>
        remote 127.0.0.1 1 udp
        </connection>
        <connection>
        remote 127.0.0.1 1 tcp
        </connection>
        """
        return head + "\n" + ca + "\n" + cert + "\n" + key + "\n"
    }

    static func sharedProfileIsValid(_ text: String) -> Bool {
        guard text.utf8.count > 1000 else { return false }
        for tag in ["<ca>", "</ca>", "<cert>", "</cert>", "<key>", "</key>"] where !text.contains(tag) {
            return false
        }
        guard text.contains("<connection>") else { return false }
        let lines = text.normalizedLines.map { $0.trimmingCharacters(in: .whitespaces) }
        guard lines.contains("client") else { return false }
        guard lines.contains(where: { $0.hasPrefix("remote ") }) else { return false }
        return lines.contains(where: { $0.hasPrefix("dev ") })
    }

    /// 常駐 openvpn を起動する直前の準備。管理ポートを取り、共通プロファイルと
    /// root で走るスクリプト（daemon.sh / up.sh / down.sh）を書き出す。
    func prepareDaemon(sampleConfig: String, openvpn: String) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        guard let profile = VPNController.buildSharedProfile(from: sampleConfig),
              VPNController.sharedProfileIsValid(profile) else {
            throw PrepareError(message: "共通プロファイルを組み立てられませんでした。「一覧を更新」を押してからやり直してください。")
        }
        try allocateMgmtPort()
        try profile.write(to: sharedURL, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: sharedURL.path)
        let back = (try? String(contentsOf: sharedURL, encoding: .utf8)) ?? ""
        guard VPNController.sharedProfileIsValid(back) else {
            throw PrepareError(message: "共通プロファイルを保存できませんでした。ディスクの空き容量を確認してください。")
        }
        try mgmtPassword.write(to: passURL, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: passURL.path)
        try Scripts.up.write(to: upURL, atomically: true, encoding: .utf8)
        try Scripts.down.write(to: downURL, atomically: true, encoding: .utf8)
        let d = Scripts.daemon
            .replacingOccurrences(of: "__DIR__", with: dir.path)
            .replacingOccurrences(of: "__OV__", with: openvpn)
            .replacingOccurrences(of: "__PORT__", with: "\(mgmtPort)")
        try d.write(to: daemonURL, atomically: true, encoding: .utf8)
        let stop = Scripts.stop.replacingOccurrences(of: "__DIR__", with: dir.path)
        try stop.write(to: stopURL, atomically: true, encoding: .utf8)
        for u in [upURL, downURL, daemonURL, stopURL] {
            try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: u.path)
        }
        for u in [resultURL, attemptURL] where fm.fileExists(atPath: u.path) { try? fm.removeItem(at: u) }
    }

    /// daemon.sh が残す起動結果（DAEMON_OK / DAEMON_FAILED / BAD_PROFILE）
    func daemonResult() -> String {
        (try? String(contentsOf: resultURL, encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }

    var selfTestURL: URL { dir.appendingPathComponent("selftest.sh") }
    var selfTestResultURL: URL { dir.appendingPathComponent("selftest.result") }
    var selfTestLogURL: URL { dir.appendingPathComponent("selftest.log") }
    func selfTestConfURL(_ i: Int) -> URL { dir.appendingPathComponent("selftest\(i).ovpn") }
    var selfTestConfURL: URL { selfTestConfURL(1) }

    /// セーフモード接続テスト用のファイルを書き出す。経路とDNSは変更しない設定にする。
    @discardableResult
    func prepareSelfTest(candidates: [Candidate], openvpn: String) throws -> [Candidate] {
        guard !candidates.isEmpty else { throw PrepareError(message: "接続テストの候補がありません。") }
        try allocateMgmtPort()
        let fm = FileManager.default
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        if fm.fileExists(atPath: selfTestResultURL.path) { try fm.removeItem(at: selfTestResultURL) }
        for i in 1...8 where fm.fileExists(atPath: selfTestConfURL(i).path) {
            try fm.removeItem(at: selfTestConfURL(i))
        }
        var accepted: [Candidate] = []
        for candidate in candidates {
            let text = VPNController.sanitize(candidate.config)
            guard VPNController.looksValid(text) else { continue }
            let url = selfTestConfURL(accepted.count + 1)
            try text.write(to: url, atomically: true, encoding: .utf8)
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            accepted.append(candidate)
        }
        guard !accepted.isEmpty else {
            throw PrepareError(message: "どのサーバーの設定も組み立てられませんでした。「一覧を更新」を押してからやり直してください。")
        }
        try mgmtPassword.write(to: passURL, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: passURL.path)
        let s = Scripts.selftest
            .replacingOccurrences(of: "__DIR__", with: dir.path)
            .replacingOccurrences(of: "__OV__", with: openvpn)
            .replacingOccurrences(of: "__N__", with: "\(accepted.count)")
            .replacingOccurrences(of: "__PORT__", with: "\(mgmtPort)")
        try s.write(to: selfTestURL, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: selfTestURL.path)
        return accepted
    }

    func selfTestReport() -> [String: String] {
        var out: [String: String] = [:]
        guard let s = try? String(contentsOf: selfTestResultURL, encoding: .utf8) else { return out }
        for line in s.normalizedLines where line.contains("=") {
            let parts = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            if parts.count == 2 { out[String(parts[0])] = String(parts[1]).trimmingCharacters(in: .whitespaces) }
        }
        return out
    }

    // MARK: - 実行ヘルパ
    @discardableResult
    static func run(_ launch: String, _ args: [String]) -> (Int32, String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: launch)
        p.arguments = args
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { return (-1, "\(error)") }
        let o = out.fileHandleForReading.readDataToEndOfFile()
        let e = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let s = (String(data: o, encoding: .utf8) ?? "") + (String(data: e, encoding: .utf8) ?? "")
        return (p.terminationStatus, s)
    }

    static func sudoNoPasswordAvailable() -> Bool {
        let (rc, _) = run("/usr/bin/sudo", ["-n", "/usr/bin/true"])
        return rc == 0
    }

    /// 管理者権限でシェルスクリプトを実行する。戻り値は (成功, メッセージ)
    static func elevate(script: String) -> (Bool, String) {
        if sudoNoPasswordAvailable() {
            let (rc, out) = run("/usr/bin/sudo", ["-n", "/bin/sh", script])
            return (rc == 0, out)
        }
        let quoted = "'" + script.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
        let command = "/bin/sh \(quoted)"
        let escaped = command.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let apple = "with timeout of 600 seconds\ndo shell script \"\(escaped)\" with administrator privileges\nend timeout"
        let (rc, out) = run("/usr/bin/osascript", ["-e", apple])
        if rc != 0 {
            if out.contains("-128") || out.lowercased().contains("cancel") {
                return (false, "CANCELLED")
            }
            return (false, out)
        }
        return (true, out)
    }

    // MARK: - 状態
    func isRunning() -> Bool {
        guard let s = try? String(contentsOf: pidURL, encoding: .utf8),
              let pid = Int32(s.trimmingCharacters(in: .whitespacesAndNewlines)), pid > 1 else { return false }
        var alive = false
        if kill(pid, 0) == 0 { alive = true } else if errno == EPERM { alive = true }
        guard alive else { return false }
        let (rc, out) = VPNController.run("/bin/ps", ["-p", "\(pid)", "-o", "comm="])
        if rc == 0 && !out.lowercased().contains("openvpn") { return false }
        return true
    }

    func currentAttempt() -> Int {
        guard let s = try? String(contentsOf: attemptURL, encoding: .utf8) else { return 0 }
        return Int(s.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
    }

    /// (完了したか, 成功か, 何番目の候補か)
    func readResult() -> (Bool, Bool, Int) {
        guard let s = try? String(contentsOf: resultURL, encoding: .utf8) else { return (false, false, 0) }
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.hasPrefix("OK") {
            let idx = Int(t.components(separatedBy: " ").last ?? "") ?? 0
            return (true, true, idx)
        }
        if t.hasPrefix("NG") { return (true, false, 0) }
        return (false, false, 0)
    }

    func activeLogPath() -> String? {
        if let s = try? String(contentsOf: activeLogURL, encoding: .utf8) {
            let p = s.trimmingCharacters(in: .whitespacesAndNewlines)
            if !p.isEmpty { return p }
        }
        return nil
    }

    func recentLog(lines: Int = 200) -> String {
        var files: [String] = []
        if FileManager.default.fileExists(atPath: logURL.path) { files.append(logURL.path) }
        if let p = activeLogPath() { files.append(p) }
        if let items = try? FileManager.default.contentsOfDirectory(atPath: dir.path) {
            for f in items.sorted() where f.hasPrefix("try") && f.hasSuffix(".log") {
                let full = dir.appendingPathComponent(f).path
                if !files.contains(full) { files.append(full) }
            }
        }
        var text = ""
        for f in files {
            if let s = try? String(contentsOfFile: f, encoding: .utf8) {
                text += "=== \((f as NSString).lastPathComponent) ===\n" + s + "\n"
            }
        }
        let all = text.normalizedLines
        if all.count > lines { return all.suffix(lines).joined(separator: "\n") }
        return text.isEmpty ? "（ログはまだありません）" : text
    }

    /// DNS の切り替え／復元に失敗していれば、その理由を返す。
    /// up.sh / down.sh は接続を巻き添えにしないよう常に成功終了し、結果だけをここに残す。
    func dnsIssue() -> String? {
        guard let s = try? String(contentsOf: dnsStatusURL, encoding: .utf8) else { return nil }
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard t.hasPrefix("failed:") else { return nil }
        let reason = String(t.dropFirst("failed:".count)).trimmingCharacters(in: .whitespaces)
        return reason.isEmpty ? "DNS設定を切り替えられませんでした" : reason
    }

    /// DNS の控えが残っているか。down.sh は復元に成功したときだけ控えを消すので、
    /// 「残っている & つながっていない」＝復元に失敗した、と判断できる。
    /// 常駐方式では切断してもプロセスは生きているため、isRunning() では判定できない。
    func dnsBackupExists() -> Bool {
        FileManager.default.fileExists(atPath: dnsBackupURL.path)
    }

    // MARK: - 切断
    func managementSignalTerm() -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        if fd < 0 { return false }
        defer { close(fd) }
        var tv = timeval(tv_sec: 3, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(currentMgmtPort()).bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let connected = withUnsafePointer(to: &addr) { ptr -> Bool in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.connect(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
            }
        }
        if !connected { return false }
        var buf = [UInt8](repeating: 0, count: 4096)
        _ = recv(fd, &buf, buf.count, 0)
        func write(_ s: String) {
            let bytes = Array((s + "\n").utf8)
            _ = bytes.withUnsafeBufferPointer { Darwin.send(fd, $0.baseAddress, $0.count, 0) }
        }
        write(mgmtPassword)
        usleep(250_000)
        _ = recv(fd, &buf, buf.count, 0)
        write("signal SIGTERM")
        usleep(250_000)
        _ = recv(fd, &buf, buf.count, 0)
        write("quit")
        usleep(150_000)
        return true
    }

    // MARK: - IP 確認
    private func getJSON<T: Decodable>(_ type: T.Type, _ urlString: String, timeout: TimeInterval = 7) async -> T? {
        guard let url = URL(string: urlString) else { return nil }
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = timeout
        cfg.timeoutIntervalForResource = timeout + 3
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        let session = URLSession(configuration: cfg)
        var req = URLRequest(url: url)
        req.setValue("curl/8.0", forHTTPHeaderField: "User-Agent")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        guard let (d, _) = try? await session.data(for: req) else { return nil }
        return try? JSONDecoder().decode(T.self, from: d)
    }

    /// (グローバルIP, 国コード) を返す。国コードは取れないこともある。
    func publicIP() async -> (String, String)? {
        struct IPOnly: Decodable { let ip: String? }
        struct Full: Decodable {
            let ip: String?
            let country: String?
            let country_iso: String?
        }
        if let ip = await getJSON(IPOnly.self, "https://api.ipify.org?format=json")?.ip, !ip.isEmpty {
            let cc = await getJSON(Full.self, "https://api.country.is/\(ip)", timeout: 5)?.country ?? ""
            return (ip, cc)
        }
        for u in ["https://ipinfo.io/json", "https://ifconfig.co/json"] {
            if let r = await getJSON(Full.self, u), let ip = r.ip, !ip.isEmpty {
                return (ip, r.country_iso ?? r.country ?? "")
            }
        }
        return nil
    }
}
