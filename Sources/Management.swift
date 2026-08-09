import Foundation
import Darwin

// MARK: - 管理インターフェースの生ソケット

/// openvpn の --management へ張りっぱなしにする TCP クライアント。
///
/// このソケットさえ握っていれば、接続先の指定・乗り換え・切断はすべて
/// 一般ユーザー権限で行える。root が要るのは openvpn を起動する最初の一度だけ。
final class ManagementClient: @unchecked Sendable {
    private var fd: Int32 = -1
    private let sendLock = NSLock()
    private var stopped = false

    /// 受信した1行（改行は含まない）。読み取りスレッドから呼ばれる。
    var onLine: ((String) -> Void)?
    /// 相手が落ちた／こちらから閉じた。
    var onClose: (() -> Void)?

    var isOpen: Bool { fd >= 0 }

    @discardableResult
    func open(port: Int, password: String, timeout: TimeInterval = 4) -> Bool {
        guard fd < 0 else { return true }
        let f = socket(AF_INET, SOCK_STREAM, 0)
        guard f >= 0 else { return false }
        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(f, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(f, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(port).bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let connected = withUnsafePointer(to: &addr) { p -> Bool in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.connect(f, sa, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
            }
        }
        guard connected else { Darwin.close(f); return false }
        // 読み取りは待ちっぱなしにする（通知はいつ来るか分からないため）
        var zero = timeval(tv_sec: 0, tv_usec: 0)
        setsockopt(f, SOL_SOCKET, SO_RCVTIMEO, &zero, socklen_t(MemoryLayout<timeval>.size))
        fd = f
        stopped = false
        let t = Thread { [weak self] in self?.readLoop() }
        t.name = "TsukubaVPN.management"
        t.stackSize = 512 * 1024
        t.start()
        send(password)
        send("state on")
        return true
    }

    func send(_ line: String) {
        sendLock.lock()
        defer { sendLock.unlock() }
        guard fd >= 0 else { return }
        let bytes = Array((line + "\n").utf8)
        bytes.withUnsafeBufferPointer { bp in
            guard var p = bp.baseAddress else { return }
            var remaining = bp.count
            while remaining > 0 {
                let n = Darwin.send(fd, p, remaining, 0)
                if n <= 0 { break }
                p = p.advanced(by: n)
                remaining -= n
            }
        }
    }

    func close() {
        sendLock.lock()
        let f = fd
        fd = -1
        stopped = true
        sendLock.unlock()
        if f >= 0 {
            shutdown(f, SHUT_RDWR)
            Darwin.close(f)
        }
    }

    private func readLoop() {
        var acc = ""
        var buf = [UInt8](repeating: 0, count: 8192)
        while !stopped {
            let f = fd
            if f < 0 { break }
            let n = recv(f, &buf, buf.count, 0)
            if n <= 0 { break }
            acc += String(decoding: buf[0..<n], as: UTF8.self)
            while let r = acc.range(of: "\n") {
                var line = String(acc[acc.startIndex..<r.lowerBound])
                if line.hasSuffix("\r") { line.removeLast() }
                acc = String(acc[r.upperBound...])
                if !line.isEmpty { onLine?(line) }
            }
        }
        onClose?()
    }
}

// MARK: - 接続セッション

/// 常駐している openvpn を管理ソケット越しに操作する。
///
/// openvpn は共通プロファイル（全サーバーで ca/cert/key が同一）で起動してあり、
/// 接続先だけを `--management-query-remote` で差し替える。したがって
/// 「別のサーバーに乗り換える」も「切断する」も root 権限を必要としない。
final class VPNSession: @unchecked Sendable {

    enum Outcome: Equatable {
        /// つながった
        case connected(VPNServer)
        /// 候補を全部試したがダメだった
        case exhausted
        /// 管理ソケットが落ちた等
        case error(String)
    }

    /// 接続先を1台あたり何回まで待つか（server-poll-timeout ごとに1回数える）
    static let pollsPerCandidate = 2

    private let client = ManagementClient()
    private let q = DispatchQueue(label: "app.rtck.tsukubavpn.session")

    private var candidates: [VPNServer] = []
    private var index = 0
    private var polls = 0
    private var wantRelease = false
    private var connecting = false
    private var finish: ((Outcome) -> Void)?
    private var nudge: DispatchWorkItem?
    private var holdWaiter: (() -> Void)?

    /// 「いま何台目を試している」等の実況。メインスレッドとは限らない。
    var onProgress: ((Int, VPNServer) -> Void)?
    /// つながっていたのに切れた（サーバー側都合など）
    var onDropped: (() -> Void)?

    private(set) var attached = false
    private(set) var lastConnected: VPNServer?

    var isAttached: Bool { q.sync { attached && client.isOpen } }

    // MARK: 接続の確立

    /// 常駐 openvpn の管理ソケットにつなぐ。openvpn が動いていなければ false。
    @discardableResult
    func attach(port: Int, password: String) -> Bool {
        var ok = false
        q.sync {
            if attached && client.isOpen { ok = true; return }
            client.onLine = { [weak self] line in
                guard let self else { return }
                self.q.async { self.handle(line) }
            }
            client.onClose = { [weak self] in
                guard let self else { return }
                self.q.async { self.handleClosed() }
            }
            ok = client.open(port: port, password: password)
            attached = ok
        }
        return ok
    }

    func detach() {
        q.sync {
            attached = false
            client.close()
        }
    }

    // MARK: 操作

    /// 候補を順に試して接続する。すでにつながっていれば、そのまま乗り換える。
    func connect(candidates list: [VPNServer], timeout: TimeInterval = 120) async -> Outcome {
        guard !list.isEmpty else { return .exhausted }
        return await withCheckedContinuation { (cont: CheckedContinuation<Outcome, Never>) in
            let done = OneShot<Outcome> { cont.resume(returning: $0) }
            q.async {
                guard self.attached, self.client.isOpen else {
                    done.fire(.error("VPN の管理接続が切れています"))
                    return
                }
                self.candidates = list
                self.index = 0
                self.polls = 0
                self.wantRelease = true
                self.connecting = true
                self.finish = { done.fire($0) }
                // どの状態から呼ばれても確実に「接続先を聞かれる」ところまで持っていく。
                // ・接続中     → SIGUSR1 で hold に落ちる
                // ・hold 待機中 → SIGUSR1 は効かないので、あとから hold release で進む
                self.client.send("hold on")
                self.client.send("signal SIGUSR1")
                self.scheduleNudge(count: 0)
                self.q.asyncAfter(deadline: .now() + timeout) {
                    guard self.connecting else { return }
                    self.connecting = false
                    self.finish = nil
                    done.fire(.error("時間内に接続できませんでした"))
                }
            }
        }
    }

    /// 切断する。openvpn プロセスは hold 状態で残すので、次の接続でパスワードは要らない。
    /// down.sh が走って DNS は元に戻る。
    func hold(timeout: TimeInterval = 20) async -> Bool {
        await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            let done = OneShot<Bool> { cont.resume(returning: $0) }
            q.async {
                guard self.attached, self.client.isOpen else { done.fire(false); return }
                self.connecting = false
                self.finish = nil
                self.wantRelease = false
                self.lastConnected = nil
                self.holdWaiter = { done.fire(true) }
                self.client.send("hold on")
                self.client.send("signal SIGUSR1")
                self.q.asyncAfter(deadline: .now() + timeout) {
                    if self.holdWaiter != nil {
                        self.holdWaiter = nil
                        done.fire(false)
                    }
                }
            }
        }
    }

    /// openvpn 本体を終了させる（root 不要）。
    func terminate() {
        q.sync {
            connecting = false
            finish = nil
            wantRelease = false
            lastConnected = nil
            guard client.isOpen else { return }
            client.send("signal SIGTERM")
        }
        usleep(400_000)
        q.sync {
            client.send("quit")
            attached = false
            client.close()
        }
    }

    // MARK: 受信処理（すべて q の上）

    private func scheduleNudge(count: Int) {
        nudge?.cancel()
        guard count < 5 else { return }
        let w = DispatchWorkItem { [weak self] in
            guard let self, self.connecting, self.wantRelease else { return }
            self.client.send("hold release")
            self.scheduleNudge(count: count + 1)
        }
        nudge = w
        q.asyncAfter(deadline: .now() + (count == 0 ? 1.2 : 2.0), execute: w)
    }

    private var target: VPNServer? {
        candidates.indices.contains(index) ? candidates[index] : nil
    }

    private func handle(_ line: String) {
        if line.hasPrefix(">HOLD:") {
            if let w = holdWaiter {
                holdWaiter = nil
                nudge?.cancel()
                w()
                return
            }
            if wantRelease { client.send("hold release") }
            return
        }
        if line.hasPrefix(">REMOTE:") {
            nudge?.cancel()
            let parts = line.dropFirst(">REMOTE:".count).components(separatedBy: ",")
            // openvpn は "tcp-client" のように返してくる
            let proto = (parts.count >= 3 ? parts[2] : "").components(separatedBy: "-").first ?? ""
            guard connecting, let t = target else {
                // 接続する気がないのに聞かれた場合、片方を SKIP すると
                // 候補を使い切って openvpn ごと終了してしまう。必ず何か答える。
                client.send("remote SKIP")
                return
            }
            if proto == t.proto {
                onProgress?(index + 1, t)
                client.send("remote MOD \(t.ip) \(t.port)")
            } else {
                client.send("remote SKIP")
            }
            return
        }
        if line.hasPrefix(">STATE:") {
            let pt = line.dropFirst(">STATE:".count).components(separatedBy: ",")
            let name = pt.count > 1 ? pt[1] : ""
            let extra = pt.count > 2 ? pt[2] : ""
            switch name {
            case "CONNECTED":
                polls = 0
                let s = target ?? lastConnected
                lastConnected = s
                if connecting, let s {
                    connecting = false
                    nudge?.cancel()
                    let f = finish
                    finish = nil
                    f?(.connected(s))
                }
            case "RECONNECTING":
                // server_poll = 接続先が応答しなかった。自分で投げた SIGUSR1 は数えない。
                if extra == "server_poll" || extra == "connection-reset" || extra == "tls-error" {
                    guard connecting else { return }
                    polls += 1
                    if polls >= VPNSession.pollsPerCandidate {
                        polls = 0
                        index += 1
                        if target == nil {
                            connecting = false
                            nudge?.cancel()
                            let f = finish
                            finish = nil
                            // 候補切れ。hold に落として待機状態へ戻す。
                            wantRelease = false
                            client.send("hold on")
                            client.send("signal SIGUSR1")
                            f?(.exhausted)
                        }
                    }
                } else if !connecting, lastConnected != nil {
                    lastConnected = nil
                    onDropped?()
                }
            case "EXITING":
                if connecting {
                    connecting = false
                    nudge?.cancel()
                    let f = finish
                    finish = nil
                    f?(.error("openvpn が終了しました"))
                }
            default:
                break
            }
        }
    }

    private func handleClosed() {
        attached = false
        if connecting {
            connecting = false
            nudge?.cancel()
            let f = finish
            finish = nil
            f?(.error("VPN の管理接続が切れました"))
        }
        if let w = holdWaiter {
            holdWaiter = nil
            w()
        }
    }
}

/// 継続を二重に再開させないための小さな箱。
private final class OneShot<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var fired = false
    private let body: (T) -> Void
    init(_ body: @escaping (T) -> Void) { self.body = body }
    func fire(_ v: T) {
        lock.lock()
        if fired { lock.unlock(); return }
        fired = true
        lock.unlock()
        body(v)
    }
}
