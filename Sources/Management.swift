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
        // 行分割は必ずバイト列で行う。
        // openvpn の管理IFは CRLF 区切りで、Swift の String では "\r\n" が
        // 1つの Character になるため range(of: "\n") が一致せず、
        // 「受信しているのに1行も取り出せない」という無言の停止になる。
        var acc = [UInt8]()
        var buf = [UInt8](repeating: 0, count: 8192)
        while !stopped {
            let f = fd
            if f < 0 { break }
            let n = recv(f, &buf, buf.count, 0)
            if n <= 0 { break }
            acc.append(contentsOf: buf[0..<n])
            while let idx = acc.firstIndex(of: 0x0A) {
                var lineBytes = Array(acc[0..<idx])
                acc.removeFirst(idx + 1)
                if lineBytes.last == 0x0D { lineBytes.removeLast() }
                if !lineBytes.isEmpty { onLine?(String(decoding: lineBytes, as: UTF8.self)) }
            }
            // "ENTER PASSWORD:" のように改行が来ない断片は残る。暴走だけ防ぐ。
            if acc.count > 1 << 20 { acc.removeAll(keepingCapacity: true) }
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
    /// 1候補にかける上限秒数。openvpn の再試行通知だけに頼ると、
    /// 通知の間隔が想定より延びたときに候補を進められず固まる（実測で踏んだ）。
    /// 生きているサーバーは2〜7秒でつながるので、20秒あれば十分。
    static let candidateTimeout: TimeInterval = 20

    /// TVPN_MGMT_DEBUG=1 で管理IFの受信行を標準エラーに流す（検証用）
    static let debug = ProcessInfo.processInfo.environment["TVPN_MGMT_DEBUG"] != nil

    private let client = ManagementClient()
    private let q = DispatchQueue(label: "app.rtck.tsukubavpn.session")

    private var candidates: [VPNServer] = []
    private var index = 0
    private var polls = 0
    private var wantRelease = false
    private var connecting = false
    private var finish: ((Outcome) -> Void)?
    private var nudge: DispatchWorkItem?
    private var candidateTimer: DispatchWorkItem?
    private var candidateGeneration = 0
    private var holdWaiter: (() -> Void)?
    /// openvpn が hold（待機）に入っているか。
    /// **hold 中に `signal SIGUSR1` を送ると openvpn がその場で固まる**（実測）ので、
    /// 状態を必ず追いかけ、hold 中は `hold release` だけで進める。
    private var inHold = false
    /// この connect() で SIGUSR1 を撃ったか（撃つのは1回だけ）
    private var signalSent = false
    /// この connect() で接続先を聞かれたか
    private var sawRemoteQuery = false
    /// >HOLD: か >STATE: を受け取って、openvpn の状態が分かったか
    private var stateKnown = false

    /// 「いま何台目を試している」等の実況。メインスレッドとは限らない。
    var onProgress: ((Int, VPNServer) -> Void)?
    /// つながっていたのに切れた（サーバー側都合など）
    var onDropped: (() -> Void)?
    /// 常駐 openvpn が居なくなった（管理ソケットが閉じた）
    var onDetached: (() -> Void)?

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
                if VPNSession.debug {
                    FileHandle.standardError.write(Data(("MGMT< " + line + "\n").utf8))
                }
                self.q.async { self.handle(line) }
            }
            client.onClose = { [weak self] in
                guard let self else { return }
                self.q.async { self.handleClosed() }
            }
            ok = client.open(port: port, password: password)
            attached = ok
        }
        guard ok else { return false }
        // openvpn は待機中の相手に対して、接続した直後 >HOLD: を投げてくる。
        // これを取りこぼしたまま connect() すると「待機中なのに SIGUSR1」になって固まるので、
        // 状態が分かるまで（もしくは短い時間だけ）待ってから返す。
        for _ in 0..<20 {
            var known = false
            q.sync { known = self.inHold || self.stateKnown }
            if known { break }
            usleep(100_000)
        }
        return true
    }

    func detach() {
        q.sync {
            attached = false
            client.close()
        }
    }

    // MARK: 操作

    /// 候補を順に試して接続する。すでにつながっていれば、そのまま乗り換える。
    /// timeout に 0 を渡すと候補数から自動で決める。
    func connect(candidates list: [VPNServer], timeout: TimeInterval = 0) async -> Outcome {
        guard !list.isEmpty else { return .exhausted }
        let limit = timeout > 0 ? timeout
            : Double(list.count) * (VPNSession.candidateTimeout + 5) + 20
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
                self.signalSent = false
                self.sawRemoteQuery = false
                self.finish = { done.fire($0) }
                // どの状態から呼ばれても「接続先を聞かれる」ところまで持っていく。
                // 順番が重要で、必ず hold release を先に撃つ。
                // ・hold 待機中 → release だけで進む（ここで SIGUSR1 を撃つと固まる）
                // ・接続中／接続処理中 → release は空振りするので、あとから SIGUSR1 で落とす
                self.client.send("hold on")
                if self.inHold {
                    self.client.send("hold release")
                    self.inHold = false
                }
                self.scheduleNudge(count: 0)
                self.armCandidateTimer()
                self.q.asyncAfter(deadline: .now() + limit) {
                    guard self.connecting else { return }
                    self.finishConnecting(.error("時間内に接続できませんでした"))
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
                self.nudge?.cancel()
                self.candidateTimer?.cancel()
                // すでに待機中なら何もしない（hold 中の SIGUSR1 は openvpn を固める）
                if self.inHold { done.fire(true); return }
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
            nudge?.cancel()
            candidateTimer?.cancel()
            guard client.isOpen else { return }
            client.send("signal SIGTERM")
            // hold で待っている場合、release して待機ループから抜けさせないと
            // 受け取った SIGTERM が処理されない。
            client.send("hold release")
        }
        usleep(400_000)
        q.sync {
            client.send("quit")
            attached = false
            client.close()
        }
    }

    // MARK: 受信処理（すべて q の上）

    /// 接続先を聞かれるまで、状態に応じて突っつく。
    /// hold 中なら release、そうでなければ（＝つながっている／接続処理中なら）
    /// 一度だけ SIGUSR1 を撃って hold まで落とす。順序を間違えると openvpn が固まる。
    private func scheduleNudge(count: Int) {
        nudge?.cancel()
        guard count < 6 else { return }
        let w = DispatchWorkItem { [weak self] in
            guard let self, self.connecting, self.wantRelease, !self.sawRemoteQuery else { return }
            if self.inHold {
                self.client.send("hold release")
                self.inHold = false
            } else if !self.signalSent {
                self.signalSent = true
                self.client.send("hold on")
                self.client.send("signal SIGUSR1")
            }
            self.scheduleNudge(count: count + 1)
        }
        nudge = w
        q.asyncAfter(deadline: .now() + (count == 0 ? 2.5 : 3.0), execute: w)
    }

    private var target: VPNServer? {
        candidates.indices.contains(index) ? candidates[index] : nil
    }

    /// 接続処理を終える。ここを通さないと wantRelease が残り、
    /// `>HOLD:` のたびに hold release を撃ち続ける無限ループになる。
    private func finishConnecting(_ outcome: Outcome) {
        connecting = false
        wantRelease = false
        nudge?.cancel()
        candidateTimer?.cancel()
        let f = finish
        finish = nil
        f?(outcome)
    }

    /// 次の候補へ進む。候補が尽きたら待機状態に戻して .exhausted を返す。
    private func advanceCandidate() {
        guard connecting else { return }
        polls = 0
        index += 1
        candidateGeneration += 1
        guard target != nil else {
            // 候補切れ。ここで SIGUSR1 を撃つと、直後に飛んでくる接続先の問い合わせと
            // 競合して openvpn が終了しかねない。hold は常に armed なので、
            // 「もう接続先を答えない」だけで自然に待機状態へ戻る。
            finishConnecting(.exhausted)
            return
        }
        armCandidateTimer()
    }

    /// 1候補ぶんの制限時間を張り直す
    private func armCandidateTimer() {
        candidateTimer?.cancel()
        let gen = candidateGeneration
        let w = DispatchWorkItem { [weak self] in
            guard let self, self.connecting, self.candidateGeneration == gen else { return }
            self.advanceCandidate()
        }
        candidateTimer = w
        q.asyncAfter(deadline: .now() + VPNSession.candidateTimeout, execute: w)
    }

    private func handle(_ line: String) {
        if line.hasPrefix(">HOLD:") {
            inHold = true
            stateKnown = true
            if let w = holdWaiter {
                holdWaiter = nil
                nudge?.cancel()
                w()
                return
            }
            if wantRelease {
                client.send("hold release")
                inHold = false
            }
            return
        }
        if line.hasPrefix(">REMOTE:") {
            inHold = false
            sawRemoteQuery = true
            nudge?.cancel()
            let parts = line.dropFirst(">REMOTE:".count).components(separatedBy: ",")
            // openvpn は "tcp-client" のように返してくる
            let proto = (parts.count >= 3 ? parts[2] : "").components(separatedBy: "-").first ?? ""
            guard connecting, let t = target else {
                // 接続する気がないのに聞かれた場合。
                // **両方の <connection> に SKIP を返すと openvpn は候補を使い切って終了する**ので、
                // 必ず片方には接続先を答える。127.0.0.1:1 は即座に拒否されるため、
                // openvpn はすぐ再起動して hold（待機）に戻る。
                client.send(proto == "tcp" ? "remote MOD 127.0.0.1 1" : "remote SKIP")
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
            stateKnown = true
            if name != "EXITING" { inHold = false }
            switch name {
            case "CONNECTED":
                polls = 0
                candidateTimer?.cancel()
                let s = target ?? lastConnected
                lastConnected = s
                if connecting, let s { finishConnecting(.connected(s)) }
            case "RECONNECTING":
                // server_poll = 接続先が応答しなかった。自分で投げた SIGUSR1 は数えない。
                if extra == "server_poll" || extra == "connection-reset"
                    || extra == "tls-error" || extra == "auth-failure" {
                    guard connecting else { return }
                    polls += 1
                    if polls >= VPNSession.pollsPerCandidate { advanceCandidate() }
                } else if !connecting, lastConnected != nil {
                    lastConnected = nil
                    onDropped?()
                }
            case "EXITING":
                if connecting { finishConnecting(.error("openvpn が終了しました")) }
            default:
                break
            }
        }
    }

    private func handleClosed() {
        attached = false
        if connecting { finishConnecting(.error("VPN の管理接続が切れました")) }
        inHold = false
        stateKnown = false
        lastConnected = nil
        onDetached?()
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
