import Foundation

enum VPNGateAPI {
    static let endpoints = [
        "https://www.vpngate.net/api/iphone/",
        "https://www.vpngate.net/api/iphone/?_t=1",
        "http://www.vpngate.net/api/iphone/"
    ]

    static func fetch() async throws -> [VPNServer] {
        var lastError: Error = URLError(.badServerResponse)
        for ep in endpoints {
            do {
                let list = try await fetchOne(ep)
                if !list.isEmpty { return list }
                lastError = URLError(.zeroByteResource)
            } catch {
                lastError = error
            }
        }
        throw lastError
    }

    private static func fetchOne(_ urlString: String) async throws -> [VPNServer] {
        guard let url = URL(string: urlString) else { throw URLError(.badURL) }
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 45
        cfg.timeoutIntervalForResource = 90
        let session = URLSession(configuration: cfg)
        var req = URLRequest(url: url)
        req.setValue("TsukubaVPN/1.0 (macOS)", forHTTPHeaderField: "User-Agent")
        let (data, resp) = try await session.data(for: req)
        if let http = resp as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw URLError(.badServerResponse)
        }
        let text = String(data: data, encoding: .utf8)
            ?? String(data: data, encoding: .shiftJIS)
            ?? String(decoding: data, as: UTF8.self)
        return parse(text)
    }

    static func parse(_ text: String) -> [VPNServer] {
        var out: [VPNServer] = []
        for line in text.normalizedLines {
            if line.isEmpty || line.hasPrefix("*") || line.hasPrefix("#") { continue }
            let f = line.components(separatedBy: ",")
            guard f.count >= 15 else { continue }
            let cfg = f[f.count - 1].trimmingCharacters(in: .whitespaces)
            guard cfg.count > 400 else { continue }
            var ip = f[1].trimmingCharacters(in: .whitespaces)
            guard !ip.isEmpty else { continue }
            // proto と接続先ポートは設定本文にしか書かれていないので、ここで一度だけ読む。
            // remote 行のホストは CSV の IP 欄より優先する（食い違うことがある）。
            var proto = "tcp"
            var port = 1194
            if let body = decodeConfig(cfg) {
                for line in body.normalizedLines {
                    let t = line.trimmingCharacters(in: .whitespaces).lowercased()
                    if t.hasPrefix("proto ") {
                        proto = t.hasSuffix("udp") ? "udp" : "tcp"
                    } else if t.hasPrefix("remote ") {
                        let parts = t.split(whereSeparator: { $0 == " " || $0 == "\t" })
                        if parts.count >= 2, !parts[1].isEmpty { ip = String(parts[1]) }
                        if parts.count >= 3, let p = Int(parts[2]), p > 0, p < 65536 { port = p }
                    }
                }
            }
            let s = VPNServer(
                id: f[0].isEmpty ? ip : f[0],
                hostName: f[0],
                ip: ip,
                score: Int(f[2]) ?? 0,
                ping: Int(f[3]) ?? 0,
                speedBps: Int(f[4]) ?? 0,
                countryLong: f[5],
                countryShort: f[6].uppercased(),
                sessions: Int(f[7]) ?? 0,
                uptimeMs: Int(f[8]) ?? 0,
                configBase64: cfg,
                proto: proto,
                port: port,
                isOfficial: f[0].lowercased().hasPrefix("public-vpn"))
            out.append(s)
        }
        var seen = Set<String>()
        return out.filter { seen.insert($0.ip).inserted }
    }

    static func decodeConfig(_ b64: String) -> String? {
        guard let d = Data(base64Encoded: b64, options: [.ignoreUnknownCharacters]) else { return nil }
        return String(data: d, encoding: .utf8)
    }
}
