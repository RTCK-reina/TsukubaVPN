import Foundation

enum VPNPolicy {
    static let candidateCount = 5
    /// サーバー一覧をこの秒数より長く放置したら、接続前に取り直す。
    /// 公開VPNは動的IP・DDNSで住所が変わるため、古い一覧は「全台死んでいる」ように見える。
    static let listStaleAfter: TimeInterval = 600
}

struct VPNServer: Identifiable, Hashable {
    let id: String
    let hostName: String
    let ip: String
    let score: Int
    let ping: Int
    let speedBps: Int
    let countryLong: String
    let countryShort: String
    let sessions: Int
    let uptimeMs: Int
    let configBase64: String
    /// 設定に書かれていた proto（tcp / udp）
    let proto: String
    /// VPN Gate 公式クラスタ（public-vpn-*.opengw.net）か。
    /// 動画配信サービスに最初にブロックされるのがこの帯なので、用途によっては避けたい。
    let isOfficial: Bool

    var speedMbps: Double { Double(speedBps) / 1_000_000.0 }
    var uptimeDays: Int { max(0, uptimeMs / 86_400_000) }
    var flag: String { Country.flag(countryShort) }
    var countryJa: String { Country.ja(countryShort) ?? countryLong }

    /// 1...5 のわかりやすい品質スコア
    var stars: Int {
        var p = 0.0
        let m = speedMbps
        if m >= 100 { p += 3 } else if m >= 50 { p += 2.5 } else if m >= 20 { p += 2.0 }
        else if m >= 8 { p += 1.2 } else if m >= 2 { p += 0.5 }
        if ping > 0 {
            if ping <= 25 { p += 2.0 } else if ping <= 60 { p += 1.5 }
            else if ping <= 120 { p += 1.0 } else { p += 0.3 }
        }
        if uptimeDays >= 3 { p += 0.3 }
        return min(5, max(1, Int(p.rounded())))
    }

    var speedText: String {
        let m = speedMbps
        if m >= 10 { return String(format: "%.0f Mbps", m) }
        if m >= 1 { return String(format: "%.1f Mbps", m) }
        return String(format: "%.2f Mbps", m)
    }
    var pingText: String { ping > 0 ? "\(ping) ms" : "—" }
    var speedWord: String {
        let m = speedMbps
        if m >= 100 { return "とても速い" }
        if m >= 40 { return "速い" }
        if m >= 10 { return "ふつう" }
        return "おそい"
    }
    /// 並び替え用スコア（大きいほど良い）。
    ///
    /// このアプリの用途は「海外から日本のエンタメを見る」なので、
    /// 評価軸は「速いか」ではなく **「ブロックされずに、途切れずに再生できるか」**。
    /// 生の帯域を追うと必ず公式クラスタ（219.100.37.x）が1位になるが、
    /// あそこは世界中で使われている既知のVPN帯で、配信サービスに真っ先に弾かれる。
    var rank: Double {
        // 速度は「足りていれば十分」。4K で 25Mbps、余裕を見て 60Mbps で頭打ちにする。
        // それ以上の帯域は再生体験を改善しないので、点差にしない。
        let usable = min(speedMbps, 60.0)
        var r = usable * 4.0

        // 混雑は体感に直結する。実効帯域は同時利用者で割られる。
        r -= Double(min(sessions, 200)) * 2.5

        // 応答は多少悪くても動画では効かない。軽く見る。
        if ping > 0 { r -= Double(min(ping, 300)) * 0.4 } else { r -= 120 }

        // 長く動いている個人サーバーは落ちにくい。
        r += Double(min(uptimeDays, 60)) * 2.0

        // TCP over TCP は再送が増幅して動画が詰まりやすい。UDP を明確に優遇する。
        if proto == "udp" { r += 120 }

        // 公式クラスタは既知のVPN帯。速いが最もブロックされやすいので後ろへ。
        if isOfficial { r -= 260 }

        return r
    }

    /// 素性の表示（住宅回線かどうかが実質のブロック耐性）
    var originWord: String { isOfficial ? "公式・要注意" : "個人" }
    var protoWord: String { proto == "udp" ? "UDP" : "TCP" }

    /// 混み具合（少ないほど接続が通りやすい）
    var crowdWord: String {
        if sessions <= 15 { return "空いている" }
        if sessions <= 45 { return "ふつう" }
        if sessions <= 80 { return "やや混雑" }
        return "混雑"
    }
}

enum Country {
    static let jaNames: [String: String] = [
        "JP": "日本", "KR": "韓国", "US": "アメリカ", "TW": "台湾", "TH": "タイ",
        "RU": "ロシア", "VN": "ベトナム", "ID": "インドネシア", "IN": "インド",
        "CN": "中国", "HK": "香港", "SG": "シンガポール", "MY": "マレーシア",
        "PH": "フィリピン", "GB": "イギリス", "DE": "ドイツ", "FR": "フランス",
        "CA": "カナダ", "AU": "オーストラリア", "BR": "ブラジル", "RO": "ルーマニア",
        "UA": "ウクライナ", "PL": "ポーランド", "NL": "オランダ", "IT": "イタリア",
        "ES": "スペイン", "SE": "スウェーデン", "NO": "ノルウェー", "FI": "フィンランド",
        "CH": "スイス", "AT": "オーストリア", "BE": "ベルギー", "CZ": "チェコ",
        "MX": "メキシコ", "AR": "アルゼンチン", "TR": "トルコ", "EG": "エジプト",
        "ZA": "南アフリカ", "NZ": "ニュージーランド", "IE": "アイルランド",
        "PT": "ポルトガル", "GR": "ギリシャ", "HU": "ハンガリー", "IL": "イスラエル",
        "SA": "サウジアラビア", "AE": "アラブ首長国連邦", "KZ": "カザフスタン",
        "BD": "バングラデシュ", "PK": "パキスタン", "LK": "スリランカ", "MN": "モンゴル",
        "KH": "カンボジア", "MM": "ミャンマー", "LA": "ラオス", "NP": "ネパール",
        "BY": "ベラルーシ", "RS": "セルビア", "BG": "ブルガリア", "HR": "クロアチア",
        "SK": "スロバキア", "SI": "スロベニア", "LT": "リトアニア", "LV": "ラトビア",
        "EE": "エストニア", "DK": "デンマーク", "IS": "アイスランド", "CL": "チリ",
        "CO": "コロンビア", "PE": "ペルー", "VE": "ベネズエラ", "EC": "エクアドル",
        "MD": "モルドバ", "GE": "ジョージア", "AM": "アルメニア", "AZ": "アゼルバイジャン",
        "UZ": "ウズベキスタン", "KG": "キルギス", "IR": "イラン", "IQ": "イラク",
        "JO": "ヨルダン", "LB": "レバノン", "KW": "クウェート", "QA": "カタール",
        "NG": "ナイジェリア", "KE": "ケニア", "MA": "モロッコ", "DZ": "アルジェリア",
        "TN": "チュニジア", "LU": "ルクセンブルク", "CY": "キプロス", "MT": "マルタ"
    ]
    static func ja(_ code: String) -> String? { jaNames[code.uppercased()] }
    static func flag(_ code: String) -> String {
        let c = code.uppercased()
        guard c.count == 2 else { return "🏳️" }
        var s = ""
        for ch in c.unicodeScalars {
            guard ch.value >= 65, ch.value <= 90,
                  let v = UnicodeScalar(127397 + ch.value) else { return "🏳️" }
            s.unicodeScalars.append(v)
        }
        return s
    }
}

extension String {
    /// CRLF は Swift では 1 つの Character になるため、素朴な split では行分割できない。
    /// 必ずこのヘルパを通して行に分ける。
    var normalizedLines: [String] {
        self.replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .components(separatedBy: "\n")
    }
}
