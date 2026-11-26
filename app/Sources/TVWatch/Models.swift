import Foundation

enum Route: String, CaseIterable {
    case vpn, direct, block
    var title: String {
        switch self {
        case .vpn: return "VPN"
        case .direct: return "Напрямую"
        case .block: return "Блок"
        }
    }
}

struct ConnEvent: Identifiable, Hashable {
    let id: UUID
    let cid: Int64
    let time: Date
    let src: String
    let host: String
    let ip: String
    let port: Int
    let net: String
    let out: String
    let route: Route
    let rule: String

    init?(_ j: [String: Any]) {
        guard let host = j["host"] as? String else { return nil }
        id = UUID()
        cid = (j["id"] as? NSNumber)?.int64Value ?? 0
        time = Date(timeIntervalSince1970: ((j["ts"] as? NSNumber)?.doubleValue ?? Date().timeIntervalSince1970 * 1000) / 1000)
        src = j["src"] as? String ?? ""
        self.host = host
        ip = j["ip"] as? String ?? ""
        port = (j["port"] as? NSNumber)?.intValue ?? 0
        net = j["net"] as? String ?? "tcp"
        out = j["out"] as? String ?? ""
        route = Route(rawValue: j["kind"] as? String ?? "") ?? .vpn
        rule = j["rule"] as? String ?? ""
    }

    var isIP: Bool { host.allSatisfy { $0.isNumber || $0 == "." || $0 == ":" } }

    /// Регистрируемый домен: www.youtube.com → youtube.com, news.bbc.co.uk → bbc.co.uk
    var baseDomain: String { Self.baseDomain(host) }

    static func baseDomain(_ host: String) -> String {
        let parts = host.split(separator: ".")
        guard parts.count > 2, !host.allSatisfy({ $0.isNumber || $0 == "." }) else { return host }
        let sld = parts[parts.count - 2]
        let secondLevel: Set<Substring> = ["co", "com", "net", "org", "gov", "edu", "ac", "msk", "spb"]
        let take = (parts.last!.count == 2 && secondLevel.contains(sld)) ? 3 : 2
        return parts.suffix(take).joined(separator: ".")
    }
}

struct DomainStat: Identifiable, Hashable {
    var id: String { host }
    let host: String
    var count: Int
    var last: Date
    var vpn: Int
    var direct: Int
    var block: Int
    var lastOut: String
}

struct ServerInfo: Identifiable, Hashable {
    var id: String { tag }
    let tag: String
    let proto: String
    let address: String
    let port: Int
    let network: String
    let security: String
    let sni: String
    var latency: Int?
    var testError = ""

    init(_ j: [String: Any]) {
        tag = j["tag"] as? String ?? ""
        proto = j["protocol"] as? String ?? ""
        address = j["address"] as? String ?? ""
        port = (j["port"] as? NSNumber)?.intValue ?? 0
        network = j["network"] as? String ?? ""
        security = j["security"] as? String ?? ""
        sni = j["sni"] as? String ?? ""
        latency = (j["latency"] as? NSNumber)?.intValue
    }

    /// Номер для сортировки: proxy → 1, proxy-14 → 14
    var number: Int { tag == "proxy" ? 1 : Int(tag.split(separator: "-").last ?? "") ?? 0 }
    var title: String { "Сервер \(number)" }
    var transport: String {
        [proto, network == proto ? "" : network, security == "none" ? "" : security]
            .filter { !$0.isEmpty }.joined(separator: " · ")
    }
    var host: String { sni.isEmpty || sni == address ? address : "\(address) (\(sni))" }
    var latencySort: Int { latency ?? (testError.isEmpty ? Int.max - 1 : Int.max) }
}

struct RatePoint: Identifiable {
    let id = UUID()
    let time: Date
    let down: Double   // байт/с к телевизору
    let up: Double     // байт/с от телевизора
}

extension Double {
    /// байт/с → «12.3 Мбит/с»
    var bitrate: String {
        let bits = self * 8
        if bits >= 1_000_000 { return String(format: "%.1f Мбит/с", bits / 1_000_000) }
        if bits >= 1_000 { return String(format: "%.0f Кбит/с", bits / 1_000) }
        return String(format: "%.0f бит/с", bits)
    }
}

struct AgentStatus {
    var uptime = 0
    var xray = "—"
    var temp = "—"
    var toTV: Int64 = 0
    var fromTV: Int64 = 0
    var profile = ""
    var profileUpdated: Date?
    var outbounds = 0
    var balancer = ""
    var events = 0

    init() {}
    init(_ j: [String: Any]) {
        uptime = (j["uptime"] as? NSNumber)?.intValue ?? 0
        xray = j["xray"] as? String ?? "—"
        temp = j["temp"] as? String ?? "—"
        toTV = (j["to_tv"] as? NSNumber)?.int64Value ?? 0
        fromTV = (j["from_tv"] as? NSNumber)?.int64Value ?? 0
        profile = j["profile"] as? String ?? ""
        if let u = (j["profile_updated"] as? NSNumber)?.doubleValue, u > 0 { profileUpdated = Date(timeIntervalSince1970: u) }
        outbounds = (j["outbounds"] as? NSNumber)?.intValue ?? 0
        balancer = j["balancer"] as? String ?? ""
        events = (j["events"] as? NSNumber)?.intValue ?? 0
    }
}

/// Профиль из подписки (сами конфиги хранятся на Pi).
struct SubProfile: Identifiable, Hashable {
    var id: String { remarks }
    let remarks: String
    let protocols: String
    let servers: Int

    init(_ j: [String: Any]) {
        remarks = j["remarks"] as? String ?? ""
        protocols = (j["protocols"] as? [String] ?? []).joined(separator: ", ")
        servers = (j["servers"] as? NSNumber)?.intValue ?? 0
    }
}

enum ListKind: String, CaseIterable, Identifiable {
    case block, direct, vpn
    var id: String { rawValue }
    var title: String {
        switch self {
        case .block: return "Заблокированные"
        case .direct: return "Всегда напрямую"
        case .vpn: return "Всегда через VPN"
        }
    }
    var icon: String {
        switch self {
        case .block: return "hand.raised.fill"
        case .direct: return "arrow.right"
        case .vpn: return "lock.shield"
        }
    }
}

/// Настройки приложения (хранятся в ~/Library/Application Support/TVWatch/config.json, доступ 600).
struct AppConfig: Codable {
    var host = "raspberrypi.local"
    var port: UInt16 = 7878
    var key = ""
    var hidden: [String] = []

    static var url: URL {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("TVWatch")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("config.json")
    }

    static func load() -> AppConfig {
        guard let d = try? Data(contentsOf: url), var c = try? JSONDecoder().decode(AppConfig.self, from: d) else { return AppConfig() }
        if !c.key.isEmpty {
            c.save()                       // старый формат: перенести ключ из файла в Связку ключей
        } else {
            c.key = Keychain.get(account: "tvwp") ?? ""
        }
        return c
    }

    func save() {
        if !key.isEmpty { Keychain.set(key, account: "tvwp") }
        var onDisk = self
        onDisk.key = ""                    // в файле ключа нет
        let enc = JSONEncoder(); enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let d = try? enc.encode(onDisk) else { return }
        try? d.write(to: Self.url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: Self.url.path)
    }
}

extension Int64 {
    var mb: String { String(format: "%.1f МБ", Double(self) / 1_048_576) }
}

extension Int {
    var duration: String {
        let d = self / 86400, h = (self % 86400) / 3600, m = (self % 3600) / 60
        if d > 0 { return "\(d) д \(h) ч" }
        if h > 0 { return "\(h) ч \(m) мин" }
        return "\(m) мин"
    }
}
