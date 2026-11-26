import AppKit
import Foundation
import SwiftUI

@MainActor
final class Store: ObservableObject {
    // соединение
    @Published var state: TVWPClient.State = .idle
    @Published var lastMessage = ""

    // данные
    @Published private(set) var events: [ConnEvent] = []
    @Published private(set) var domains: [String: DomainStat] = [:]
    @Published var lists: [ListKind: [String]] = [.block: [], .direct: [], .vpn: []]
    @Published var status = AgentStatus()

    // фильтры ленты
    @Published var paused = false
    @Published var search = ""
    @Published var routeFilter: Route? = nil
    @Published var onlyHost: String? = nil

    // подписка
    @Published var profiles: [SubProfile] = []
    @Published var selectedProfile = ""
    @Published var subStatus = ""
    @Published var subBusy = false
    @Published var subInfo = ""
    @Published var subRelay = ""
    @Published var subError = ""
    @Published var subFetched: Date?

    @Published var config = AppConfig.load()

    // серверы текущего профиля на Pi
    @Published var servers: [ServerInfo] = []
    @Published var selectedServer = ""        // "" = автовыбор
    @Published var serversAuto = true
    @Published var testing = false

    // режим «на весь экран»: панель трафика
    @Published var isFullScreen = false
    @Published private(set) var rates: [RatePoint] = []
    private var lastCounters: (time: Date, toTV: Int64, fromTV: Int64)?

    private(set) var client: TVWPClient?
    private var pendingEvents: [ConnEvent] = []
    private var timers: [Timer] = []
    private var reconnectDelay: TimeInterval = 1
    private var pendingAcks: [UInt32: String] = [:]
    static let maxEvents = 20_000

    init() {
        timers.append(Timer.scheduledTimer(withTimeInterval: 0.3, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.flushEvents() }
        })
        timers.append(Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self, self.state == .ready else { return }
                self.client?.send(.statusGet)
                self.client?.send(.ping, ["t": Int(Date().timeIntervalSince1970)])
            }
        })
        // на весь экран — счётчики трафика каждые 2 секунды, чтобы рисовать скорость
        timers.append(Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self, self.isFullScreen, self.state == .ready else { return }
                self.client?.send(.statusGet)
            }
        })
    }

    private func updateRates(_ s: AgentStatus) {
        let now = Date()
        defer { lastCounters = (now, s.toTV, s.fromTV) }
        guard let last = lastCounters else { return }
        let dt = now.timeIntervalSince(last.time)
        guard dt > 0.5, s.toTV >= last.toTV, s.fromTV >= last.fromTV else { return }
        rates.append(RatePoint(time: now,
                               down: Double(s.toTV - last.toTV) / dt,
                               up: Double(s.fromTV - last.fromTV) / dt))
        rates.removeAll { now.timeIntervalSince($0.time) > 300 }   // последние 5 минут
    }

    /// Счётчики по маршрутам и серверам за то, что сейчас в ленте.
    var routeCounts: [Route: Int] {
        var c: [Route: Int] = [.vpn: 0, .direct: 0, .block: 0]
        for e in events { c[e.route, default: 0] += 1 }
        return c
    }

    var serverCounts: [(String, Int)] {
        var c: [String: Int] = [:]
        for e in events where e.route == .vpn { c[e.out, default: 0] += 1 }
        return c.sorted { $0.value > $1.value }.map { ($0.key, $0.value) }
    }

    var recentDevices: [String] {
        Array(Set(events.suffix(500).map(\.src))).sorted()
    }

    // MARK: соединение

    var isConfigured: Bool { !config.key.isEmpty && !config.host.isEmpty }

    func connect() {
        client?.stop()
        guard isConfigured else { state = .failed("Укажи адрес Pi и ключ в настройках"); return }
        let c = TVWPClient(host: config.host, port: config.port, keyHex: config.key)
        c.onState = { [weak self] s in self?.handleState(s) }
        c.onFrame = { [weak self] f in self?.handle(f) }
        client = c
        state = .connecting
        c.start()
    }

    private func handleState(_ s: TVWPClient.State) {
        state = s
        switch s {
        case .ready:
            reconnectDelay = 1
            client?.send(.subscribe, ["backlog": 2000])
            client?.send(.listsGet)
            client?.send(.statusGet)
            client?.send(.serversGet)
            client?.send(.subGet)
        case .failed:
            let delay = reconnectDelay
            reconnectDelay = min(reconnectDelay * 2, 30)
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
                guard let self, case .failed = self.state else { return }
                self.connect()
            }
        default: break
        }
    }

    private func handle(_ f: Frame) {
        switch MsgType(rawValue: f.type) {
        case .event:
            if let e = ConnEvent(f.json) { pendingEvents.append(e) }
        case .eventBatch:
            for j in f.json["events"] as? [[String: Any]] ?? [] {
                if let e = ConnEvent(j) { pendingEvents.append(e) }
            }
        case .lists:
            for k in ListKind.allCases { lists[k] = f.json[k.rawValue] as? [String] ?? [] }
        case .status:
            status = AgentStatus(f.json)
            updateRates(status)
        case .servers:
            let old = Dictionary(uniqueKeysWithValues: servers.map { ($0.tag, $0) })
            servers = (f.json["servers"] as? [[String: Any]] ?? []).map { j in
                var s = ServerInfo(j)
                if s.latency == nil, let prev = old[s.tag] { s.latency = prev.latency; s.testError = prev.testError }
                return s
            }
            selectedServer = f.json["selected"] as? String ?? ""
            serversAuto = f.json["auto"] as? Bool ?? true
            testing = f.json["testing"] as? Bool ?? false
        case .subProfiles:
            applySubSummary(f.json)
        case .serverTestResult:
            if f.json["done"] as? Bool == true {
                testing = false
                lastMessage = "Проверка серверов завершена"
            } else if let tag = f.json["tag"] as? String, let i = servers.firstIndex(where: { $0.tag == tag }) {
                servers[i].latency = (f.json["ms"] as? NSNumber)?.intValue
                servers[i].testError = f.json["error"] as? String ?? ""
            }
        case .ack:
            let ref = (f.json["ref"] as? NSNumber)?.uint32Value ?? 0
            let what = pendingAcks.removeValue(forKey: ref) ?? ""
            let msg = f.json["msg"] as? String ?? "ok"
            if !what.isEmpty { lastMessage = "\(what): \(Self.human(msg))" }
            if what.hasPrefix("Подписка") { subStatus = Self.human(msg); subBusy = false; client?.send(.statusGet) }
        case .error:
            let ref = (f.json["ref"] as? NSNumber)?.uint32Value ?? 0
            let what = pendingAcks.removeValue(forKey: ref) ?? "Запрос"
            lastMessage = "\(what): ошибка — \(f.json["msg"] as? String ?? "")"
            if what.hasPrefix("Подписка") { subStatus = lastMessage; subBusy = false }
        default: break
        }
    }

    static func human(_ msg: String) -> String {
        switch msg {
        case "applied live": return "применено сразу, без перезапуска"
        case "applied with xray restart": return "применено (Xray перезапущен)"
        case "unchanged": return "без изменений"
        default: return msg
        }
    }

    private func flushEvents() {
        guard !pendingEvents.isEmpty else { return }
        let batch = pendingEvents
        pendingEvents.removeAll()
        for e in batch {
            var d = domains[e.host] ?? DomainStat(host: e.host, count: 0, last: e.time, vpn: 0, direct: 0, block: 0, lastOut: e.out)
            d.count += 1; d.last = max(d.last, e.time); d.lastOut = e.out
            switch e.route { case .vpn: d.vpn += 1; case .direct: d.direct += 1; case .block: d.block += 1 }
            domains[e.host] = d
        }
        guard !paused else { return }
        events.append(contentsOf: batch)
        if events.count > Self.maxEvents { events.removeFirst(events.count - Self.maxEvents) }
    }

    func clearFeed() { events.removeAll(); domains.removeAll() }

    // MARK: фильтрация

    var visibleEvents: [ConnEvent] {
        let hidden = Set(config.hidden)
        let q = search.lowercased()
        return events.reversed().filter { e in
            if hidden.contains(e.host) || hidden.contains(e.baseDomain) { return false }
            if let r = routeFilter, e.route != r { return false }
            if let h = onlyHost, e.host != h, e.baseDomain != h { return false }
            if !q.isEmpty, !e.host.lowercased().contains(q), !e.ip.contains(q), !e.out.lowercased().contains(q) { return false }
            return true
        }
    }

    var sortedDomains: [DomainStat] {
        let q = search.lowercased()
        return domains.values
            .filter { q.isEmpty || $0.host.lowercased().contains(q) }
            .sorted { $0.count > $1.count }
    }

    // MARK: списки (правая кнопка мыши)

    enum Scope { case host, domain }

    static func item(_ host: String, _ scope: Scope) -> String {
        scope == .host ? "full:\(host)" : "domain:\(ConnEvent.baseDomain(host))"
    }

    func listMembership(_ host: String) -> (ListKind, String)? {
        let candidates = ["full:\(host)", "domain:\(ConnEvent.baseDomain(host))", "domain:\(host)"]
        for k in ListKind.allCases {
            if let hit = lists[k]?.first(where: { candidates.contains($0) }) { return (k, hit) }
        }
        return nil
    }

    func add(_ hosts: [String], to kind: ListKind, scope: Scope) {
        let items = Array(Set(hosts.filter { !$0.isEmpty }.map { Self.item($0, scope) })).sorted()
        guard !items.isEmpty, let c = client, state == .ready else { lastMessage = "Нет связи с Pi"; return }
        let seq = c.send(.listEdit, ["list": kind.rawValue, "op": "add", "items": items])
        pendingAcks[seq] = "\(kind.title) ← \(items.joined(separator: ", "))"
    }

    func remove(_ items: [String], from kind: ListKind) {
        guard !items.isEmpty, let c = client, state == .ready else { lastMessage = "Нет связи с Pi"; return }
        let seq = c.send(.listEdit, ["list": kind.rawValue, "op": "remove", "items": items])
        pendingAcks[seq] = "Убрано из «\(kind.title)»: \(items.joined(separator: ", "))"
    }

    func removeFromAllLists(_ hosts: [String]) {
        for h in hosts {
            if let (k, item) = listMembership(h) { remove([item], from: k) }
        }
    }

    func addRaw(_ text: String, to kind: ListKind) {
        var t = text.trimmingCharacters(in: .whitespaces).lowercased()
        guard !t.isEmpty else { return }
        if !t.contains(":") { t = "domain:" + t }
        guard let c = client, state == .ready else { lastMessage = "Нет связи с Pi"; return }
        let seq = c.send(.listEdit, ["list": kind.rawValue, "op": "add", "items": [t]])
        pendingAcks[seq] = "\(kind.title) ← \(t)"
    }

    func hide(_ hosts: [String], scope: Scope) {
        let items = hosts.map { scope == .host ? $0 : ConnEvent.baseDomain($0) }
        config.hidden = Array(Set(config.hidden + items)).sorted()
        config.save()
    }

    func unhide(_ items: [String]) {
        config.hidden.removeAll { items.contains($0) }
        config.save()
    }

    func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    // MARK: выбор сервера

    func selectServer(_ tag: String) {
        guard let c = client, state == .ready else { lastMessage = "Нет связи с Pi"; return }
        let seq = c.send(.serverSelect, ["tag": tag])
        pendingAcks[seq] = tag.isEmpty ? "Сервер" : "Сервер \(tag)"
    }

    func testServers(_ tags: [String] = []) {
        guard let c = client, state == .ready else { lastMessage = "Нет связи с Pi"; return }
        testing = true
        if tags.isEmpty {
            for i in servers.indices { servers[i].latency = nil; servers[i].testError = "" }
        }
        let seq = c.send(.serverTest, ["tags": tags])
        pendingAcks[seq] = "Проверка серверов"
    }

    // MARK: подписка (качает сам Pi через свой сервер-ретранслятор)

    func refreshSubscription() {
        guard let c = client, state == .ready else { subStatus = "Нет связи с Pi"; return }
        guard !subBusy else { return }
        subBusy = true
        subStatus = "Pi запрашивает подписку через \(subRelay.isEmpty ? "сервер" : subRelay)…"
        let seq = c.send(.subRefresh)
        pendingAcks[seq] = "Подписка"
    }

    func selectProfile(_ remarks: String) {
        guard let c = client, state == .ready else { subStatus = "Нет связи с Pi"; return }
        subBusy = true
        subStatus = "Применяю «\(remarks)»…"
        let seq = c.send(.subSelect, ["remarks": remarks])
        pendingAcks[seq] = "Подписка"
    }

    func applySubSummary(_ j: [String: Any]) {
        profiles = (j["profiles"] as? [[String: Any]] ?? []).map(SubProfile.init)
        selectedProfile = j["selected"] as? String ?? ""
        subRelay = j["relay"] as? String ?? ""
        subError = j["error"] as? String ?? ""
        if let busy = j["busy"] as? Bool { subBusy = busy }
        if let t = (j["fetched_at"] as? NSNumber)?.doubleValue, t > 0 { subFetched = Date(timeIntervalSince1970: t) }
        subInfo = Self.userInfo(j["userinfo"] as? String ?? "")
    }

    static func userInfo(_ s: String) -> String {
        guard !s.isEmpty else { return "" }
        var parts: [String: Double] = [:]
        for kv in s.split(separator: ";") {
            let p = kv.split(separator: "=").map { $0.trimmingCharacters(in: .whitespaces) }
            if p.count == 2, let v = Double(p[1]) { parts[p[0]] = v }
        }
        var out: [String] = []
        if let d = parts["download"] { out.append(String(format: "скачано %.1f ГБ", d / 1_073_741_824)) }
        if let e = parts["expire"], e > 0 {
            let f = DateFormatter(); f.dateStyle = .medium; f.locale = Locale(identifier: "ru_RU")
            out.append("оплачено до \(f.string(from: Date(timeIntervalSince1970: e)))")
        }
        return out.joined(separator: ", ")
    }
}
