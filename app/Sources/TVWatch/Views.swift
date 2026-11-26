import SwiftUI

enum NavSection: Hashable {
    case live, domains, list(ListKind), hidden, servers, subscription, status
}

struct ContentView: View {
    @EnvironmentObject var store: Store
    @State private var section: NavSection? = .live

    var body: some View {
        NavigationSplitView {
            List(selection: $section) {
                Section("Наблюдение") {
                    Label("Поток запросов", systemImage: "waveform.path.ecg").tag(NavSection.live)
                    Label("Домены", systemImage: "chart.bar.xaxis").tag(NavSection.domains)
                }
                Section("Фильтры на Pi") {
                    ForEach(ListKind.allCases) { k in
                        Label(k.title, systemImage: k.icon)
                            .badge(store.lists[k]?.count ?? 0)
                            .tag(NavSection.list(k))
                    }
                    Label("Скрытые в ленте", systemImage: "eye.slash")
                        .badge(store.config.hidden.count)
                        .tag(NavSection.hidden)
                }
                Section("VPN") {
                    Label("Выбор сервера", systemImage: "server.rack")
                        .badge(store.selectedServer.isEmpty ? Text("авто") : Text("ручной"))
                        .tag(NavSection.servers)
                    Label("Подписка и серверы", systemImage: "antenna.radiowaves.left.and.right").tag(NavSection.subscription)
                    Label("Состояние Pi", systemImage: "cpu").tag(NavSection.status)
                }
            }
            .navigationSplitViewColumnWidth(min: 200, ideal: 230)
        } detail: {
            HStack(spacing: 0) {
                Group {
                    switch section ?? .live {
                    case .live: LiveView()
                    case .domains: DomainsView()
                    case .list(let k): ListEditor(kind: k)
                    case .hidden: HiddenEditor()
                    case .servers: ServersView()
                    case .subscription: SubscriptionView()
                    case .status: StatusView()
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                if store.isFullScreen {
                    Divider()
                    TrafficPanel().transition(.move(edge: .trailing))
                }
            }
            .animation(.default, value: store.isFullScreen)
        }
        .background(FullScreenObserver { full in
            store.isFullScreen = full
            if full { store.client?.send(.statusGet) }
        })
        .toolbar {
            ToolbarItem(placement: .navigation) { ConnectionBadge() }
            ToolbarItem {
                Button { store.refreshSubscription() } label: {
                    Label("Обновить подписку", systemImage: "arrow.triangle.2.circlepath")
                }
                .help("Скачать подписку с HWID и обновить серверы на Pi")
                .disabled(store.subBusy)
            }
        }
        .safeAreaInset(edge: .bottom) {
            if !store.lastMessage.isEmpty {
                HStack {
                    Image(systemName: "info.circle")
                    Text(store.lastMessage).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Button { store.lastMessage = "" } label: { Image(systemName: "xmark") }.buttonStyle(.borderless)
                }
                .font(.callout)
                .padding(.horizontal, 12).padding(.vertical, 6)
                .background(.bar)
            }
        }
        .frame(minWidth: 980, minHeight: 600)
    }
}

struct ConnectionBadge: View {
    @EnvironmentObject var store: Store
    var body: some View {
        HStack(spacing: 6) {
            Circle().fill(color).frame(width: 8, height: 8)
            Text(text).font(.callout).foregroundStyle(.secondary).lineLimit(1)
        }
        .help(text)
    }
    var color: Color {
        switch store.state {
        case .ready: return .green
        case .connecting, .authenticating: return .orange
        case .failed: return .red
        case .idle: return .gray
        }
    }
    var text: String {
        switch store.state {
        case .ready: return "Pi \(store.config.host)"
        case .connecting: return "Подключение…"
        case .authenticating: return "Проверка ключа…"
        case .failed(let e): return e
        case .idle: return "Не подключено"
        }
    }
}

struct RouteTag: View {
    let route: Route
    var body: some View {
        Text(route.title)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 6).padding(.vertical, 1)
            .background(color.opacity(0.18), in: Capsule())
            .foregroundStyle(color)
    }
    var color: Color {
        switch route { case .vpn: return .blue; case .direct: return .green; case .block: return .red }
    }
}

/// Контекстное меню для доменов: общее для ленты и статистики.
struct HostMenu: View {
    @EnvironmentObject var store: Store
    let hosts: [String]

    var body: some View {
        let one = hosts.count == 1 ? hosts[0] : nil
        let base = one.map { ConnEvent.baseDomain($0) }
        if let one {
            Text(one)
            if let (k, item) = store.listMembership(one) {
                Text("Сейчас в «\(k.title)»: \(item)")
            }
        } else {
            Text("Выбрано: \(hosts.count)")
        }
        Divider()
        Menu("Заблокировать") {
            Button("Только этот адрес") { store.add(hosts, to: .block, scope: .host) }
            Button("Весь домен \(base.map { "*.\($0)" } ?? "")") { store.add(hosts, to: .block, scope: .domain) }
        }
        Menu("Всегда напрямую (без VPN)") {
            Button("Только этот адрес") { store.add(hosts, to: .direct, scope: .host) }
            Button("Весь домен \(base.map { "*.\($0)" } ?? "")") { store.add(hosts, to: .direct, scope: .domain) }
        }
        Menu("Всегда через VPN") {
            Button("Только этот адрес") { store.add(hosts, to: .vpn, scope: .host) }
            Button("Весь домен \(base.map { "*.\($0)" } ?? "")") { store.add(hosts, to: .vpn, scope: .domain) }
        }
        Button("Убрать из списков фильтров") { store.removeFromAllLists(hosts) }
            .disabled(!hosts.contains { store.listMembership($0) != nil })
        Divider()
        if let one {
            Button("Показать только \(base ?? one)") { store.onlyHost = base ?? one }
        }
        Menu("Скрыть из ленты") {
            Button("Этот адрес") { store.hide(hosts, scope: .host) }
            Button("Весь домен") { store.hide(hosts, scope: .domain) }
        }
        Divider()
        Button("Скопировать") { store.copy(hosts.joined(separator: "\n")) }
    }
}

struct LiveView: View {
    @EnvironmentObject var store: Store
    @State private var selection = Set<ConnEvent.ID>()

    var body: some View {
        let rows = Array(store.visibleEvents.prefix(5000))
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Picker("Маршрут", selection: $store.routeFilter) {
                    Text("Все").tag(Route?.none)
                    ForEach(Route.allCases, id: \.self) { r in Text(r.title).tag(Route?.some(r)) }
                }
                .pickerStyle(.segmented)
                .frame(width: 300)
                if let h = store.onlyHost {
                    Button { store.onlyHost = nil } label: { Label(h, systemImage: "xmark.circle.fill") }
                        .buttonStyle(.bordered)
                }
                Spacer()
                Text("\(rows.count) из \(store.events.count)").foregroundStyle(.secondary).monospacedDigit()
                Toggle(isOn: $store.paused) { Label("Пауза", systemImage: "pause.fill") }.toggleStyle(.button)
                Button { store.clearFeed() } label: { Label("Очистить", systemImage: "trash") }
            }
            .padding(10)
            Table(rows, selection: $selection) {
                TableColumn("Время") { e in Text(e.time, format: .dateTime.hour().minute().second()).monospacedDigit() }
                    .width(70)
                TableColumn("Домен") { e in
                    HStack(spacing: 4) {
                        if let (k, _) = store.listMembership(e.host) {
                            Image(systemName: k.icon).foregroundStyle(.secondary).help(k.title)
                        }
                        Text(e.host).fontWeight(e.isIP ? .regular : .medium)
                    }
                }
                .width(min: 200, ideal: 320)
                TableColumn("Маршрут") { e in RouteTag(route: e.route) }.width(80)
                TableColumn("Сервер") { e in Text(e.out).foregroundStyle(.secondary) }.width(80)
                TableColumn("IP") { e in Text(e.ip.isEmpty ? "—" : "\(e.ip):\(e.port)").monospacedDigit().foregroundStyle(.secondary) }
                    .width(min: 120, ideal: 150)
                TableColumn("Правило") { e in Text(ruleTitle(e.rule)).foregroundStyle(.secondary) }.width(min: 80, ideal: 120)
                TableColumn("Устройство") { e in Text(e.src).foregroundStyle(.secondary) }.width(90)
            }
            .contextMenu(forSelectionType: ConnEvent.ID.self) { ids in
                let hosts = Array(Set(rows.filter { ids.contains($0.id) }.map(\.host))).sorted()
                if !hosts.isEmpty { HostMenu(hosts: hosts) }
            } primaryAction: { ids in
                if let e = rows.first(where: { ids.contains($0.id) }) { store.onlyHost = e.baseDomain }
            }
        }
        .searchable(text: $store.search, prompt: "Домен, IP или сервер")
        .navigationTitle("Поток запросов")
    }

    func ruleTitle(_ r: String) -> String {
        switch r {
        case "u-block": return "твой блок"
        case "u-direct": return "твоё «напрямую»"
        case "u-vpn": return "твоё «VPN»"
        case "ads": return "реклама/слежка"
        case "": return "—"
        default: return r.hasPrefix("base-") ? "подписка" : r
        }
    }
}

struct DomainsView: View {
    @EnvironmentObject var store: Store
    @State private var selection = Set<DomainStat.ID>()

    var body: some View {
        let rows = store.sortedDomains
        Table(rows, selection: $selection) {
            TableColumn("Домен") { d in
                HStack(spacing: 4) {
                    if let (k, _) = store.listMembership(d.host) { Image(systemName: k.icon).foregroundStyle(.secondary) }
                    Text(d.host).fontWeight(.medium)
                }
            }
            .width(min: 220, ideal: 340)
            TableColumn("Запросов") { d in Text("\(d.count)").monospacedDigit() }.width(70)
            TableColumn("VPN") { d in Text(d.vpn > 0 ? "\(d.vpn)" : "").monospacedDigit().foregroundStyle(.blue) }.width(50)
            TableColumn("Напрямую") { d in Text(d.direct > 0 ? "\(d.direct)" : "").monospacedDigit().foregroundStyle(.green) }.width(70)
            TableColumn("Блок") { d in Text(d.block > 0 ? "\(d.block)" : "").monospacedDigit().foregroundStyle(.red) }.width(50)
            TableColumn("Последний") { d in Text(d.last, format: .dateTime.hour().minute().second()).monospacedDigit() }.width(80)
            TableColumn("Сервер") { d in Text(d.lastOut).foregroundStyle(.secondary) }.width(80)
        }
        .contextMenu(forSelectionType: DomainStat.ID.self) { ids in
            if !ids.isEmpty { HostMenu(hosts: Array(ids).sorted()) }
        }
        .searchable(text: $store.search, prompt: "Домен")
        .navigationTitle("Домены (\(rows.count))")
    }
}

struct ListEditor: View {
    @EnvironmentObject var store: Store
    let kind: ListKind
    @State private var newItem = ""
    @State private var selection = Set<String>()

    var body: some View {
        let items = store.lists[kind] ?? []
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                TextField("example.com или full:host.example.com", text: $newItem)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(add)
                Button("Добавить", action: add).disabled(newItem.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .padding(10)
            Text(hint).font(.caption).foregroundStyle(.secondary).padding(.horizontal, 10).padding(.bottom, 6)
            List(items, id: \.self, selection: $selection) { item in
                HStack {
                    Text(item.hasPrefix("domain:") ? "*.\(item.dropFirst(7))" : String(item.drop { $0 != ":" }.dropFirst()))
                        .fontWeight(.medium)
                    Spacer()
                    Text(item.hasPrefix("domain:") ? "домен целиком" : "точный адрес").foregroundStyle(.secondary).font(.caption)
                }
            }
            .contextMenu(forSelectionType: String.self) { ids in
                if !ids.isEmpty {
                    Button("Убрать из списка") { store.remove(Array(ids), from: kind) }
                    Button("Скопировать") { store.copy(ids.sorted().joined(separator: "\n")) }
                }
            }
            .onDeleteCommand { store.remove(Array(selection), from: kind) }
        }
        .navigationTitle("\(kind.title) (\(items.count))")
    }

    var hint: String {
        switch kind {
        case .block: return "Запросы к этим адресам телевизор не получит."
        case .direct: return "Пойдут мимо VPN, через обычный интернет."
        case .vpn: return "Всегда через VPN, даже если по правилам подписки шли бы напрямую или блокировались как реклама."
        }
    }

    func add() { store.addRaw(newItem, to: kind); newItem = "" }
}

struct HiddenEditor: View {
    @EnvironmentObject var store: Store
    @State private var selection = Set<String>()
    var body: some View {
        List(store.config.hidden, id: \.self, selection: $selection) { Text($0) }
            .contextMenu(forSelectionType: String.self) { ids in
                Button("Снова показывать") { store.unhide(Array(ids)) }
            }
            .onDeleteCommand { store.unhide(Array(selection)) }
            .overlay { if store.config.hidden.isEmpty { Text("Скрытых нет. Скрыть домен из ленты: правая кнопка → «Скрыть из ленты».").foregroundStyle(.secondary) } }
            .navigationTitle("Скрытые в ленте")
    }
}

struct SubscriptionView: View {
    @EnvironmentObject var store: Store
    @State private var selection: SubProfile.ID?

    var body: some View {
        Form {
            Section("Подписка") {
                LabeledContent("Откуда", value: store.subRelay.isEmpty ? "сервер-ретранслятор не настроен на Pi" : "Pi → \(store.subRelay) → провайдер VPN")
                if let t = store.subFetched {
                    LabeledContent("Обновлена", value: t.formatted(date: .abbreviated, time: .shortened))
                }
                if !store.subInfo.isEmpty { LabeledContent("Аккаунт", value: store.subInfo) }
                HStack {
                    Button { store.refreshSubscription() } label: {
                        Label("Обновить сейчас", systemImage: "arrow.triangle.2.circlepath")
                    }
                    .disabled(store.subBusy || store.state != .ready)
                    if store.subBusy { ProgressView().controlSize(.small) }
                    Text(store.subStatus).foregroundStyle(.secondary).lineLimit(2)
                }
                if !store.subError.isEmpty {
                    Label(store.subError, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                }
                Text("HWID и адрес подписки хранятся только на твоём сервере. Подписка обновляется при каждом запуске приложения, по кнопке (⌘R) и сама на Pi раз в 6 часов. Если серверы не изменились, Pi ничего не перезапускает.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Профиль для телевизора (сейчас на Pi: \(store.status.profile.isEmpty ? "—" : store.status.profile))") {
                if store.profiles.isEmpty {
                    Text("Список появится после обновления подписки.").foregroundStyle(.secondary)
                } else {
                    Table(store.profiles, selection: $selection) {
                        TableColumn("") { p in
                            if p.remarks == store.selectedProfile { Image(systemName: "checkmark").foregroundStyle(.tint) }
                        }.width(20)
                        TableColumn("Название") { p in Text(p.remarks) }.width(min: 220, ideal: 300)
                        TableColumn("Протоколы") { p in Text(p.protocols).foregroundStyle(.secondary) }
                        TableColumn("Серверов") { p in Text("\(p.servers)").monospacedDigit() }.width(70)
                    }
                    .contextMenu(forSelectionType: SubProfile.ID.self) { ids in
                        if let id = ids.first {
                            Button("Применить на Pi") { store.selectProfile(id) }
                        }
                    } primaryAction: { ids in
                        if let id = ids.first { store.selectProfile(id) }
                    }
                    .frame(minHeight: 260)
                    Text("Двойной щелчок или правая кнопка → «Применить на Pi».").font(.caption).foregroundStyle(.secondary)
                }
            }
            Section("Подключение к Pi") {
                TextField("Адрес Pi", text: $store.config.host)
                TextField("Порт", value: $store.config.port, format: .number.grouping(.never))
                SecureField("Ключ TVWP", text: $store.config.key)
                Button("Сохранить и переподключиться") { store.config.save(); store.connect() }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Подписка и серверы")
    }
}

struct StatusView: View {
    @EnvironmentObject var store: Store
    var body: some View {
        let s = store.status
        Form {
            Section("Raspberry Pi") {
                LabeledContent("Работает без перезагрузки", value: s.uptime.duration)
                LabeledContent("Температура", value: s.temp)
                LabeledContent("Xray (VPN)", value: s.xray == "active" ? "работает" : s.xray)
            }
            Section("Телевизор") {
                LabeledContent("Получил через Pi", value: s.toTV.mb)
                LabeledContent("Отправил", value: s.fromTV.mb)
                LabeledContent("Запросов замечено агентом", value: "\(s.events)")
            }
            Section("VPN") {
                LabeledContent("Профиль", value: s.profile.isEmpty ? "—" : s.profile)
                if let u = s.profileUpdated { LabeledContent("Обновлён", value: u.formatted(date: .abbreviated, time: .shortened)) }
                LabeledContent("Серверов в конфиге", value: "\(max(s.outbounds - 2, 0))")
                if !s.balancer.isEmpty {
                    Text(s.balancer).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled)
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Состояние Pi")
    }
}
