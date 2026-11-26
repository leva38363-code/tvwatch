import SwiftUI

/// Ручной выбор сервера VPN для телевизора.
struct ServersView: View {
    @EnvironmentObject var store: Store
    @State private var selection = Set<ServerInfo.ID>()
    @State private var sortOrder = [KeyPathComparator(\ServerInfo.number)]

    var body: some View {
        let rows = store.servers.sorted(using: sortOrder)
        VStack(spacing: 0) {
            header
            Divider()
            Table(rows, selection: $selection, sortOrder: $sortOrder) {
                TableColumn("", value: \.number) { s in
                    if s.tag == store.selectedServer {
                        Image(systemName: "checkmark.circle.fill").foregroundStyle(.tint).help("Выбран вручную")
                    }
                }
                .width(24)
                TableColumn("Сервер", value: \.number) { s in Text(s.title).fontWeight(.medium) }
                    .width(min: 80, ideal: 90)
                TableColumn("Задержка", value: \.latencySort) { s in LatencyLabel(server: s, testing: store.testing) }
                    .width(min: 90, ideal: 100)
                TableColumn("Тип", value: \.proto) { s in Text(s.transport).foregroundStyle(.secondary) }
                    .width(min: 140, ideal: 190)
                TableColumn("Адрес", value: \.address) { s in Text(s.host).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle) }
                    .width(min: 200, ideal: 320)
                TableColumn("Тег", value: \.tag) { s in Text(s.tag).font(.caption).foregroundStyle(.tertiary) }
                    .width(70)
            }
            .contextMenu(forSelectionType: ServerInfo.ID.self) { ids in
                if let tag = ids.first {
                    Button("Использовать для телевизора") { store.selectServer(tag) }
                        .disabled(!store.serversAuto || tag == store.selectedServer)
                    Button("Проверить задержку") { store.testServers(Array(ids)) }
                        .disabled(store.testing)
                    Divider()
                    Button("Вернуть автовыбор") { store.selectServer("") }
                        .disabled(store.selectedServer.isEmpty)
                }
            } primaryAction: { ids in
                if let tag = ids.first, store.serversAuto { store.selectServer(tag) }
            }
        }
        .navigationTitle("Серверы (\(store.servers.count))")
    }

    var header: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                if store.selectedServer.isEmpty {
                    Label("Автовыбор: Pi сам берёт самый быстрый сервер", systemImage: "wand.and.stars")
                        .font(.headline)
                } else {
                    let s = store.servers.first { $0.tag == store.selectedServer }
                    Label("Закреплён \(s?.title ?? store.selectedServer)", systemImage: "pin.fill")
                        .font(.headline)
                    if let s { Text("\(s.transport) · \(s.host)").font(.caption).foregroundStyle(.secondary) }
                }
                if !store.serversAuto {
                    Text("В этом профиле один сервер — выбери другой профиль в «Подписка и серверы».")
                        .font(.caption).foregroundStyle(.orange)
                }
            }
            Spacer()
            if store.testing { ProgressView().controlSize(.small) }
            Button { store.testServers() } label: { Label("Проверить все", systemImage: "speedometer") }
                .disabled(store.testing || store.servers.isEmpty)
                .help("Проверка идёт через отдельный тестовый вход и не мешает телевизору")
            Button { store.selectServer("") } label: { Label("Автовыбор", systemImage: "wand.and.stars") }
                .disabled(store.selectedServer.isEmpty)
            Button {
                if let best = store.servers.filter({ $0.latency != nil }).min(by: { $0.latency! < $1.latency! }) {
                    store.selectServer(best.tag)
                }
            } label: { Label("Самый быстрый", systemImage: "hare") }
                .disabled(!store.servers.contains { $0.latency != nil } || !store.serversAuto)
                .help("Закрепить сервер с наименьшей задержкой по последней проверке")
        }
        .padding(12)
    }
}

struct LatencyLabel: View {
    let server: ServerInfo
    let testing: Bool
    var body: some View {
        if let ms = server.latency {
            Text("\(ms) мс").monospacedDigit().foregroundStyle(ms < 300 ? .green : ms < 800 ? .orange : .red)
        } else if !server.testError.isEmpty {
            Text(server.testError).foregroundStyle(.red)
        } else {
            Text(testing ? "…" : "—").foregroundStyle(.secondary)
        }
    }
}
