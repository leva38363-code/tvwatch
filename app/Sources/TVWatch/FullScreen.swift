import AppKit
import Charts
import SwiftUI

/// Сообщает Store, развёрнуто ли окно на весь экран.
struct FullScreenObserver: NSViewRepresentable {
    let onChange: (Bool) -> Void

    func makeNSView(context: Context) -> NSView {
        let v = ObserverView()
        v.onChange = onChange
        return v
    }

    func updateNSView(_ nsView: NSView, context: Context) {}

    final class ObserverView: NSView {
        var onChange: ((Bool) -> Void)?
        private var tokens: [NSObjectProtocol] = []

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            tokens.forEach(NotificationCenter.default.removeObserver)
            tokens.removeAll()
            guard let w = window else { return }
            let nc = NotificationCenter.default
            tokens.append(nc.addObserver(forName: NSWindow.didEnterFullScreenNotification, object: w, queue: .main) { [weak self] _ in
                self?.onChange?(true)
            })
            tokens.append(nc.addObserver(forName: NSWindow.didExitFullScreenNotification, object: w, queue: .main) { [weak self] _ in
                self?.onChange?(false)
            })
            onChange?(w.styleMask.contains(.fullScreen))
        }

        deinit { tokens.forEach(NotificationCenter.default.removeObserver) }
    }
}

/// Панель трафика, видна только в полноэкранном режиме.
struct TrafficPanel: View {
    @EnvironmentObject var store: Store

    var body: some View {
        let s = store.status
        let cur = store.rates.last
        let routes = store.routeCounts
        let total = max(routes.values.reduce(0, +), 1)

        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text("Телевизор").font(.title2.bold())

                HStack(spacing: 12) {
                    BigNumber(title: "Получил", value: s.toTV.mb, sub: cur.map { "↓ \($0.down.bitrate)" } ?? "↓ —", color: .blue)
                    BigNumber(title: "Отправил", value: s.fromTV.mb, sub: cur.map { "↑ \($0.up.bitrate)" } ?? "↑ —", color: .orange)
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text("Скорость, последние 5 минут").font(.headline)
                    if store.rates.count < 2 {
                        Text("Собираю данные…").foregroundStyle(.secondary).frame(height: 140)
                    } else {
                        Chart {
                            ForEach(store.rates) { p in
                                AreaMark(x: .value("Время", p.time), y: .value("Мбит/с", p.down * 8 / 1_000_000))
                                    .foregroundStyle(by: .value("Направление", "к телевизору"))
                                    .interpolationMethod(.monotone)
                                LineMark(x: .value("Время", p.time), y: .value("Мбит/с", p.up * 8 / 1_000_000))
                                    .foregroundStyle(by: .value("Направление", "от телевизора"))
                                    .interpolationMethod(.monotone)
                            }
                        }
                        .chartForegroundStyleScale(["к телевизору": Color.blue.opacity(0.6), "от телевизора": Color.orange])
                        .chartYAxisLabel("Мбит/с")
                        .chartXAxis { AxisMarks(values: .stride(by: .minute)) { _ in AxisGridLine(); AxisValueLabel(format: .dateTime.hour().minute()) } }
                        .frame(height: 140)
                    }
                }

                VStack(alignment: .leading, spacing: 8) {
                    Text("Запросы в ленте").font(.headline)
                    ForEach(Route.allCases, id: \.self) { r in
                        let n = routes[r] ?? 0
                        HStack {
                            RouteTag(route: r)
                            ProgressView(value: Double(n), total: Double(total)).tint(color(r))
                            Text("\(n)").monospacedDigit().frame(width: 50, alignment: .trailing)
                        }
                    }
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text("Чаще всего").font(.headline)
                    ForEach(store.sortedDomains.prefix(8)) { d in
                        HStack {
                            Text(d.host).lineLimit(1).truncationMode(.middle)
                            Spacer()
                            if d.block > 0 { Image(systemName: "hand.raised.fill").foregroundStyle(.red).font(.caption) }
                            Text("\(d.count)").monospacedDigit().foregroundStyle(.secondary)
                        }
                        .contextMenu { HostMenu(hosts: [d.host]) }
                    }
                    if store.domains.isEmpty { Text("Пока пусто").foregroundStyle(.secondary) }
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text("Серверы VPN").font(.headline)
                    let servers = store.serverCounts
                    if servers.isEmpty {
                        Text("Пока пусто").foregroundStyle(.secondary)
                    } else {
                        Chart(servers.prefix(8), id: \.0) { item in
                            BarMark(x: .value("Запросов", item.1), y: .value("Сервер", item.0))
                                .foregroundStyle(Color.blue.gradient)
                        }
                        .frame(height: CGFloat(min(servers.count, 8)) * 22 + 20)
                    }
                    Text("Профиль: \(s.profile.isEmpty ? "—" : s.profile)").font(.caption).foregroundStyle(.secondary)
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text("Pi").font(.headline)
                    LabeledContent("Без перезагрузки", value: s.uptime.duration)
                    LabeledContent("Температура", value: s.temp)
                    LabeledContent("VPN", value: s.xray == "active" ? "работает" : s.xray)
                    LabeledContent("Устройства", value: store.recentDevices.joined(separator: ", "))
                }
                .font(.callout)
            }
            .padding(16)
        }
        .frame(width: 360)
        .background(.background.secondary)
    }

    func color(_ r: Route) -> Color {
        switch r { case .vpn: return .blue; case .direct: return .green; case .block: return .red }
    }
}

struct BigNumber: View {
    let title: String
    let value: String
    let sub: String
    let color: Color
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.title.bold()).monospacedDigit().foregroundStyle(color)
            Text(sub).font(.callout).monospacedDigit().foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(color.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
    }
}
