import CryptoKit
import Foundation
import Network

/// TVWP/1 — протокол между приложением и агентом на Raspberry Pi (см. PROTOCOL.md).
enum MsgType: UInt8 {
    case hello = 0x01, auth = 0x02, authOK = 0x03, authFail = 0x04, ack = 0x05, error = 0x06
    case subscribe = 0x10, event = 0x11, eventBatch = 0x12, unsubscribe = 0x13
    case listsGet = 0x20, lists = 0x21, listEdit = 0x22
    case statusGet = 0x30, status = 0x31
    case configPush = 0x40
    case serversGet = 0x50, servers = 0x51, serverSelect = 0x52, serverTest = 0x53, serverTestResult = 0x54
    case subGet = 0x60, subProfiles = 0x61, subRefresh = 0x62, subSelect = 0x63
    case ping = 0x7E, pong = 0x7F
}

enum TVWPError: LocalizedError {
    case badFrame(String), authFailed(String), badServerProof
    var errorDescription: String? {
        switch self {
        case .badFrame(let s): return "Повреждённый кадр: \(s)"
        case .authFailed(let s): return "Агент отклонил ключ: \(s)"
        case .badServerProof: return "Агент не смог доказать подлинность (неверный ключ?)"
        }
    }
}

struct Frame {
    let type: UInt8
    let seq: UInt32
    let json: [String: Any]
}

enum Wire {
    static let magic: [UInt8] = [0x54, 0x57] // "TW"
    static let version: UInt8 = 1
    static let headerLen = 14
    static let tagLen = 16
    static let maxLen = 8 * 1024 * 1024
    static let flagZlib: UInt8 = 0x01

    static func hmac(_ key: SymmetricKey, _ parts: Data...) -> Data {
        var h = HMAC<SHA256>(key: key)
        for p in parts { h.update(data: p) }
        return Data(h.finalize())
    }

    static func header(type: UInt8, flags: UInt8, seq: UInt32, len: UInt32) -> Data {
        var d = Data(magic)
        d.append(version); d.append(type); d.append(flags); d.append(0)
        withUnsafeBytes(of: seq.bigEndian) { d.append(contentsOf: $0) }
        withUnsafeBytes(of: len.bigEndian) { d.append(contentsOf: $0) }
        return d
    }

    /// zlib (RFC 1950) → данные. Foundation умеет «сырой» deflate, поэтому снимаем заголовок и adler32.
    static func inflate(_ data: Data) throws -> Data {
        guard data.count > 6 else { throw TVWPError.badFrame("short zlib") }
        let raw = data.subdata(in: (data.startIndex + 2)..<(data.endIndex - 4))
        return try (raw as NSData).decompressed(using: .zlib) as Data
    }

    static func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
    static func unhex(_ s: String) -> Data? {
        var out = Data(); var it = s.makeIterator()
        while let a = it.next() {
            guard let b = it.next(), let v = UInt8(String([a, b]), radix: 16) else { return nil }
            out.append(v)
        }
        return out
    }
}

/// Клиент TVWP/1 поверх Network.framework. Колбэки вызываются в главном потоке.
final class TVWPClient {
    enum State: Equatable { case idle, connecting, authenticating, ready, failed(String) }

    var onState: ((State) -> Void)?
    var onFrame: ((Frame) -> Void)?

    private let host: String
    private let port: UInt16
    private let key: SymmetricKey
    private let queue = DispatchQueue(label: "tvwp")
    private var conn: NWConnection?
    private var buffer = Data()
    private var sessionKey: SymmetricKey?
    private var txSeq: UInt32 = 0
    private var rxSeq: Int64 = -1
    private var serverNonce = Data()
    private var clientNonce = Data()
    private var closed = false

    init(host: String, port: UInt16, keyHex: String) {
        self.host = host
        self.port = port
        self.key = SymmetricKey(data: Wire.unhex(keyHex) ?? Data())
    }

    func start() {
        let c = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
        conn = c
        c.stateUpdateHandler = { [weak self] st in
            guard let self else { return }
            switch st {
            case .ready: self.emit(.authenticating); self.receive()
            case .waiting(let e): self.emit(.failed("Нет связи с Pi: \(e.localizedDescription)"))
            case .failed(let e): self.emit(.failed(e.localizedDescription))
            case .preparing: self.emit(.connecting)
            default: break
            }
        }
        c.start(queue: queue)
    }

    func stop() {
        queue.async {
            self.closed = true
            self.conn?.cancel()
            self.conn = nil
        }
    }

    @discardableResult
    func send(_ type: MsgType, _ obj: [String: Any] = [:]) -> UInt32 {
        var seqOut: UInt32 = 0
        queue.sync {
            seqOut = self.sendLocked(type.rawValue, obj)
        }
        return seqOut
    }

    private func sendLocked(_ type: UInt8, _ obj: [String: Any]) -> UInt32 {
        guard let conn else { return 0 }
        let payload = (try? JSONSerialization.data(withJSONObject: obj)) ?? Data("{}".utf8)
        txSeq += 1
        let hdr = Wire.header(type: type, flags: 0, seq: txSeq, len: UInt32(payload.count))
        let tag: Data
        if let sk = sessionKey { tag = Wire.hmac(sk, hdr, payload).prefix(Wire.tagLen) } else { tag = Data(count: Wire.tagLen) }
        conn.send(content: hdr + payload + tag, completion: .contentProcessed { _ in })
        return txSeq
    }

    private func emit(_ s: State) { DispatchQueue.main.async { self.onState?(s) } }

    private func fail(_ msg: String) {
        emit(.failed(msg))
        conn?.cancel()
        conn = nil
    }

    private func receive() {
        conn?.receive(minimumIncompleteLength: 1, maximumLength: 1 << 20) { [weak self] data, _, done, err in
            guard let self, !self.closed else { return }
            if let data, !data.isEmpty {
                self.buffer.append(data)
                do { try self.drain() } catch { self.fail(error.localizedDescription); return }
            }
            if let err { self.fail(err.localizedDescription); return }
            if done { self.fail("Агент закрыл соединение"); return }
            self.receive()
        }
    }

    private func drain() throws {
        while buffer.count >= Wire.headerLen {
            let b = [UInt8](buffer.prefix(Wire.headerLen))
            guard b[0] == Wire.magic[0], b[1] == Wire.magic[1], b[2] == Wire.version else { throw TVWPError.badFrame("magic") }
            let type = b[3], flags = b[4]
            let seq = UInt32(b[6]) << 24 | UInt32(b[7]) << 16 | UInt32(b[8]) << 8 | UInt32(b[9])
            let len = Int(UInt32(b[10]) << 24 | UInt32(b[11]) << 16 | UInt32(b[12]) << 8 | UInt32(b[13]))
            guard len <= Wire.maxLen else { throw TVWPError.badFrame("too long") }
            let total = Wire.headerLen + len + Wire.tagLen
            guard buffer.count >= total else { return }
            let start = buffer.startIndex
            let hdr = buffer.subdata(in: start..<(start + Wire.headerLen))
            var payload = buffer.subdata(in: (start + Wire.headerLen)..<(start + Wire.headerLen + len))
            let tag = buffer.subdata(in: (start + Wire.headerLen + len)..<(start + total))
            buffer.removeSubrange(start..<(start + total))
            buffer = Data(buffer) // сбросить индексы

            if let sk = sessionKey {
                guard Wire.hmac(sk, hdr, payload).prefix(Wire.tagLen) == tag else { throw TVWPError.badFrame("подпись") }
                guard Int64(seq) > rxSeq else { throw TVWPError.badFrame("повтор") }
            }
            rxSeq = Int64(seq)
            if flags & Wire.flagZlib != 0 { payload = try Wire.inflate(payload) }
            let obj = (try? JSONSerialization.jsonObject(with: payload)) as? [String: Any] ?? [:]
            try handle(Frame(type: type, seq: seq, json: obj))
        }
    }

    private func handle(_ f: Frame) throws {
        switch MsgType(rawValue: f.type) {
        case .hello:
            guard let ns = (f.json["nonce"] as? String).flatMap(Wire.unhex) else { throw TVWPError.badFrame("hello") }
            serverNonce = ns
            var nc = Data(count: 16)
            _ = nc.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
            clientNonce = nc
            let mac = Wire.hmac(key, Data("TVWP1-client|".utf8), ns, nc)
            _ = sendLocked(MsgType.auth.rawValue, ["client": "TVWatch.app", "ver": 1, "nonce": Wire.hex(nc), "mac": Wire.hex(mac)])
        case .authOK:
            let expected = Wire.hmac(key, Data("TVWP1-server|".utf8), clientNonce, serverNonce)
            guard (f.json["proof"] as? String).flatMap(Wire.unhex) == expected else { throw TVWPError.badServerProof }
            sessionKey = SymmetricKey(data: Wire.hmac(key, Data("TVWP1-session|".utf8), serverNonce, clientNonce))
            emit(.ready)
        case .authFail:
            throw TVWPError.authFailed(f.json["reason"] as? String ?? "")
        default:
            guard sessionKey != nil else { throw TVWPError.badFrame("до авторизации") }
            DispatchQueue.main.async { self.onFrame?(f) }
        }
    }
}
