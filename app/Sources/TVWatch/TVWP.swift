import CryptoKit
import Foundation
import Network

/// TVWP/2 — протокол между приложением и агентом на Raspberry Pi (см. docs/PROTOCOL.md).
/// Рукопожатие: общий ключ (256 бит) + одноразовый ML-KEM-1024 → гибридные ключи сессии (HKDF-SHA256);
/// кадры: ChaCha20-Poly1305, свой ключ на каждое направление.
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
        case .badServerProof: return "Агент не смог доказать подлинность (неверный ключ или подмена)"
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
    static let version: UInt8 = 2
    static let headerLen = 14
    static let aeadTag = 16
    static let preauthMax = 4096
    static let frameMax = 8 * 1024 * 1024
    static let flagEnc: UInt8 = 0x02
    static let kemPubLen = 1568
    static let kemCtLen = 1568

    static let lClient = Data("TVWP2-client".utf8)
    static let lServer = Data("TVWP2-server".utf8)
    static let lC2S = Data("TVWP2 c2s".utf8)
    static let lS2C = Data("TVWP2 s2c".utf8)

    static func sha(_ d: Data) -> Data { Data(SHA256.hash(data: d)) }

    static func header(type: UInt8, flags: UInt8, seq: UInt32, len: UInt32) -> Data {
        var d = Data(magic)
        d.append(version); d.append(type); d.append(flags); d.append(0)
        withUnsafeBytes(of: seq.bigEndian) { d.append(contentsOf: $0) }
        withUnsafeBytes(of: len.bigEndian) { d.append(contentsOf: $0) }
        return d
    }

    /// 4 нулевых байта + 8-байтный номер кадра (у каждого направления свой ключ, поэтому nonce не повторяется).
    static func nonce(_ seq: UInt32) -> ChaChaPoly.Nonce {
        var d = Data(count: 4)
        withUnsafeBytes(of: UInt64(seq).bigEndian) { d.append(contentsOf: $0) }
        return try! ChaChaPoly.Nonce(data: d)
    }

    static func b64(_ d: Data) -> String { d.base64EncodedString() }
    static func unb64(_ s: Any?, max: Int) -> Data? {
        guard let s = s as? String, s.count <= max else { return nil }
        return Data(base64Encoded: s)
    }
}

/// Клиент TVWP/2 поверх Network.framework. Колбэки вызываются в главном потоке.
final class TVWPClient {
    enum State: Equatable { case idle, connecting, authenticating, ready, failed(String) }

    var onState: ((State) -> Void)?
    var onFrame: ((Frame) -> Void)?

    private let host: String
    private let port: UInt16
    private let psk: SymmetricKey
    private let pskData: Data
    private let queue = DispatchQueue(label: "tvwp")
    private var conn: NWConnection?
    private var buffer = Data()
    private var sendKey: SymmetricKey?
    private var recvKey: SymmetricKey?
    private var txSeq: UInt32 = 0
    private var rxSeq: UInt32 = 0
    private var serverNonce = Data()
    private var clientNonce = Data()
    private var kem: MLKEM1024.PrivateKey?
    private var closed = false

    init(host: String, port: UInt16, keyHex: String) {
        self.host = host
        self.port = port
        var d = Data()
        var it = keyHex.makeIterator()
        while let a = it.next(), let b = it.next(), let v = UInt8(String([a, b]), radix: 16) { d.append(v) }
        self.pskData = d
        self.psk = SymmetricKey(data: d)
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
        queue.sync { seqOut = (try? self.sendLocked(type.rawValue, obj)) ?? 0 }
        return seqOut
    }

    private func sendLocked(_ type: UInt8, _ obj: [String: Any]) throws -> UInt32 {
        guard let conn else { return 0 }
        let payload = try JSONSerialization.data(withJSONObject: obj)
        txSeq += 1
        let frame: Data
        if let key = sendKey {
            let hdr = Wire.header(type: type, flags: Wire.flagEnc, seq: txSeq, len: UInt32(payload.count + Wire.aeadTag))
            let box = try ChaChaPoly.seal(payload, using: key, nonce: Wire.nonce(txSeq), authenticating: hdr)
            frame = hdr + box.ciphertext + box.tag
        } else {
            frame = Wire.header(type: type, flags: 0, seq: txSeq, len: UInt32(payload.count)) + payload
        }
        conn.send(content: frame, completion: .contentProcessed { _ in })
        return txSeq
    }

    private func emit(_ s: State) { DispatchQueue.main.async { self.onState?(s) } }

    private func fail(_ msg: String) {
        emit(.failed(msg))
        conn?.cancel()
        conn = nil
        sendKey = nil; recvKey = nil; kem = nil
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
            guard b[0] == Wire.magic[0], b[1] == Wire.magic[1], b[2] == Wire.version else { throw TVWPError.badFrame("версия или сигнатура") }
            let type = b[3], flags = b[4]
            let seq = UInt32(b[6]) << 24 | UInt32(b[7]) << 16 | UInt32(b[8]) << 8 | UInt32(b[9])
            let len = Int(UInt32(b[10]) << 24 | UInt32(b[11]) << 16 | UInt32(b[12]) << 8 | UInt32(b[13]))
            // до входа — только маленькие кадры: подставной «Pi» не забьёт память приложения
            guard len <= (recvKey == nil ? Wire.preauthMax : Wire.frameMax) else { throw TVWPError.badFrame("слишком длинный") }
            guard buffer.count >= Wire.headerLen + len else { return }
            guard seq > rxSeq else { throw TVWPError.badFrame("повтор") }
            let start = buffer.startIndex
            let hdr = buffer.subdata(in: start..<(start + Wire.headerLen))
            var body = buffer.subdata(in: (start + Wire.headerLen)..<(start + Wire.headerLen + len))
            buffer.removeSubrange(start..<(start + Wire.headerLen + len))
            buffer = Data(buffer)

            if let key = recvKey {
                guard flags & Wire.flagEnc != 0, body.count >= Wire.aeadTag else { throw TVWPError.badFrame("без шифрования") }
                let box = try ChaChaPoly.SealedBox(nonce: Wire.nonce(seq),
                                                   ciphertext: body.prefix(body.count - Wire.aeadTag),
                                                   tag: body.suffix(Wire.aeadTag))
                do { body = try ChaChaPoly.open(box, using: key, authenticating: hdr) }
                catch { throw TVWPError.badFrame("подпись") }
            } else if flags != 0 {
                throw TVWPError.badFrame("флаги до входа")
            }
            rxSeq = seq
            let obj = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] ?? [:]
            try handle(Frame(type: type, seq: seq, json: obj))
        }
    }

    private func handle(_ f: Frame) throws {
        switch MsgType(rawValue: f.type) {
        case .hello:
            guard kem == nil, let ns = Wire.unb64(f.json["nonce"], max: 64), ns.count == 32 else { throw TVWPError.badFrame("hello") }
            serverNonce = ns
            var nc = Data(count: 32)
            _ = nc.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
            clientNonce = nc
            let k = try MLKEM1024.PrivateKey()      // одноразовый ключ на это соединение
            kem = k
            let pub = k.publicKey.rawRepresentation
            let mac = HMAC<SHA256>.authenticationCode(for: Wire.lClient + ns + nc + Wire.sha(pub), using: psk)
            _ = try sendLocked(MsgType.auth.rawValue, ["client": "TVWatch.app", "ver": 2, "nonce": Wire.b64(nc),
                                                        "kem_pub": Wire.b64(pub), "mac": Wire.b64(Data(mac))])
        case .authOK:
            guard let k = kem,
                  let ct = Wire.unb64(f.json["ct"], max: 2200), ct.count == Wire.kemCtLen,
                  let proof = Wire.unb64(f.json["proof"], max: 64) else { throw TVWPError.badFrame("auth_ok") }
            let pub = k.publicKey.rawRepresentation
            // проверка за постоянное время
            guard HMAC<SHA256>.isValidAuthenticationCode(proof,
                    authenticating: Wire.lServer + clientNonce + serverNonce + Wire.sha(pub) + Wire.sha(ct), using: psk)
            else { throw TVWPError.badServerProof }
            let ss = try k.decapsulate(ct).withUnsafeBytes { Data($0) }
            let salt = Wire.sha(serverNonce + clientNonce + Wire.sha(pub) + Wire.sha(ct))
            let ikm = SymmetricKey(data: pskData + ss)
            sendKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: ikm, salt: salt, info: Wire.lC2S, outputByteCount: 32)
            recvKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: ikm, salt: salt, info: Wire.lS2C, outputByteCount: 32)
            kem = nil                                 // одноразовый ключ больше не нужен
            emit(.ready)
        case .authFail:
            throw TVWPError.authFailed(f.json["reason"] as? String ?? "")
        default:
            guard recvKey != nil else { throw TVWPError.badFrame("до входа") }
            DispatchQueue.main.async { self.onFrame?(f) }
        }
    }
}
