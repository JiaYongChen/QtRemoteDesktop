#include "Protocol.h"
#include "../crypto/SessionCrypto.h"
#include <QtCore/QDataStream>
#include <QtCore/QIODevice>
#include <QtCore/QString>
#include <QtCore/QCryptographicHash>
#include <QtCore/QDateTime>
#include <QtCore/QtEndian>
#include "../logging/LoggingCategories.h"
#include "../config/NetworkConstants.h"
#include <cstring>

// ─────────────────────────────────────────────
// Protocol::createMessage
//
// 消息帧格式：
//   [明文 MessageHeader (28字节)]
//   [payload]
//     • crypto == nullptr : payload = message.encode()（明文）
//     • crypto != nullptr : payload = SessionCrypto::encrypt(message.encode())
//                           格式：nonce(12) || ciphertext || tag(16)
// ─────────────────────────────────────────────
QByteArray Protocol::createMessage(MessageType type, const IMessageCodec& message,
                                   SessionCrypto* crypto) {
    // 1. 编码消息载荷
    QByteArray plainPayload = message.encode();

    // 2. 加密（如果会话已建立）
    QByteArray transmittedPayload;
    if (crypto && crypto->isReady()) {
        transmittedPayload = crypto->encrypt(plainPayload);
        if (transmittedPayload.isEmpty()) {
            qWarning(lcProtocol) << "createMessage: 加密失败";
            return {};
        }
    } else {
        transmittedPayload = plainPayload;
    }

    // 3. 构建明文消息头
    MessageHeader header;
    header.magic     = PROTOCOL_MAGIC;
    header.version   = PROTOCOL_VERSION;
    header.type      = type;
    header.length    = static_cast<quint32>(transmittedPayload.size());
    header.timestamp = static_cast<quint64>(QDateTime::currentMSecsSinceEpoch());
    header.checksum  = calculateChecksum(transmittedPayload);

    return header.encode() + transmittedPayload;
}

// ─────────────────────────────────────────────
// Protocol::parseMessage
// ─────────────────────────────────────────────
qsizetype Protocol::parseMessage(const QByteArray& data, MessageHeader& header,
                                  QByteArray& payload, SessionCrypto* crypto) {
    qsizetype totalSize = validateReceivedDataIntegrity(data, header);
    if (totalSize <= 0) return totalSize;

    QByteArray received = data.mid(static_cast<qsizetype>(SERIALIZED_HEADER_SIZE),
                                   static_cast<qsizetype>(header.length));

    if (crypto && crypto->isReady()) {
        payload = crypto->decrypt(received);
        if (payload.isEmpty()) {
            qWarning(lcProtocol) << "parseMessage: AES-256-GCM 解密/认证失败，丢弃消息";
            return 0;   // 无效消息
        }
    } else {
        payload = received;
    }

    return totalSize;
}

// ─────────────────────────────────────────────
// validateReceivedDataIntegrity
// 注意：消息头现在是明文传输，不再 XOR 加密
// ─────────────────────────────────────────────
qsizetype Protocol::validateReceivedDataIntegrity(const QByteArray& data,
                                                   MessageHeader& header) {
    // 1. 检查是否有完整的消息头
    if (data.size() < static_cast<qsizetype>(SERIALIZED_HEADER_SIZE)) {
        return -1;
    }

    // 2. 直接反序列化消息头（明文）
    QByteArray headerBytes = data.left(static_cast<qsizetype>(SERIALIZED_HEADER_SIZE));
    if (!header.decode(headerBytes)) {
        qWarning(lcProtocol) << "消息头解析失败";
        return 0;
    }

    // 3. 验证魔数
    if (header.magic != PROTOCOL_MAGIC) {
        qWarning(lcProtocol) << "无效魔数:" << Qt::hex << header.magic;
        return 0;
    }

    // 4. 验证协议版本
    if (header.version != PROTOCOL_VERSION) {
        qWarning(lcProtocol) << "不支持的协议版本:" << header.version;
        return 0;
    }

    // 5. 时间戳验证（±120 秒，容忍 NTP 偏差和系统时钟跳变）
    qint64 now     = QDateTime::currentMSecsSinceEpoch();
    qint64 msgTime = static_cast<qint64>(header.timestamp);
    if (qAbs(now - msgTime) > 120000) {
        qWarning(lcProtocol) << "消息时间戳超出可接受范围:"
                             << (now - msgTime) << "ms";
        return 0;
    }

    // 6. 按消息类型检查载荷长度上限，防止伪造超大包耗尽接收缓冲区
    quint32 maxAllowed;
    switch (header.type) {
        case MessageType::MOUSE_EVENT:
        case MessageType::KEYBOARD_EVENT:
            maxAllowed = static_cast<quint32>(NetworkConstants::MAX_PAYLOAD_INPUT);
            break;
        case MessageType::SCREEN_DATA:
        case MessageType::SCREEN_UPDATE:
            maxAllowed = static_cast<quint32>(NetworkConstants::MAX_PAYLOAD_SCREEN);
            break;
        case MessageType::CLIPBOARD_DATA:
            maxAllowed = static_cast<quint32>(NetworkConstants::MAX_PAYLOAD_CLIPBOARD);
            break;
        case MessageType::FILE_DATA:
        case MessageType::AUDIO_DATA:
            maxAllowed = static_cast<quint32>(NetworkConstants::MAX_PAYLOAD_FILE);
            break;
        default:
            // 握手、认证、心跳、光标、文件请求/响应等控制消息
            maxAllowed = static_cast<quint32>(NetworkConstants::MAX_PAYLOAD_CONTROL);
            break;
    }
    if (header.length > maxAllowed) {
        qWarning(lcProtocol) << "载荷长度超出类型限制: type="
                             << static_cast<quint32>(header.type)
                             << "length=" << header.length
                             << "max=" << maxAllowed;
        return 0;
    }

    // 7. 等待完整载荷
    qsizetype totalSize = static_cast<qsizetype>(SERIALIZED_HEADER_SIZE)
                        + static_cast<qsizetype>(header.length);
    if (data.size() < totalSize) {
        return -1;
    }

    // 8. 校验和验证
    QByteArray payload = data.mid(static_cast<qsizetype>(SERIALIZED_HEADER_SIZE),
                                   static_cast<qsizetype>(header.length));
    quint32 calcChecksum = calculateChecksum(payload);
    if (calcChecksum != header.checksum) {
        qWarning(lcProtocol) << "校验和不匹配，期望:"
                             << Qt::hex << header.checksum
                             << "计算得:" << Qt::hex << calcChecksum;
        return 0;
    }

    return totalSize;
}

quint32 Protocol::calculateChecksum(const QByteArray& data) {
    QCryptographicHash hash(QCryptographicHash::Md5);
    hash.addData(data);
    QByteArray result = hash.result();
    quint32 checksum = 0;
    if (result.size() >= 4) {
        checksum = qFromLittleEndian<quint32>(result.constData());
    }
    return checksum;
}

// ─────────────────────────────────────────────
// 辅助函数：定长字符串读写
// ─────────────────────────────────────────────
static void writeFixedStringLE(QDataStream& ds, const QString& s, int fixedLen) {
    QByteArray utf8 = s.toUtf8();
    if (utf8.size() > fixedLen) utf8.truncate(fixedLen);
    if (!utf8.isEmpty()) ds.writeRawData(utf8.constData(), utf8.size());
    int pad = fixedLen - utf8.size();
    if (pad > 0) {
        QByteArray zero(pad, '\0');
        ds.writeRawData(zero.constData(), zero.size());
    }
}

static QString readFixedStringLE(QDataStream& ds, int fixedLen) {
    QByteArray buf(fixedLen, 0);
    int read = ds.readRawData(buf.data(), fixedLen);
    if (read != fixedLen) return {};
    int nul = buf.indexOf('\0');
    if (nul >= 0) buf.truncate(nul);
    return QString::fromUtf8(buf);
}

// ─────────────────────────────────────────────
// MessageHeader
// ─────────────────────────────────────────────
QByteArray MessageHeader::encode() const {
    QByteArray data;
    QDataStream ds(&data, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::LittleEndian);
    ds << magic << version << static_cast<quint32>(type) << length << checksum << timestamp;
    return data;
}

bool MessageHeader::decode(const QByteArray& data) {
    if (data.size() < static_cast<qsizetype>(SERIALIZED_HEADER_SIZE)) return false;
    QDataStream ds(data);
    ds.setByteOrder(QDataStream::LittleEndian);
    quint32 typeValue;
    ds >> magic >> version >> typeValue >> length >> checksum >> timestamp;
    type = static_cast<MessageType>(typeValue);
    return ds.status() == QDataStream::Ok;
}

// ─────────────────────────────────────────────
// BaseMessage
// ─────────────────────────────────────────────
QByteArray BaseMessage::encode() const {
    QByteArray buf;
    QDataStream ds(&buf, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::LittleEndian);
    if (!this->data.isEmpty()) ds.writeRawData(this->data.constData(), this->data.size());
    return buf;
}

bool BaseMessage::decode(const QByteArray& rawData) {
    this->data = rawData;
    return true;
}

// ─────────────────────────────────────────────
// HandshakeRequest  （新增 ECDH 公钥 + 客户端 nonce）
// ─────────────────────────────────────────────
QByteArray HandshakeRequest::encode() const {
    QByteArray bytes;
    QDataStream ds(&bytes, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::LittleEndian);
    ds << clientVersion << screenWidth << screenHeight << colorDepth;
    writeFixedStringLE(ds, QString::fromUtf8(clientName), 64);
    writeFixedStringLE(ds, QString::fromUtf8(clientOS),   32);
    ds.writeRawData(reinterpret_cast<const char*>(ecdhPublicKey), 65);
    ds.writeRawData(reinterpret_cast<const char*>(clientNonce),   16);
    return bytes;
}

bool HandshakeRequest::decode(const QByteArray& bytes) {
    // 原始字段：4+2+2+1+64+32 = 105，新增：65+16 = 81，共 186 字节
    if (bytes.size() < (4 + 2 + 2 + 1 + 64 + 32 + 65 + 16)) return false;
    QDataStream ds(bytes);
    ds.setByteOrder(QDataStream::LittleEndian);
    ds >> clientVersion >> screenWidth >> screenHeight >> colorDepth;
    QString name = readFixedStringLE(ds, 64);
    QString os   = readFixedStringLE(ds, 32);
    if (ds.status() != QDataStream::Ok) return false;
    memset(clientName, 0, sizeof(clientName));
    memset(clientOS,   0, sizeof(clientOS));
    qstrncpy(clientName, name.toUtf8().constData(), int(sizeof(clientName)) - 1);
    qstrncpy(clientOS,   os.toUtf8().constData(),   int(sizeof(clientOS))   - 1);
    // 读取 ECDH 公钥 + nonce
    if (ds.readRawData(reinterpret_cast<char*>(ecdhPublicKey), 65) != 65) return false;
    if (ds.readRawData(reinterpret_cast<char*>(clientNonce),   16) != 16) return false;
    return ds.status() == QDataStream::Ok;
}

// ─────────────────────────────────────────────
// HandshakeResponse  （新增 ECDH 公钥 + 服务端 nonce）
// ─────────────────────────────────────────────
QByteArray HandshakeResponse::encode() const {
    QByteArray bytes;
    QDataStream ds(&bytes, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::LittleEndian);
    ds << serverVersion << screenWidth << screenHeight << colorDepth << supportedFeatures;
    writeFixedStringLE(ds, QString::fromUtf8(serverName), 64);
    writeFixedStringLE(ds, QString::fromUtf8(serverOS),   32);
    ds.writeRawData(reinterpret_cast<const char*>(ecdhPublicKey), 65);
    ds.writeRawData(reinterpret_cast<const char*>(serverNonce),   16);
    return bytes;
}

bool HandshakeResponse::decode(const QByteArray& bytes) {
    if (bytes.size() < (4 + 2 + 2 + 1 + 1 + 64 + 32 + 65 + 16)) return false;
    QDataStream ds(bytes);
    ds.setByteOrder(QDataStream::LittleEndian);
    ds >> serverVersion >> screenWidth >> screenHeight >> colorDepth >> supportedFeatures;
    QString name = readFixedStringLE(ds, 64);
    QString os   = readFixedStringLE(ds, 32);
    if (ds.status() != QDataStream::Ok) return false;
    memset(serverName, 0, sizeof(serverName));
    memset(serverOS,   0, sizeof(serverOS));
    qstrncpy(serverName, name.toUtf8().constData(), int(sizeof(serverName)) - 1);
    qstrncpy(serverOS,   os.toUtf8().constData(),   int(sizeof(serverOS))   - 1);
    if (ds.readRawData(reinterpret_cast<char*>(ecdhPublicKey), 65) != 65) return false;
    if (ds.readRawData(reinterpret_cast<char*>(serverNonce),   16) != 16) return false;
    return ds.status() == QDataStream::Ok;
}

// ─────────────────────────────────────────────
// AuthenticationRequest
// ─────────────────────────────────────────────
QByteArray AuthenticationRequest::encode() const {
    QByteArray bytes;
    QDataStream ds(&bytes, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::LittleEndian);
    writeFixedStringLE(ds, QString::fromUtf8(username), 64);
    {
        QByteArray utf8 = QString::fromUtf8(passwordHash).toUtf8();
        if (utf8.size() > 64) utf8.truncate(64);
        if (!utf8.isEmpty()) ds.writeRawData(utf8.constData(), utf8.size());
        int pad = 64 - utf8.size();
        if (pad > 0) { QByteArray zero(pad, '\0'); ds.writeRawData(zero.constData(), zero.size()); }
    }
    ds << static_cast<quint32>(authMethod);
    return bytes;
}

bool AuthenticationRequest::decode(const QByteArray& bytes) {
    if (bytes.size() < (64 + 64 + 4)) return false;
    QDataStream ds(bytes);
    ds.setByteOrder(QDataStream::LittleEndian);
    QString user = readFixedStringLE(ds, 64);
    QString pass = readFixedStringLE(ds, 64);
    quint32 method = 0; ds >> method;
    if (ds.status() != QDataStream::Ok) return false;
    QByteArray u8 = user.toUtf8(), p8 = pass.toUtf8();
    memset(username, 0, sizeof(username));
    memset(passwordHash, 0, sizeof(passwordHash));
    qstrncpy(username, u8.constData(), int(sizeof(username)) - 1);
    if (p8.size() >= int(sizeof(passwordHash)))
        memcpy(passwordHash, p8.constData(), sizeof(passwordHash));
    else
        qstrncpy(passwordHash, p8.constData(), int(sizeof(passwordHash)) - 1);
    authMethod = method;
    return true;
}

// ─────────────────────────────────────────────
// AuthenticationResponse
// ─────────────────────────────────────────────
QByteArray AuthenticationResponse::encode() const {
    QByteArray bytes;
    QDataStream ds(&bytes, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::LittleEndian);
    ds << static_cast<quint8>(result);
    writeFixedStringLE(ds, QString::fromUtf8(sessionId), 32);
    ds << static_cast<quint32>(permissions);
    return bytes;
}

bool AuthenticationResponse::decode(const QByteArray& bytes) {
    if (bytes.size() < (1 + 32 + 4)) return false;
    QDataStream ds(bytes);
    ds.setByteOrder(QDataStream::LittleEndian);
    quint8 res8 = 0; ds >> res8;
    QString sid = readFixedStringLE(ds, 32);
    quint32 perms = 0; ds >> perms;
    if (ds.status() != QDataStream::Ok) return false;
    result = static_cast<AuthResult>(res8);
    QByteArray sid8 = sid.toUtf8();
    memset(sessionId, 0, sizeof(sessionId));
    qstrncpy(sessionId, sid8.constData(), int(sizeof(sessionId)) - 1);
    permissions = perms;
    return true;
}

// ─────────────────────────────────────────────
// MouseEvent
// ─────────────────────────────────────────────
QByteArray MouseEvent::encode() const {
    QByteArray bytes;
    QDataStream ds(&bytes, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::LittleEndian);
    ds << static_cast<quint8>(eventType) << static_cast<qint16>(x)
       << static_cast<qint16>(y) << static_cast<qint16>(wheelDelta);
    return bytes;
}

bool MouseEvent::decode(const QByteArray& bytes) {
    if (bytes.size() < (1 + 2 + 2 + 2)) return false;
    QDataStream ds(bytes);
    ds.setByteOrder(QDataStream::LittleEndian);
    quint8 type8; qint16 xv, yv, wheel;
    ds >> type8 >> xv >> yv >> wheel;
    if (ds.status() != QDataStream::Ok) return false;
    eventType = static_cast<MouseEventType>(type8);
    x = xv; y = yv; wheelDelta = wheel;
    return true;
}

// ─────────────────────────────────────────────
// KeyboardEvent
// ─────────────────────────────────────────────
QByteArray KeyboardEvent::encode() const {
    QByteArray bytes;
    QDataStream ds(&bytes, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::LittleEndian);
    ds << static_cast<quint8>(eventType) << static_cast<quint32>(keyCode)
       << static_cast<quint32>(modifiers);
    writeFixedStringLE(ds, QString::fromUtf8(text), 8);
    return bytes;
}

bool KeyboardEvent::decode(const QByteArray& bytes) {
    if (bytes.size() < (1 + 4 + 4 + 8)) return false;
    QDataStream ds(bytes);
    ds.setByteOrder(QDataStream::LittleEndian);
    quint8 type8; quint32 key, mods;
    ds >> type8 >> key >> mods;
    QString textStr = readFixedStringLE(ds, 8);
    if (ds.status() != QDataStream::Ok) return false;
    eventType = static_cast<KeyboardEventType>(type8);
    keyCode = key; modifiers = mods;
    memset(text, 0, sizeof(text));
    QByteArray t8 = textStr.toUtf8();
    qstrncpy(text, t8.constData(), int(sizeof(text)) - 1);
    return true;
}

// ─────────────────────────────────────────────
// ScreenData
// ─────────────────────────────────────────────
QByteArray ScreenData::encode() const {
    QByteArray bytes;
    QDataStream ds(&bytes, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::LittleEndian);
    ds << static_cast<quint16>(x) << static_cast<quint16>(y)
       << static_cast<quint16>(width) << static_cast<quint16>(height);
    quint32 actualDataSize = static_cast<quint32>(imageData.size());
    if (dataSize != actualDataSize) {
        qCWarning(lcProtocol, "ScreenData数据大小不一致: dataSize=%u, actual=%u", dataSize, actualDataSize);
        ds << actualDataSize;
    } else {
        ds << static_cast<quint32>(dataSize);
    }
    const quint32 maxScreenDataSize = 50 * 1024 * 1024;
    if (actualDataSize > maxScreenDataSize) {
        qCWarning(lcProtocol, "ScreenData数据过大: %u bytes", actualDataSize);
        return {};
    }
    if (!imageData.isEmpty()) ds.writeRawData(imageData.constData(), imageData.size());
    return bytes;
}

bool ScreenData::decode(const QByteArray& bytes) {
    const qsizetype headerSize = 2 + 2 + 2 + 2 + 4;
    if (bytes.size() < headerSize) return false;
    QDataStream ds(bytes);
    ds.setByteOrder(QDataStream::LittleEndian);
    quint16 xv, yv, w, h; quint32 size;
    ds >> xv >> yv >> w >> h >> size;
    if (ds.status() != QDataStream::Ok) return false;
    if (w == 0 || h == 0) return false;
    if (size > 50 * 1024 * 1024u) return false;
    qsizetype totalNeeded = headerSize + qsizetype(size);
    if (bytes.size() < totalNeeded) return false;
    x = xv; y = yv; width = w; height = h; dataSize = size;
    if (size > 0) {
        imageData = bytes.mid(headerSize, size);
        if (imageData.size() != static_cast<qsizetype>(size)) return false;
    } else {
        imageData = {};
    }
    return true;
}

// ─────────────────────────────────────────────
// AudioData
// ─────────────────────────────────────────────
QByteArray AudioData::encode() const {
    QByteArray bytes;
    QDataStream ds(&bytes, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::LittleEndian);
    ds << static_cast<quint32>(sampleRate) << static_cast<quint8>(channels)
       << static_cast<quint8>(bitsPerSample) << static_cast<quint32>(dataSize);
    return bytes;
}

bool AudioData::decode(const QByteArray& bytes) {
    if (bytes.size() < (4 + 1 + 1 + 4)) return false;
    QDataStream ds(bytes);
    ds.setByteOrder(QDataStream::LittleEndian);
    quint32 rate, size; quint8 ch, bits;
    ds >> rate >> ch >> bits >> size;
    if (ds.status() != QDataStream::Ok) return false;
    if (bytes.size() < qsizetype(4 + 1 + 1 + 4) + qsizetype(size)) return false;
    sampleRate = rate; channels = ch; bitsPerSample = bits; dataSize = size;
    return true;
}

// ─────────────────────────────────────────────
// AuthChallenge
// ─────────────────────────────────────────────
QByteArray AuthChallenge::encode() const {
    QByteArray bytes;
    QDataStream ds(&bytes, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::LittleEndian);
    ds << method << iterations << keyLength;
    ds.writeRawData(saltHex, 64);
    return bytes;
}

bool AuthChallenge::decode(const QByteArray& bytes) {
    if (bytes.size() < (4 + 4 + 4 + 64)) return false;
    QDataStream ds(bytes);
    ds.setByteOrder(QDataStream::LittleEndian);
    ds >> method >> iterations >> keyLength;
    int bytesRead = ds.readRawData(saltHex, 64);
    return bytesRead == 64 && ds.status() == QDataStream::Ok;
}

// ─────────────────────────────────────────────
// CursorMessage
// ─────────────────────────────────────────────
CursorMessage::CursorMessage() : cursorType(Qt::ArrowCursor) {}
CursorMessage::CursorMessage(Qt::CursorShape type) : cursorType(type) {}

QByteArray CursorMessage::encode() const {
    QByteArray data;
    QDataStream ds(&data, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::LittleEndian);
    ds << static_cast<quint8>(cursorType);
    return data;
}

bool CursorMessage::decode(const QByteArray& dataBuffer) {
    if (dataBuffer.isEmpty()) return false;
    QDataStream ds(dataBuffer);
    ds.setByteOrder(QDataStream::LittleEndian);
    quint8 type; ds >> type;
    cursorType = static_cast<Qt::CursorShape>(type);
    return ds.status() == QDataStream::Ok;
}

// ─────────────────────────────────────────────
// FileTransferRequest / Response / Data
// ─────────────────────────────────────────────
QByteArray FileTransferRequest::encode() const {
    QByteArray bytes;
    QDataStream ds(&bytes, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::LittleEndian);
    writeFixedStringLE(ds, QString::fromUtf8(fileName), 256);
    ds << static_cast<quint64>(fileSize) << static_cast<quint32>(transferId)
       << static_cast<quint8>(direction);
    return bytes;
}

bool FileTransferRequest::decode(const QByteArray& bytes) {
    if (bytes.size() < (256 + 8 + 4 + 1)) return false;
    QDataStream ds(bytes);
    ds.setByteOrder(QDataStream::LittleEndian);
    QString name = readFixedStringLE(ds, 256);
    quint64 size; quint32 tid; quint8 dir;
    ds >> size >> tid >> dir;
    if (ds.status() != QDataStream::Ok) return false;
    memset(fileName, 0, sizeof(fileName));
    QByteArray n8 = name.toUtf8();
    qstrncpy(fileName, n8.constData(), int(sizeof(fileName)) - 1);
    fileSize = size; transferId = tid; direction = dir;
    return true;
}

QByteArray FileTransferResponse::encode() const {
    QByteArray bytes;
    QDataStream ds(&bytes, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::LittleEndian);
    ds << static_cast<quint32>(transferId) << static_cast<quint8>(status);
    writeFixedStringLE(ds, QString::fromUtf8(errorMessage), 256);
    return bytes;
}

bool FileTransferResponse::decode(const QByteArray& bytes) {
    if (bytes.size() < (4 + 1 + 256)) return false;
    QDataStream ds(bytes);
    ds.setByteOrder(QDataStream::LittleEndian);
    quint32 tid; quint8 st; ds >> tid >> st;
    QString err = readFixedStringLE(ds, 256);
    if (ds.status() != QDataStream::Ok) return false;
    transferId = tid; status = static_cast<FileTransferStatus>(st);
    memset(errorMessage, 0, sizeof(errorMessage));
    QByteArray e8 = err.toUtf8();
    qstrncpy(errorMessage, e8.constData(), int(sizeof(errorMessage)) - 1);
    return true;
}

QByteArray FileData::encode() const {
    QByteArray bytes;
    QDataStream ds(&bytes, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::LittleEndian);
    ds << static_cast<quint32>(transferId) << static_cast<quint64>(offset)
       << static_cast<quint32>(dataSize);
    return bytes;
}

bool FileData::decode(const QByteArray& bytes) {
    if (bytes.size() < (4 + 8 + 4)) return false;
    QDataStream ds(bytes);
    ds.setByteOrder(QDataStream::LittleEndian);
    quint32 tid, len; quint64 off;
    ds >> tid >> off >> len;
    if (ds.status() != QDataStream::Ok) return false;
    if (bytes.size() < qsizetype(4 + 8 + 4) + qsizetype(len)) return false;
    transferId = tid; offset = off; dataSize = len;
    return true;
}

// ─────────────────────────────────────────────
// ClipboardMessage
// ─────────────────────────────────────────────
ClipboardMessage::ClipboardMessage() : dataType(ClipboardDataType::TEXT), width(0), height(0) {}
ClipboardMessage::ClipboardMessage(const QString& text)
    : dataType(ClipboardDataType::TEXT), data(text.toUtf8()), width(0), height(0) {}
ClipboardMessage::ClipboardMessage(const QByteArray& imageData, quint32 w, quint32 h)
    : dataType(ClipboardDataType::IMAGE), data(imageData), width(w), height(h) {}

bool ClipboardMessage::isText()  const { return dataType == ClipboardDataType::TEXT; }
bool ClipboardMessage::isImage() const { return dataType == ClipboardDataType::IMAGE; }
QString    ClipboardMessage::text()      const { return isText()  ? QString::fromUtf8(data) : QString(); }
QByteArray ClipboardMessage::imageData() const { return isImage() ? data : QByteArray(); }

QByteArray ClipboardMessage::encode() const {
    QByteArray buffer;
    QDataStream ds(&buffer, QIODevice::WriteOnly);
    ds.setByteOrder(QDataStream::LittleEndian);
    ds << static_cast<quint8>(dataType);
    if (dataType == ClipboardDataType::TEXT) {
        ds << static_cast<quint32>(data.size());
        ds.writeRawData(data.constData(), data.size());
    } else if (dataType == ClipboardDataType::IMAGE) {
        ds << width << height << static_cast<quint32>(data.size());
        ds.writeRawData(data.constData(), data.size());
    }
    return buffer;
}

bool ClipboardMessage::decode(const QByteArray& dataBuffer) {
    if (dataBuffer.size() < int(sizeof(quint8))) return false;
    QDataStream ds(dataBuffer);
    ds.setByteOrder(QDataStream::LittleEndian);
    quint8 type; ds >> type;
    dataType = static_cast<ClipboardDataType>(type);
    if (dataType == ClipboardDataType::TEXT) {
        if (dataBuffer.size() < int(sizeof(quint8) + sizeof(quint32))) return false;
        quint32 dataSize; ds >> dataSize;
        if (dataBuffer.size() < int(sizeof(quint8) + sizeof(quint32) + dataSize)) return false;
        data.resize(dataSize);
        ds.readRawData(data.data(), dataSize);
        width = 0; height = 0;
    } else if (dataType == ClipboardDataType::IMAGE) {
        if (dataBuffer.size() < int(sizeof(quint8) + 3 * sizeof(quint32))) return false;
        ds >> width >> height;
        quint32 dataSize; ds >> dataSize;
        if (dataBuffer.size() < int(sizeof(quint8) + 3 * sizeof(quint32) + dataSize)) return false;
        data.resize(dataSize);
        ds.readRawData(data.data(), dataSize);
    } else {
        return false;
    }
    return ds.status() == QDataStream::Ok;
}
