#ifndef SESSIONCRYPTO_H
#define SESSIONCRYPTO_H

#include <QtCore/QByteArray>
#include <atomic>
#include <memory>

/**
 * @brief ECDH-P256 密钥交换 + AES-256-GCM 会话加密
 *
 * 使用流程：
 * 1. generateKeyPair()        — 生成临时 ECDH 密钥对（握手前调用）
 * 2. publicKey()              — 获取本端公钥（65字节，发给对端）
 * 3. generateNonce()          — 生成随机 nonce（发给对端）
 * 4. deriveSessionKey(...)    — 收到对端公钥+nonce后，派生会话密钥
 * 5. isReady()                — 返回 true 后，可调用 encrypt/decrypt
 *
 * 加密格式：nonce(12) || ciphertext || tag(16)
 *   nonce = seq(8字节,大端) || random(4字节)
 */
class SessionCrypto {
public:
    SessionCrypto();
    ~SessionCrypto();

    SessionCrypto(const SessionCrypto&) = delete;
    SessionCrypto& operator=(const SessionCrypto&) = delete;

    // 生成 ECDH 密钥对（P-256）
    bool generateKeyPair();

    // 返回本端公钥（65字节，未压缩格式：04 || x || y）
    QByteArray publicKey() const;

    // 生成随机 nonce（握手时随公钥一起发送）
    static QByteArray generateNonce(int size = 16);

    /**
     * @brief 从对端公钥派生会话密钥
     * @param peerPublicKey  对端公钥（65字节未压缩 P-256 点）
     * @param localNonce     本端 nonce（16字节）
     * @param peerNonce      对端 nonce（16字节）
     * @return 成功返回 true，失败返回 false
     *
     * 派生过程：
     *   sharedSecret = ECDH(myPrivKey, peerPubKey)
     *   sessionKey   = HMAC-SHA256(key=sharedSecret, data="QtRD-v1"||localNonce||peerNonce)
     */
    bool deriveSessionKey(const QByteArray& peerPublicKey,
                          const QByteArray& localNonce,
                          const QByteArray& peerNonce);

    // 会话密钥是否已就绪
    bool isReady() const { return m_ready; }

    /**
     * @brief AES-256-GCM 加密
     * @param plaintext 明文
     * @return nonce(12) || ciphertext || tag(16)，失败返回空
     */
    QByteArray encrypt(const QByteArray& plaintext);

    /**
     * @brief AES-256-GCM 解密并验证
     * @param cipherdata nonce(12) || ciphertext || tag(16)
     * @return 明文，认证失败返回空
     */
    QByteArray decrypt(const QByteArray& cipherdata);

private:
    void*      m_pkey = nullptr;    // EVP_PKEY* (ECDH 私钥)
    QByteArray m_publicKeyBytes;    // 65 字节未压缩 P-256 公钥
    QByteArray m_sessionKey;        // 32 字节 AES-256 密钥
    bool       m_ready = false;
    std::atomic<quint64> m_sendSeq{0};
};

#endif // SESSIONCRYPTO_H
