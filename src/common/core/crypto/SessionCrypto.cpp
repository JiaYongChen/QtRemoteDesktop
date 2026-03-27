// 抑制 OpenSSL 3.x 中 EC_KEY 相关的弃用警告（仍可正常使用）
#ifndef OPENSSL_SUPPRESS_DEPRECATED
#define OPENSSL_SUPPRESS_DEPRECATED
#endif

#include "SessionCrypto.h"
#include "Encryption.h"     // 复用 HashGenerator::hmacSha256
#include <QtCore/QDebug>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <cstring>

// ─────────────────────────────────────────────
// 辅助：打印 OpenSSL 错误链（仅 Debug）
// ─────────────────────────────────────────────
static void logOpenSSLError(const char* context) {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        qWarning("[SessionCrypto] %s: %s", context, buf);
    }
}

// ─────────────────────────────────────────────
// 构造 / 析构
// ─────────────────────────────────────────────
SessionCrypto::SessionCrypto() = default;

SessionCrypto::~SessionCrypto() {
    if (m_pkey) {
        EVP_PKEY_free(static_cast<EVP_PKEY*>(m_pkey));
        m_pkey = nullptr;
    }
    // 安全清零密钥
    if (!m_sessionKey.isEmpty()) {
        OPENSSL_cleanse(m_sessionKey.data(), m_sessionKey.size());
    }
}

// ─────────────────────────────────────────────
// generateKeyPair: 生成 P-256 ECDH 密钥对
// ─────────────────────────────────────────────
bool SessionCrypto::generateKeyPair() {
    // 先生成参数对象
    EVP_PKEY_CTX* paramCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!paramCtx) { logOpenSSLError("paramCtx"); return false; }

    if (EVP_PKEY_paramgen_init(paramCtx) <= 0) {
        logOpenSSLError("paramgen_init");
        EVP_PKEY_CTX_free(paramCtx);
        return false;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramCtx, NID_X9_62_prime256v1) <= 0) {
        logOpenSSLError("set_curve");
        EVP_PKEY_CTX_free(paramCtx);
        return false;
    }

    EVP_PKEY* params = nullptr;
    if (EVP_PKEY_paramgen(paramCtx, &params) <= 0) {
        logOpenSSLError("paramgen");
        EVP_PKEY_CTX_free(paramCtx);
        return false;
    }
    EVP_PKEY_CTX_free(paramCtx);

    // 生成密钥对
    EVP_PKEY_CTX* keyCtx = EVP_PKEY_CTX_new(params, nullptr);
    EVP_PKEY_free(params);
    if (!keyCtx) { logOpenSSLError("keyCtx"); return false; }

    if (EVP_PKEY_keygen_init(keyCtx) <= 0) {
        logOpenSSLError("keygen_init");
        EVP_PKEY_CTX_free(keyCtx);
        return false;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(keyCtx, &pkey) <= 0) {
        logOpenSSLError("keygen");
        EVP_PKEY_CTX_free(keyCtx);
        return false;
    }
    EVP_PKEY_CTX_free(keyCtx);

    // 释放旧密钥
    if (m_pkey) EVP_PKEY_free(static_cast<EVP_PKEY*>(m_pkey));
    m_pkey = pkey;

    // 提取公钥字节（65字节未压缩格式）
    EC_KEY* ecKey = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ecKey) { logOpenSSLError("get1_EC_KEY"); return false; }

    const EC_POINT* pubPoint = EC_KEY_get0_public_key(ecKey);
    const EC_GROUP* group    = EC_KEY_get0_group(ecKey);

    size_t pubLen = EC_POINT_point2oct(
        group, pubPoint, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);

    m_publicKeyBytes.resize(static_cast<int>(pubLen));
    EC_POINT_point2oct(group, pubPoint, POINT_CONVERSION_UNCOMPRESSED,
        reinterpret_cast<unsigned char*>(m_publicKeyBytes.data()), pubLen, nullptr);

    EC_KEY_free(ecKey);

    m_ready = false; // 还需要 deriveSessionKey
    return true;
}

QByteArray SessionCrypto::publicKey() const {
    return m_publicKeyBytes;
}

// ─────────────────────────────────────────────
// generateNonce: 生成密码学安全随机 nonce
// ─────────────────────────────────────────────
QByteArray SessionCrypto::generateNonce(int size) {
    QByteArray nonce(size, 0);
    if (RAND_bytes(reinterpret_cast<unsigned char*>(nonce.data()), size) != 1) {
        logOpenSSLError("RAND_bytes");
        return {};
    }
    return nonce;
}

// ─────────────────────────────────────────────
// deriveSessionKey: ECDH 计算共享密钥，再用 HMAC-SHA256 派生会话密钥
// ─────────────────────────────────────────────
bool SessionCrypto::deriveSessionKey(const QByteArray& peerPublicKey,
                                     const QByteArray& localNonce,
                                     const QByteArray& peerNonce) {
    if (!m_pkey) {
        qWarning("[SessionCrypto] deriveSessionKey: 未生成本端密钥对");
        return false;
    }
    if (peerPublicKey.size() != 65) {
        qWarning("[SessionCrypto] deriveSessionKey: 对端公钥长度错误 (%d)", peerPublicKey.size());
        return false;
    }

    // 从字节重建对端 EVP_PKEY
    EC_KEY* myECKey  = EVP_PKEY_get1_EC_KEY(static_cast<EVP_PKEY*>(m_pkey));
    if (!myECKey) { logOpenSSLError("get1_EC_KEY(mine)"); return false; }

    const EC_GROUP* group = EC_KEY_get0_group(myECKey);

    EC_POINT* peerPoint = EC_POINT_new(group);
    if (EC_POINT_oct2point(group, peerPoint,
            reinterpret_cast<const unsigned char*>(peerPublicKey.data()),
            static_cast<size_t>(peerPublicKey.size()), nullptr) != 1) {
        logOpenSSLError("oct2point");
        EC_POINT_free(peerPoint);
        EC_KEY_free(myECKey);
        return false;
    }

    EC_KEY* peerECKey = EC_KEY_new();
    EC_KEY_set_group(peerECKey, group);
    EC_KEY_set_public_key(peerECKey, peerPoint);

    EVP_PKEY* peerPKey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(peerPKey, peerECKey);

    EC_KEY_free(myECKey);
    EC_POINT_free(peerPoint);
    EC_KEY_free(peerECKey);

    // ECDH 派生
    EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(static_cast<EVP_PKEY*>(m_pkey), nullptr);
    if (!dctx) {
        logOpenSSLError("derive ctx");
        EVP_PKEY_free(peerPKey);
        return false;
    }
    if (EVP_PKEY_derive_init(dctx) <= 0 || EVP_PKEY_derive_set_peer(dctx, peerPKey) <= 0) {
        logOpenSSLError("derive_init/set_peer");
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peerPKey);
        return false;
    }

    size_t sharedLen = 0;
    EVP_PKEY_derive(dctx, nullptr, &sharedLen);
    QByteArray sharedSecret(static_cast<int>(sharedLen), 0);
    if (EVP_PKEY_derive(dctx,
            reinterpret_cast<unsigned char*>(sharedSecret.data()), &sharedLen) <= 0) {
        logOpenSSLError("derive");
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peerPKey);
        return false;
    }
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(peerPKey);

    // KDF: sessionKey = HMAC-SHA256(key=sharedSecret, data="QtRD-v1"||localNonce||peerNonce)
    // 结果为 32 字节，刚好用于 AES-256
    QByteArray info = QByteArray("QtRD-v1") + localNonce + peerNonce;
    m_sessionKey = HashGenerator::hmacSha256(info, sharedSecret);

    // 安全清零共享密钥
    OPENSSL_cleanse(sharedSecret.data(), sharedSecret.size());

    if (m_sessionKey.size() != 32) {
        qWarning("[SessionCrypto] HMAC-SHA256 输出长度异常: %d", m_sessionKey.size());
        return false;
    }

    m_ready = true;
    m_sendSeq.store(0);
    return true;
}

// ─────────────────────────────────────────────
// encrypt: AES-256-GCM 加密
// 输出：nonce(12) || ciphertext(N) || tag(16)
// ─────────────────────────────────────────────
QByteArray SessionCrypto::encrypt(const QByteArray& plaintext) {
    if (!m_ready) {
        qWarning("[SessionCrypto] encrypt: 会话密钥未就绪");
        return {};
    }

    // 构建 12 字节 nonce：8字节序号(大端) + 4字节随机
    quint64 seq = m_sendSeq.fetch_add(1);
    QByteArray nonce(12, 0);
    unsigned char* np = reinterpret_cast<unsigned char*>(nonce.data());
    np[0] = static_cast<unsigned char>((seq >> 56) & 0xFF);
    np[1] = static_cast<unsigned char>((seq >> 48) & 0xFF);
    np[2] = static_cast<unsigned char>((seq >> 40) & 0xFF);
    np[3] = static_cast<unsigned char>((seq >> 32) & 0xFF);
    np[4] = static_cast<unsigned char>((seq >> 24) & 0xFF);
    np[5] = static_cast<unsigned char>((seq >> 16) & 0xFF);
    np[6] = static_cast<unsigned char>((seq >>  8) & 0xFF);
    np[7] = static_cast<unsigned char>( seq        & 0xFF);
    if (RAND_bytes(np + 8, 4) != 1) { logOpenSSLError("RAND nonce"); return {}; }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    auto cleanup = [&]() { EVP_CIPHER_CTX_free(ctx); };

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr)         != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(m_sessionKey.constData()),
            np) != 1)
    {
        logOpenSSLError("EncryptInit");
        cleanup();
        return {};
    }

    QByteArray ciphertext(plaintext.size() + 16, 0);  // 预分配足够空间
    int len1 = 0, len2 = 0;

    if (!plaintext.isEmpty()) {
        if (EVP_EncryptUpdate(ctx,
                reinterpret_cast<unsigned char*>(ciphertext.data()), &len1,
                reinterpret_cast<const unsigned char*>(plaintext.constData()),
                plaintext.size()) != 1)
        {
            logOpenSSLError("EncryptUpdate");
            cleanup();
            return {};
        }
    }

    if (EVP_EncryptFinal_ex(ctx,
            reinterpret_cast<unsigned char*>(ciphertext.data()) + len1, &len2) != 1)
    {
        logOpenSSLError("EncryptFinal");
        cleanup();
        return {};
    }
    ciphertext.resize(len1 + len2);

    // 提取 16 字节认证标签
    QByteArray tag(16, 0);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
            reinterpret_cast<unsigned char*>(tag.data())) != 1)
    {
        logOpenSSLError("GET_TAG");
        cleanup();
        return {};
    }

    cleanup();
    return nonce + ciphertext + tag;  // nonce(12) || ciphertext || tag(16)
}

// ─────────────────────────────────────────────
// decrypt: AES-256-GCM 解密并验证认证标签
// 输入：nonce(12) || ciphertext || tag(16)
// ─────────────────────────────────────────────
QByteArray SessionCrypto::decrypt(const QByteArray& cipherdata) {
    if (!m_ready) {
        qWarning("[SessionCrypto] decrypt: 会话密钥未就绪");
        return {};
    }
    // 最小长度：nonce(12) + tag(16) = 28，允许空明文
    if (cipherdata.size() < 28) {
        qWarning("[SessionCrypto] decrypt: 数据过短 (%d bytes)", cipherdata.size());
        return {};
    }

    const QByteArray nonce      = cipherdata.left(12);
    const int        cipherLen  = cipherdata.size() - 28;
    const QByteArray ciphertext = cipherdata.mid(12, cipherLen);
    QByteArray       tag        = cipherdata.right(16);  // non-const for SET_TAG

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    auto cleanup = [&]() { EVP_CIPHER_CTX_free(ctx); };

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr)         != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(m_sessionKey.constData()),
            reinterpret_cast<const unsigned char*>(nonce.constData())) != 1)
    {
        logOpenSSLError("DecryptInit");
        cleanup();
        return {};
    }

    QByteArray plaintext(cipherLen, 0);
    int len1 = 0;

    if (cipherLen > 0) {
        if (EVP_DecryptUpdate(ctx,
                reinterpret_cast<unsigned char*>(plaintext.data()), &len1,
                reinterpret_cast<const unsigned char*>(ciphertext.constData()),
                cipherLen) != 1)
        {
            logOpenSSLError("DecryptUpdate");
            cleanup();
            return {};
        }
    }

    // 设置期望的认证标签
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
            reinterpret_cast<unsigned char*>(tag.data())) != 1)
    {
        logOpenSSLError("SET_TAG");
        cleanup();
        return {};
    }

    unsigned char finalBuf[16];
    int len2 = 0;
    int ret = EVP_DecryptFinal_ex(ctx, finalBuf, &len2);
    cleanup();

    if (ret <= 0) {
        // 认证标签验证失败——可能遭到篡改
        qWarning("[SessionCrypto] AES-256-GCM 认证标签验证失败，消息可能被篡改");
        ERR_clear_error();
        return {};
    }

    plaintext.resize(len1 + len2);
    return plaintext;
}
