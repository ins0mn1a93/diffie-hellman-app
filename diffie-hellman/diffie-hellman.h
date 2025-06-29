#ifndef DIFFIE_HELLMAN_H
#define DIFFIE_HELLMAN_H

#include <openssl/bn.h>
#include <pthread.h>
#include <openssl/evp.h>  // 添加EVP支持

// DH会话上下文
typedef struct {
    BIGNUM *private_key;
    BIGNUM *public_key;
    BIGNUM *shared_secret;
    BIGNUM *prime;
    BIGNUM *generator;
    int is_active;
    pthread_mutex_t lock;
} DHSession;

// 增加密钥派生上下文
typedef struct {
    unsigned char encryption_key[32];  // AES-256密钥
    unsigned char mac_key[32];         // HMAC密钥
    unsigned char iv[16];              // 初始化向量
} DerivedKeys;

// 初始化DH会话
int dh_session_init(DHSession *session, const BIGNUM *p, const BIGNUM *g);

// 计算共享密钥
int dh_compute_shared_secret(DHSession *session, const BIGNUM *peer_public_key);

// 安全清理DH会话
void dh_session_clear(DHSession *session);

// 生成DH参数
int dh_generate_parameters(int bits, BIGNUM **p, BIGNUM **g);

// 序列化密钥
int dh_serialize_key(const BIGNUM *key, char *buffer, size_t buf_size);

// 反序列化密钥
int dh_deserialize_key(const char *buffer, size_t len, BIGNUM *key);

// 新增：密钥派生函数
int dh_derive_keys(const BIGNUM *shared_secret, const unsigned char *salt, 
                   size_t salt_len, DerivedKeys *keys);

// 新增：公钥签名验证
int dh_verify_public_key(const BIGNUM *pubkey, const BIGNUM *p, 
                         const BIGNUM *g, const char *expected_hash);

#endif // DIFFIE_HELLMAN_H