#ifndef DIFFIE_HELLMAN_H
#define DIFFIE_HELLMAN_H

#include <openssl/bn.h>

// DH会话上下文
typedef struct {
    BIGNUM *private_key;
    BIGNUM *public_key;
    BIGNUM *shared_secret;
    BIGNUM *prime;
    BIGNUM *generator;
    int is_active;
} DHSession;

// 初始化DH会话
int dh_session_init(DHSession *session, const BIGNUM *p, const BIGNUM *g);

// 计算共享密钥
int dh_compute_shared_secret(DHSession *session, const BIGNUM *peer_public_key);

// 安全清理DH会话
void dh_session_clear(DHSession *session);

// 序列化密钥
int dh_serialize_key(const BIGNUM *key, char *buffer, size_t buf_size);

// 反序列化密钥
int dh_deserialize_key(const char *buffer, size_t len, BIGNUM **key);

// 生成DH参数
void dh_generate_parameters(int bits, BIGNUM **p, BIGNUM **g);

#endif

