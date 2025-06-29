#include "diffie-hellman.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

// 安全清除内存的函数（放在文件顶部，确保在调用前定义）
static void secure_clear(void *s, size_t n) {
    volatile unsigned char *p = s;
    while (n--) *p++ = 0;
}

int dh_session_init(DHSession *session, const BIGNUM *p, const BIGNUM *g) {
    // 清零整个结构体（关键修复）
    memset(session, 0, sizeof(DHSession));
    
    // 初始化互斥锁
    if (pthread_mutex_init(&session->lock, NULL) != 0) {
        fprintf(stderr, "Mutex init failed\n");
        return -1;
    }

    // 验证输入参数
    if (!p || !g || BN_is_zero(p) || BN_is_zero(g)) {
        fprintf(stderr, "Invalid DH parameters\n");
        goto error;
    }

    // 分配BIGNUM对象（使用BN_new()而非BN_dup()保证独立性）
    session->prime = BN_new();
    session->generator = BN_new();
    session->private_key = BN_new();
    session->public_key = BN_new();
    
    if (!session->prime || !session->generator || 
        !session->private_key || !session->public_key) {
        fprintf(stderr, "BN_new allocation failed\n");
        goto error;
    }

    // 复制参数（添加错误检查）
    if (!BN_copy(session->prime, p) || !BN_copy(session->generator, g)) {
        fprintf(stderr, "BN_copy failed\n");
        goto error;
    }

    // 生成私钥（使用更安全的范围计算）
    BIGNUM *max_range = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if (!max_range || !ctx) {
        fprintf(stderr, "Range calculation init failed\n");
        if (max_range) BN_free(max_range);
        goto error;
    }

    // max_range = p - 2
    if (!BN_sub(max_range, p, BN_value_one()) || !BN_sub_word(max_range, 1)) {
        fprintf(stderr, "Range calculation failed\n");
        BN_free(max_range);
        BN_CTX_free(ctx);
        goto error;
    }

    // 生成随机私钥 [1, p-2]
    if (!BN_rand_range(session->private_key, max_range) || 
        !BN_add_word(session->private_key, 1)) {
        fprintf(stderr, "Private key generation failed\n");
        BN_free(max_range);
        BN_CTX_free(ctx);
        goto error;
    }

    // 计算公钥: g^private_key mod p
    if (!BN_mod_exp(session->public_key, g, session->private_key, p, ctx)) {
        fprintf(stderr, "Public key calculation failed\n");
        BN_free(max_range);
        BN_CTX_free(ctx);
        goto error;
    }

    // 清理临时变量
    BN_free(max_range);
    BN_CTX_free(ctx);
    
    session->is_active = 1;
    return 0;

error:
    // 确保所有资源被释放
    if (session->prime) BN_free(session->prime);
    if (session->generator) BN_free(session->generator);
    if (session->private_key) BN_clear_free(session->private_key);
    if (session->public_key) BN_free(session->public_key);
    memset(session, 0, sizeof(DHSession)); // 重置整个结构体
    return -1;
}

// 计算共享密钥
int dh_compute_shared_secret(DHSession *session, const BIGNUM *peer_public_key) {
    if (!session || !peer_public_key || !session->is_active) {
        fprintf(stderr, "Error: Invalid parameters to dh_compute_shared_secret\n");
        return -1;
    }
    
    pthread_mutex_lock(&session->lock);
    
    // 计算共享密钥: peer_public_key^private_key mod p
    session->shared_secret = BN_new();
    if (!session->shared_secret) {
        fprintf(stderr, "Error: BN_new failed for shared_secret\n");
        pthread_mutex_unlock(&session->lock);
        return -1;
    }
    
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: BN_CTX_new failed\n");
        pthread_mutex_unlock(&session->lock);
        return -1;
    }
    
    int ret = BN_mod_exp(session->shared_secret, peer_public_key, 
                        session->private_key, session->prime, ctx);
    BN_CTX_free(ctx);
    
    pthread_mutex_unlock(&session->lock);
    return ret ? 0 : -1;
}

// 安全清理DH会话
void dh_session_clear(DHSession *session) {
    if (!session) return;
    
    pthread_mutex_lock(&session->lock);
    
    if (session->private_key) {
        BN_clear_free(session->private_key);
        session->private_key = NULL;
    }
    if (session->public_key) {
        BN_free(session->public_key);
        session->public_key = NULL;
    }
    if (session->shared_secret) {
        BN_clear_free(session->shared_secret);
        session->shared_secret = NULL;
    }
    if (session->prime) {
        BN_free(session->prime);
        session->prime = NULL;
    }
    if (session->generator) {
        BN_free(session->generator);
        session->generator = NULL;
    }
    
    session->is_active = 0;
    pthread_mutex_unlock(&session->lock);
    pthread_mutex_destroy(&session->lock);
}

// 生成DH参数
int dh_generate_parameters(int bits, BIGNUM **p, BIGNUM **g) {
    if (!p || !g || bits < 128) {
        fprintf(stderr, "Error: Invalid parameters to dh_generate_parameters\n");
        return -1;
    }
    
    *p = BN_new();
    *g = BN_new();
    if (!*p || !*g) {
        fprintf(stderr, "Error: BN_new failed\n");
        if (*p) BN_free(*p);
        if (*g) BN_free(*g);
        return -1;
    }
    
    // 生成安全素数p
    if (!BN_generate_prime_ex(*p, bits, 1, NULL, NULL, NULL)) {
        fprintf(stderr, "Error: BN_generate_prime_ex failed\n");
        BN_free(*p);
        BN_free(*g);
        return -1;
    }
    
    // 使用2作为生成元(常见安全选择)
    BN_set_word(*g, 2);
    
    return 0;
}

// 序列化密钥
int dh_serialize_key(const BIGNUM *key, char *buffer, size_t buf_size) {
    if (!key || !buffer || buf_size == 0) {
        fprintf(stderr, "Error: Invalid parameters to dh_serialize_key\n");
        return -1;
    }
    
    int len = BN_num_bytes(key);
    if (len < 0 || (size_t)len >= buf_size) {
        fprintf(stderr, "Error: Buffer too small for serialization\n");
        return -1;
    }
    
    int written = BN_bn2bin(key, (unsigned char *)buffer);
    if (written != len) {
        fprintf(stderr, "Error: BN_bn2bin wrote %d bytes, expected %d\n", written, len);
        return -1;
    }
    
    return len;
}

// 反序列化密钥
int dh_deserialize_key(const char *buffer, size_t len, BIGNUM *key) {
    if (!buffer || len == 0 || !key) {
        fprintf(stderr, "Error: Invalid parameters to dh_deserialize_key\n");
        return -1;
    }
    
    const unsigned char *tmp = (const unsigned char *)buffer;
    if (!BN_bin2bn(tmp, len, key)) {
        fprintf(stderr, "Error: BN_bin2bn failed\n");
        return -1;
    }
    
    return 0;
}

  // 修改后的密钥派生函数（兼容 OpenSSL 1.0.2）
int dh_derive_keys(const BIGNUM *shared_secret, const unsigned char *salt, 
                   size_t salt_len, DerivedKeys *keys) {
    if (!shared_secret || !keys) return -1;
    
    // 将共享密钥转换为字节
    int secret_len = BN_num_bytes(shared_secret);
    unsigned char *secret_bytes = malloc(secret_len);
    if (!secret_bytes) return -1;
    BN_bn2bin(shared_secret, secret_bytes);
    
    // 手动实现 HKDF (RFC 5869)
    unsigned char prk[SHA256_DIGEST_LENGTH];  // 伪随机密钥
    unsigned char info[] = "Diffie-Hellman Key Derivation";
    size_t info_len = sizeof(info) - 1;  // 不包括终止符
    
    // 步骤1: HKDF-Extract
    unsigned char *real_salt = (unsigned char *)salt;
    size_t real_salt_len = salt_len;
    
    if (salt == NULL || salt_len == 0) {
        real_salt = (unsigned char *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        real_salt_len = 16;
    }
    
    // 使用 HMAC_CTX（旧版 OpenSSL 方式）
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx); // 初始化替代 HMAC_CTX_new
    
    // 提取 PRK
    if (!HMAC_Init_ex(&ctx, real_salt, real_salt_len, EVP_sha256(), NULL) ||
        !HMAC_Update(&ctx, secret_bytes, secret_len) ||
        !HMAC_Final(&ctx, prk, NULL)) {
        HMAC_CTX_cleanup(&ctx); // 清理替代 HMAC_CTX_free
        free(secret_bytes);
        return -1;
    }
    HMAC_CTX_cleanup(&ctx);
    
    // 步骤2: HKDF-Expand
    unsigned char okm[64];  // 输出密钥材料
    unsigned char t[SHA256_DIGEST_LENGTH];
    unsigned char ctr = 0x01;
    int remaining = sizeof(okm);
    
    // 第一轮
    HMAC_CTX ctx_expand;
    HMAC_CTX_init(&ctx_expand);
    
    if (!HMAC_Init_ex(&ctx_expand, prk, sizeof(prk), EVP_sha256(), NULL) ||
        !HMAC_Update(&ctx_expand, info, info_len) ||
        !HMAC_Update(&ctx_expand, &ctr, 1) ||
        !HMAC_Final(&ctx_expand, t, NULL)) {
        HMAC_CTX_cleanup(&ctx_expand);
        free(secret_bytes);
        return -1;
    }
    
    memcpy(okm, t, SHA256_DIGEST_LENGTH);
    remaining -= SHA256_DIGEST_LENGTH;
    
    // 第二轮
    ctr++;
    if (!HMAC_Init_ex(&ctx_expand, prk, sizeof(prk), EVP_sha256(), NULL) ||
        !HMAC_Update(&ctx_expand, t, sizeof(t)) ||
        !HMAC_Update(&ctx_expand, info, info_len) ||
        !HMAC_Update(&ctx_expand, &ctr, 1) ||
        !HMAC_Final(&ctx_expand, t, NULL)) {
        HMAC_CTX_cleanup(&ctx_expand);
        free(secret_bytes);
        return -1;
    }
    
    memcpy(okm + SHA256_DIGEST_LENGTH, t, SHA256_DIGEST_LENGTH);
    HMAC_CTX_cleanup(&ctx_expand);
    
    // 分割派生的密钥
    memcpy(keys->encryption_key, okm, 32);
    memcpy(keys->mac_key, okm + 32, 32);
    
    // 生成随机 IV
    if (!RAND_bytes(keys->iv, sizeof(keys->iv))) {
        free(secret_bytes);
        return -1;
    }
    
    // 安全清理临时数据
    free(secret_bytes);
    secure_clear(prk, sizeof(prk));
    secure_clear(t, sizeof(t));
    secure_clear(okm, sizeof(okm));
    
    return 0;
}
    
    

// 新增：公钥验证 (防止中间人攻击)
int dh_verify_public_key(const BIGNUM *pubkey, const BIGNUM *p, 
                         const BIGNUM *g, const char *expected_hash) {
    if (!pubkey || !p || !g || !expected_hash) return 0;
    
    // 验证公钥在有效范围内 [2, p-1]
    if (BN_cmp(pubkey, BN_value_one()) <= 0 || BN_cmp(pubkey, p) >= 0) {
        fprintf(stderr, "Public key out of range\n");
        return 0;
    }
    
    // 计算公钥哈希 (实际应用中应使用证书)
    unsigned char hash[SHA256_DIGEST_LENGTH];
    int key_len = BN_num_bytes(pubkey);
    unsigned char *key_bytes = malloc(key_len);
    if (!key_bytes) return 0;
    
    BN_bn2bin(pubkey, key_bytes);
    SHA256(key_bytes, key_len, hash);
    free(key_bytes);
    
    // 转换为十六进制字符串
    char hex_hash[2*SHA256_DIGEST_LENGTH + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex_hash + 2*i, "%02x", hash[i]);
    }
    hex_hash[2*SHA256_DIGEST_LENGTH] = '\0';
    
    // 与预期哈希比较
    if (strcmp(hex_hash, expected_hash) != 0) {
        fprintf(stderr, "Public key verification failed\n");
        fprintf(stderr, "Expected: %s\n", expected_hash);
        fprintf(stderr, "Received: %s\n", hex_hash);
        return 0;
    }
    
    return 1;
}