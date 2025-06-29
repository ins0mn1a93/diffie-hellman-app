#include "diffie-hellman.h"
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

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