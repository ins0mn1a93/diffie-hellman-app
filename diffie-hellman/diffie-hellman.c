#include "diffie_hellman.h"
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

int dh_session_init(DHSession *session, const BIGNUM *p, const BIGNUM *g) {
    // 复制DH参数
    session->prime = BN_dup(p);
    session->generator = BN_dup(g);
    
    // 生成私钥 (1 < priv < p-1)
    session->private_key = BN_new();
    int bits = BN_num_bits(p);
    do {
        if (!BN_rand(session->private_key, bits - 1, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
            fprintf(stderr, "Private key generation failed\n");
            return -1;
        }
    } while (BN_is_zero(session->private_key) || 
             BN_cmp(session->private_key, p) >= 0);
    
    // 计算公钥: pub = g^priv mod p
    session->public_key = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return -1;
    
    if (!BN_mod_exp(session->public_key, g, session->private_key, p, ctx)) {
        BN_CTX_free(ctx);
        return -1;
    }
    
    BN_CTX_free(ctx);
    session->is_active = 1;
    return 0;
}

int dh_compute_shared_secret(DHSession *session, const BIGNUM *peer_public_key) {
    if (!session->is_active) return -1;
    
    session->shared_secret = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return -1;
    
    // 计算共享密钥: shared = peer_pub^priv mod p
    int result = BN_mod_exp(session->shared_secret, peer_public_key, 
                           session->private_key, session->prime, ctx);
    BN_CTX_free(ctx);
    
    return result ? 0 : -1;
}

void dh_session_clear(DHSession *session) {
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
}

int dh_serialize_key(const BIGNUM *key, char *buffer, size_t buf_size) {
    if (!key || !buffer) return -1;
    char *hex = BN_bn2hex(key);
    if (!hex) return -1;
    
    size_t len = strlen(hex);
    if (len + 1 > buf_size) {
        OPENSSL_free(hex);
        return -1;
    }
    
    memcpy(buffer, hex, len + 1);
    OPENSSL_free(hex);
    return (int)len;
}

int dh_deserialize_key(const char *buffer, size_t len, BIGNUM **key) {
    if (!buffer || len == 0) return -1;
    *key = BN_new();
    return BN_hex2bn(key, buffer) ? 0 : -1;
}

void dh_generate_parameters(int bits, BIGNUM **p, BIGNUM **g) {
    *p = BN_new();
    *g = BN_new();
    BN_generate_prime_ex(*p, bits, 1, NULL, NULL, NULL);
    BN_set_word(*g, 5);  // 常用生成器
}

