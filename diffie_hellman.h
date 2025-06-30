#ifndef DIFFIE_HELLMAN_H
#define DIFFIE_HELLMAN_H

#include <openssl/bn.h>
#include <pthread.h>

// DH会话上下文(面向对象设计)
typedef struct {
    BIGNUM *private_key;   // 私钥
    BIGNUM *public_key;    // 公钥
    BIGNUM *shared_secret; // 共享密钥
    BIGNUM *prime;         // 素数p
    BIGNUM *generator;     // 生成元g
    int is_active;         // 会话状态标志
    pthread_mutex_t lock;  // 线程安全锁
} DHSession;

// 初始化DH会话
// 参数: session - 要初始化的会话对象
//       p - 素数
//       g - 生成元
// 返回: 0成功, -1失败
int dh_session_init(DHSession *session, const BIGNUM *p, const BIGNUM *g);

// 计算共享密钥
// 参数: session - 会话对象
//       peer_public_key - 对端公钥
// 返回: 0成功, -1失败
int dh_compute_shared_secret(DHSession *session, const BIGNUM *peer_public_key);

// 安全清理DH会话
// 参数: session - 要清理的会话对象
void dh_session_clear(DHSession *session);

// 生成DH参数
// 参数: bits - 素数位数
//       p - 输出的素数
//       g - 输出的生成元
// 返回: 0成功, -1失败
int dh_generate_parameters(int bits, BIGNUM **p, BIGNUM **g);

// 序列化密钥
// 参数: key - 要序列化的密钥
//       buffer - 输出缓冲区
//       buf_size - 缓冲区大小
// 返回: 序列化后的长度, -1表示失败
int dh_serialize_key(const BIGNUM *key, char *buffer, size_t buf_size);

// 反序列化密钥
// 参数: buffer - 输入缓冲区
//       len - 数据长度
//       key - 输出的密钥对象(需要先创建)
// 返回: 0成功, -1失败
int dh_deserialize_key(const char *buffer, size_t len, BIGNUM *key);

#endif // DIFFIE_HELLMAN_H