#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/bn.h>//引入OpenSSL的BIGNUM大数运算库
#include "diffie-hellman.h"

#define SERVER_IP "127.0.0.1"// 服务器IP地址
#define PORT 8080// 服务器端口
#define BUFFER_SIZE 1024// 缓冲区大小

int main() {   
    // 创建IPv4的TCP套接字
    int client_socket;
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }
    
    // 设置服务器地址结构（127.0.0.1:8080）
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(EXIT_FAILURE);
    }
    
    // 连接到服务器
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Connected to server\n");
    
    // 动态生成DH参数
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
    /*调用dh_generate_parameters生成2048位安全素数p和生成元g*/
    if (dh_generate_parameters(2048, &p, &g) != 0) {
        fprintf(stderr, "Failed to generate DH parameters\n");
        close(client_socket);
        exit(EXIT_FAILURE);
    }
    
    // 初始化DH会话
       //初始化DHSession结构体
       //内部会生成客户端私钥和公钥
    DHSession session;
    if (dh_session_init(&session, p, g) != 0) {
        fprintf(stderr, "Failed to initialize DH session\n");
        BN_free(p);
        BN_free(g);
        close(client_socket);
        exit(EXIT_FAILURE);
    }
    
    // 将客户端的公钥序列化为字节流发送给服务器
    char buffer[BUFFER_SIZE];
    int len = dh_serialize_key(session.public_key, buffer, sizeof(buffer));
    if (len < 0 || send(client_socket, buffer, len, 0) != len) {
        perror("Send public key failed");
        dh_session_clear(&session);
        BN_free(p);
        BN_free(g);
        close(client_socket);
        exit(EXIT_FAILURE);
    }
    
    // 接收服务器的公钥并反序列化为BIGNUM对象
    len = recv(client_socket, buffer, sizeof(buffer), 0);
    if (len <= 0) {
        perror("Receive public key failed");
        dh_session_clear(&session);
        BN_free(p);
        BN_free(g);
        close(client_socket);
        exit(EXIT_FAILURE);
    }
    
    BIGNUM *server_pubkey = BN_new();
    if (dh_deserialize_key(buffer, len, server_pubkey) != 0) {
        fprintf(stderr, "Deserialize server key failed\n");
        BN_free(server_pubkey);
        dh_session_clear(&session);
        BN_free(p);
        BN_free(g);
        close(client_socket);
        exit(EXIT_FAILURE);
    }
    
    // 使用服务器公钥和客户端私钥计算共享密钥
    if (dh_compute_shared_secret(&session, server_pubkey) != 0) {
        fprintf(stderr, "Compute shared secret failed\n");
        BN_free(server_pubkey);
        dh_session_clear(&session);
        BN_free(p);
        BN_free(g);
        close(client_socket);
        exit(EXIT_FAILURE);
    }
    
    // 派生加密密钥
     //使用HKDF算法从共享密钥派生加密密钥
     //派生出的密钥包括：
     //256位加密密钥（AES-256）
     //256位MAC密钥（HMAC）
     //128位初始化向量（IV）
     //使用固定salt（实际应用中应使用随机salt
    DerivedKeys keys;
    const unsigned char salt[] = "StaticSaltForDemo";
    if (dh_derive_keys(session.shared_secret, salt, sizeof(salt)-1, &keys) != 0) {
        fprintf(stderr, "Key derivation failed\n");
    } else {
        printf("Key exchange successful!\n");
    }
    
    // 资源清理
    BN_free(server_pubkey);
    BN_free(p);
    BN_free(g);//释放所有BIGNUM对象
    dh_session_clear(&session);//安全清除DH会话（特别保护私钥）
    close(client_socket);//关闭网络连接
    
    return 0;
}