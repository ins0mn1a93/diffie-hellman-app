#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/bn.h>
#include "diffie-hellman.h"

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int client_socket;
    struct sockaddr_in server_addr;
    
    // 创建套接字
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }
    
    // 配置服务器地址
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
    if (dh_generate_parameters(2048, &p, &g) != 0) {
        fprintf(stderr, "Failed to generate DH parameters\n");
        close(client_socket);
        exit(EXIT_FAILURE);
    }
    
    // 初始化DH会话
    DHSession session;
    if (dh_session_init(&session, p, g) != 0) {
        fprintf(stderr, "Failed to initialize DH session\n");
        BN_free(p);
        BN_free(g);
        close(client_socket);
        exit(EXIT_FAILURE);
    }
    
    // 序列化并发送公钥
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
    
    // 接收服务器公钥
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
    
    // 计算共享密钥
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
    DerivedKeys keys;
    const unsigned char salt[] = "StaticSaltForDemo";
    if (dh_derive_keys(session.shared_secret, salt, sizeof(salt)-1, &keys) != 0) {
        fprintf(stderr, "Key derivation failed\n");
    } else {
        printf("Key exchange successful!\n");
    }
    
    // 清理
    BN_free(server_pubkey);
    BN_free(p);
    BN_free(g);
    dh_session_clear(&session);
    close(client_socket);
    
    return 0;
}