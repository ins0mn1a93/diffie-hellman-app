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

void print_hex(const char *label, const BIGNUM *num) {
    char *hex = BN_bn2hex(num);
    printf("%s: %s\n", label, hex);
    OPENSSL_free(hex);
}

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
        perror("Invalid address/Address not supported");
        exit(EXIT_FAILURE);
    }
    
    // 连接到服务器
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Connected to server at %s:%d\n", SERVER_IP, PORT);
    
    // 生成DH参数(实际应用中应使用固定安全参数)
    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();
    BN_hex2bn(&p, "e6f03f6f711b0c24ff7afe3605a17ab3a11d3e075483aa211958d903f2b41b4b6a6ea1c19bf3144b28ae2575fabe896b1c72b3775a81b3f341ab1ec1adf34f2b"); // 示例使用小素数
    BN_set_word(g, 2);  // 使用2作为生成元
    
    // 初始化DH会话
    DHSession session;
    if (dh_session_init(&session, p, g) != 0) {
        fprintf(stderr, "Failed to initialize DH session\n");
        close(client_socket);
        exit(EXIT_FAILURE);
    }
    
    print_hex("Client private key", session.private_key);
    // print_hex("Client public key", session.public_key);
    
    // 序列化并发送公钥
    char buffer[BUFFER_SIZE];
    int len = dh_serialize_key(session.public_key, buffer, sizeof(buffer));
    if (send(client_socket, buffer, len, 0) != len) {
        perror("Send failed");
        dh_session_clear(&session);
        close(client_socket);
        exit(EXIT_FAILURE);
    }
    
    printf("Sent public key to server\n");
    
    // 接收服务器公钥
    len = recv(client_socket, buffer, sizeof(buffer), 0);
    if (len <= 0) {
        perror("Receive failed");
        dh_session_clear(&session);
        close(client_socket);
        exit(EXIT_FAILURE);
    }
    
    BIGNUM *server_pubkey = BN_new();
    if (dh_deserialize_key(buffer, len, server_pubkey) != 0) {
        fprintf(stderr, "Failed to deserialize server public key\n");
        BN_free(server_pubkey);
        dh_session_clear(&session);
        close(client_socket);
        exit(EXIT_FAILURE);
    }
    
    print_hex("Received server public key", server_pubkey);
    
    // 计算共享密钥
    if (dh_compute_shared_secret(&session, server_pubkey) != 0) {
        fprintf(stderr, "Failed to compute shared secret\n");
        BN_free(server_pubkey);
        dh_session_clear(&session);
        close(client_socket);
        exit(EXIT_FAILURE);
    }
    
    print_hex("Shared secret", session.shared_secret);
    
    // 清理
    BN_free(server_pubkey);
    BN_free(p);
    BN_free(g);
    dh_session_clear(&session);
    close(client_socket);
    
    printf("Client exiting...\n");
    return 0;
}