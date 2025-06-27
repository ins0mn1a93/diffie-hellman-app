#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include "diffie_hellman.h"

#pragma comment(lib, "ws2_32.lib")

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 4096

int main() {
    WSADATA wsaData;
    SOCKET client_socket;
    struct sockaddr_in server_addr;
    
    // 初始化Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }
    
    // 创建套接字
    if ((client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    
    // 配置服务器地址
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address: %d\n", WSAGetLastError());
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }
    
    // 连接服务器
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Connection failed: %d\n", WSAGetLastError());
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }
    
    printf("Connected to server\n");
    
    // 接收DH参数
    char params_buffer[BUFFER_SIZE * 2];
    int recv_len = recv(client_socket, params_buffer, sizeof(params_buffer) - 1, 0);
    if (recv_len <= 0) {
        fprintf(stderr, "Receive parameters failed: %d\n", WSAGetLastError());
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }
    params_buffer[recv_len] = '\0';
    
    // 解析参数
    char *p_hex = strtok(params_buffer, "\n");
    char *g_hex = strtok(NULL, "\n");
    
    if (!p_hex || !g_hex) {
        fprintf(stderr, "Invalid parameter format\n");
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }
    
    BIGNUM *p = NULL, *g = NULL;
    if (dh_deserialize_key(p_hex, strlen(p_hex), &p) != 0 || 
        dh_deserialize_key(g_hex, strlen(g_hex), &g) != 0) {
        fprintf(stderr, "Invalid DH parameters\n");
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }
    
    // 初始化会话
    DHSession session;
    memset(&session, 0, sizeof(session));
    if (dh_session_init(&session, p, g) != 0) {
        fprintf(stderr, "Session initialization failed\n");
        BN_free(p);
        BN_free(g);
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }
    
    // 发送客户端公钥
    char client_pub_hex[BUFFER_SIZE];
    dh_serialize_key(session.public_key, client_pub_hex, sizeof(client_pub_hex));
    send(client_socket, client_pub_hex, (int)strlen(client_pub_hex), 0);
    
    // 接收服务器公钥
    char server_pub_buffer[BUFFER_SIZE];
    recv_len = recv(client_socket, server_pub_buffer, sizeof(server_pub_buffer) - 1, 0);
    if (recv_len <= 0) {
        fprintf(stderr, "Receive server public key failed: %d\n", WSAGetLastError());
        dh_session_clear(&session);
        BN_free(p);
        BN_free(g);
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }
    server_pub_buffer[recv_len] = '\0';
    
    BIGNUM *server_pub = NULL;
    if (dh_deserialize_key(server_pub_buffer, recv_len, &server_pub) != 0) {
        fprintf(stderr, "Invalid server public key\n");
        dh_session_clear(&session);
        BN_free(p);
        BN_free(g);
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }
    
    // 计算共享密钥
    if (dh_compute_shared_secret(&session, server_pub) == 0) {
        char *shared_hex = BN_bn2hex(session.shared_secret);
        printf("Shared secret: %s\n", shared_hex);
        OPENSSL_free(shared_hex);
    } else {
        fprintf(stderr, "Shared secret computation failed\n");
    }
    
    // 清理资源
    BN_free(server_pub);
    BN_free(p);
    BN_free(g);
    dh_session_clear(&session);
    closesocket(client_socket);
    WSACleanup();
    
    return 0;
}
