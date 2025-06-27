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

#define PORT 8080
#define BUFFER_SIZE 4096
#define DH_BITS 2048

typedef struct {
    SOCKET client_socket;
    struct sockaddr_in client_addr;
} ThreadParams;

DWORD WINAPI handle_client(LPVOID arg) {
    ThreadParams *params = (ThreadParams *)arg;
    SOCKET client_socket = params->client_socket;
    
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(params->client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    
    printf("Thread %lu handling client %s:%d\n", 
           GetCurrentThreadId(), 
           client_ip,
           ntohs(params->client_addr.sin_port));
    
    // 生成DH参数
    BIGNUM *p = NULL, *g = NULL;
    dh_generate_parameters(DH_BITS, &p, &g);
    
    // 初始化会话
    DHSession session;
    memset(&session, 0, sizeof(session));
    if (dh_session_init(&session, p, g) != 0) {
        fprintf(stderr, "Session initialization failed\n");
        closesocket(client_socket);
        free(params);
        return 1;
    }
    
    // 发送DH参数
    char p_hex[BUFFER_SIZE], g_hex[BUFFER_SIZE];
    dh_serialize_key(p, p_hex, sizeof(p_hex));
    dh_serialize_key(g, g_hex, sizeof(g_hex));
    
    char params_msg[BUFFER_SIZE * 2];
    snprintf(params_msg, sizeof(params_msg), "%s\n%s", p_hex, g_hex);
    send(client_socket, params_msg, (int)strlen(params_msg), 0);
    
    // 接收客户端公钥
    char buffer[BUFFER_SIZE];
    int recv_len = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (recv_len <= 0) {
        fprintf(stderr, "Receive client public key failed: %d\n", WSAGetLastError());
        dh_session_clear(&session);
        closesocket(client_socket);
        free(params);
        return 1;
    }
    buffer[recv_len] = '\0';
    
    BIGNUM *client_pub = NULL;
    if (dh_deserialize_key(buffer, recv_len, &client_pub) != 0) {
        fprintf(stderr, "Invalid client public key\n");
        dh_session_clear(&session);
        closesocket(client_socket);
        free(params);
        return 1;
    }
    
    // 发送服务器公钥
    char server_pub_hex[BUFFER_SIZE];
    dh_serialize_key(session.public_key, server_pub_hex, sizeof(server_pub_hex));
    send(client_socket, server_pub_hex, (int)strlen(server_pub_hex), 0);
    
    // 计算共享密钥
    if (dh_compute_shared_secret(&session, client_pub) == 0) {
        char *shared_hex = BN_bn2hex(session.shared_secret);
        printf("Shared secret: %s\n", shared_hex);
        OPENSSL_free(shared_hex);
    } else {
        fprintf(stderr, "Shared secret computation failed\n");
    }
    
    // 清理资源
    BN_free(client_pub);
    BN_free(p);
    BN_free(g);
    dh_session_clear(&session);
    closesocket(client_socket);
    free(params);
    
    printf("Thread %lu finished\n", GetCurrentThreadId());
    return 0;
}

int main() {
    WSADATA wsaData;
    SOCKET server_socket;
    struct sockaddr_in server_addr;
    
    // 初始化Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }
    
    // 创建套接字
    if ((server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    
    // 配置服务器
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    // 绑定和监听
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Bind failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        fprintf(stderr, "Listen failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    printf("Server listening on port %d\n", PORT);
    
    // 主循环
    while (1) {
        struct sockaddr_in client_addr;
        int client_addr_len = sizeof(client_addr);
        SOCKET client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_socket == INVALID_SOCKET) {
            fprintf(stderr, "Accept failed: %d\n", WSAGetLastError());
            continue;
        }
        
        // 创建线程参数
        ThreadParams *params = (ThreadParams *)malloc(sizeof(ThreadParams));
        params->client_socket = client_socket;
        memcpy(&params->client_addr, &client_addr, sizeof(client_addr));
        
        // 创建线程
        HANDLE thread = CreateThread(NULL, 0, handle_client, params, 0, NULL);
        if (thread == NULL) {
            fprintf(stderr, "Thread creation failed: %d\n", GetLastError());
            closesocket(client_socket);
            free(params);
        } else {
            CloseHandle(thread); // 不需要保持句柄
        }
    }
    
    closesocket(server_socket);
    WSACleanup();
    return 0;
}
