#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/bn.h>
#include "diffie-hellman.h"

#define PORT 8080
#define BUFFER_SIZE 1024

typedef struct {
    int client_socket;
    struct sockaddr_in client_addr;
} thread_data_t;

void *handle_client(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    int client_socket = data->client_socket;
    char client_ip[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &(data->client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    printf("Client connected: %s\n", client_ip);
    
    // 动态生成DH参数
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
    if (dh_generate_parameters(2048, &p, &g) != 0) {
        fprintf(stderr, "Failed to generate DH parameters\n");
        close(client_socket);
        free(data);
        return NULL;
    }
    
    // 初始化DH会话
    DHSession session;
    if (dh_session_init(&session, p, g) != 0) {
        fprintf(stderr, "DH session init failed\n");
        BN_free(p);
        BN_free(g);
        close(client_socket);
        free(data);
        return NULL;
    }
    
    // 接收客户端公钥
    char buffer[BUFFER_SIZE];
    int len = recv(client_socket, buffer, sizeof(buffer), 0);
    if (len <= 0) {
        perror("Receive public key failed");
        dh_session_clear(&session);
        BN_free(p);
        BN_free(g);
        close(client_socket);
        free(data);
        return NULL;
    }
    
    BIGNUM *client_pubkey = BN_new();
    if (dh_deserialize_key(buffer, len, client_pubkey) != 0) {
        fprintf(stderr, "Deserialize client key failed\n");
        BN_free(client_pubkey);
        dh_session_clear(&session);
        BN_free(p);
        BN_free(g);
        close(client_socket);
        free(data);
        return NULL;
    }
    
    // 发送服务器公钥
    len = dh_serialize_key(session.public_key, buffer, sizeof(buffer));
    if (len < 0 || send(client_socket, buffer, len, 0) != len) {
        perror("Send public key failed");
        BN_free(client_pubkey);
        dh_session_clear(&session);
        BN_free(p);
        BN_free(g);
        close(client_socket);
        free(data);
        return NULL;
    }
    
    // 计算共享密钥
    if (dh_compute_shared_secret(&session, client_pubkey) != 0) {
        fprintf(stderr, "Compute shared secret failed\n");
        BN_free(client_pubkey);
        dh_session_clear(&session);
        BN_free(p);
        BN_free(g);
        close(client_socket);
        free(data);
        return NULL;
    }
    
    // 派生加密密钥
    DerivedKeys keys;
    const unsigned char salt[] = "StaticSaltForDemo";
    if (dh_derive_keys(session.shared_secret, salt, sizeof(salt)-1, &keys) != 0) {
        fprintf(stderr, "Key derivation failed\n");
    } else {
        printf("Key exchange successful with %s\n", client_ip);
    }
    
    // 清理
    BN_free(client_pubkey);
    BN_free(p);
    BN_free(g);
    dh_session_clear(&session);
    close(client_socket);
    free(data);
    
    return NULL;
}

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    // 创建套接字
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }
    
    // 配置服务器地址
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    // 绑定套接字
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    
    // 监听连接
    if (listen(server_socket, 5) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Server listening on port %d\n", PORT);
    
    while (1) {
        // 接受新连接
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }
        
        // 为每个客户端创建线程
        pthread_t thread_id;
        thread_data_t *data = malloc(sizeof(thread_data_t));
        if (!data) {
            perror("Memory allocation failed");
            close(client_socket);
            continue;
        }
        
        data->client_socket = client_socket;
        memcpy(&data->client_addr, &client_addr, sizeof(client_addr));
        
        if (pthread_create(&thread_id, NULL, handle_client, data) != 0) {
            perror("Thread creation failed");
            free(data);
            close(client_socket);
            continue;
        }
        
        // 分离线程，使其结束后自动释放资源
        pthread_detach(thread_id);
    }
    
    close(server_socket);
    return 0;
}