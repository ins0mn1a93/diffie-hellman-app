# 编译器和标志
CC = gcc
CFLAGS = -Wall -g -std=c11 -I./diffie-hellman -pthread
LIBS = -lcrypto

# 目标可执行文件
TARGET_SERVER = server
TARGET_CLIENT = client

# 源文件目录
SRC_DIR = diffie-hellman

# 源文件
DH_SRC = $(SRC_DIR)/diffie-hellman.c
SERVER_SRC = $(SRC_DIR)/server.c
CLIENT_SRC = $(SRC_DIR)/client.c

# 目标文件
DH_OBJ = diffie-hellman.o
SERVER_OBJ = server.o
CLIENT_OBJ = client.o

# 默认目标
all: $(TARGET_SERVER) $(TARGET_CLIENT)

# 编译服务端
$(TARGET_SERVER): $(SERVER_OBJ) $(DH_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

# 编译客户端
$(TARGET_CLIENT): $(CLIENT_OBJ) $(DH_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

# 显式规则编译每个目标文件
$(DH_OBJ): $(DH_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(SERVER_OBJ): $(SERVER_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(CLIENT_OBJ): $(CLIENT_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

# 清理
clean:
	rm -f *.o $(TARGET_SERVER) $(TARGET_CLIENT)

# 运行服务端
run-server: $(TARGET_SERVER)
	./$(TARGET_SERVER)

# 运行客户端
run-client: $(TARGET_CLIENT)
	./$(TARGET_CLIENT)

# 伪目标声明
.PHONY: all clean run-server run-client