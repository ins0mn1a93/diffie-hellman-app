CC = gcc
CFLAGS = -Wall -g -std=c11
LIBS = -lssl -lcrypto

# 目标可执行文件
TARGET_SERVER = server
TARGET_CLIENT = client

# 服务端的源文件
SRC_SERVER = src/diffie_hellman.c src/server.c
OBJ_SERVER = $(SRC_SERVER:.c=.o)

# 客户端的源文件
SRC_CLIENT = src/diffie_hellman.c src/client.c
OBJ_CLIENT = $(SRC_CLIENT:.c=.o)

# 默认目标
all: $(TARGET_SERVER) $(TARGET_CLIENT)

# 编译服务端
$(TARGET_SERVER): $(OBJ_SERVER)
	$(CC) $(OBJ_SERVER) -o $(TARGET_SERVER) $(LIBS)

# 编译客户端
$(TARGET_CLIENT): $(OBJ_CLIENT)
	$(CC) $(OBJ_CLIENT) -o $(TARGET_CLIENT) $(LIBS)

# 编译.c文件为.o文件
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理中间文件
clean:
	rm -f src/*.o $(TARGET_SERVER) $(TARGET_CLIENT)
