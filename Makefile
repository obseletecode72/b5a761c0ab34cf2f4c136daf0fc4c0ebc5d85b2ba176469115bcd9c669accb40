# Makefile - SSH Brute com RawSSH (biblioteca propria)
# Compilar em Linux: make
# Requer: libssl-dev (apt install libssl-dev)

CC = gcc
CFLAGS = -std=c11 -O3 -march=native -mtune=native -Wall -Wextra -pthread -D_GNU_SOURCE -I/opt/openssl3/include
LDFLAGS = -L/opt/openssl3/lib64 -lssl -lcrypto -lpthread -Wl,-rpath=/opt/openssl3/lib64

TARGET = ssh_brute
OBJS = rawssh.o ssh_brute.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

rawssh.o: rawssh.c rawssh.h
	$(CC) $(CFLAGS) -c -o $@ $<

ssh_brute.o: ssh_brute.c rawssh.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)

# Compilacao rapida (tudo em um comando)
quick:
	$(CC) $(CFLAGS) -o $(TARGET) rawssh.c ssh_brute.c $(LDFLAGS)

.PHONY: all clean quick
