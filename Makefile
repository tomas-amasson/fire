
CC = gcc
FLAGS = -g -Wall
TARGET = fire
SRC = firewall.c stack/stack.c queue/queue.c hash/hash.c ip/ip.c

$(TARGET): $(SRC)
	$(CC) $(FLAGS) $(SRC) -o $(TARGET)


run: $(TARGET)
	sudo ./$(TARGET)
