CC = gcc
CFLAGS = -Wall -Wextra -Iinclude
LDFLAGS = -lpthread

TARGET = monitor

SRC = src/main.c \
      src/scanner.c \
      src/logger.c \
      src/config.c \
      src/utils.c \
      src/webserver.c \
      src/anomaly.c \
      src/health.c \
      src/http_probe.c \
      src/http_health.c \
      src/http_anomaly.c \
      src/auth_anomaly.c \
      src/auth_status.c \
      src/status.c

OBJ = $(SRC:.c=.o)

$(TARGET): $(OBJ)
	$(CC) -o $(TARGET) $(OBJ) $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
