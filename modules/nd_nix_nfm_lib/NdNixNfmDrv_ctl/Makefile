# Makefile for building the user application

# 변수 정의
CC = gcc
CFLAGS = -Wall -ldl
LIB_NAME = -lnd_nix_nfm_lib
SOURCE = nixdrvctl.c

# 기본 타겟
all: nixdrvctl

# 사용자 애플리케이션 빌드
nixdrvctl: $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $^ -L. $(LIB_NAME)

# 클린업
clean:
	rm -f nixdrvctl

.PHONY: all clean

