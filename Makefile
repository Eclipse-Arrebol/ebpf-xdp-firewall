# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
CLANG ?= clang
CC ?= gcc
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPFTOOL ?= bpftool

LIBBPF_SRC := $(abspath ./libbpf/src)
LIBBPF_OBJ := $(abspath .output/libbpf.a)
INCLUDES := -I.output -I./libbpf/include/uapi

CFLAGS := -g -Wall $(INCLUDES)
LDFLAGS := -lelf -lz -lpthread

TARGET := firewall

.PHONY: all clean

all: $(TARGET)

# 创建输出目录
.output:
	mkdir -p .output

# 编译 libbpf
$(LIBBPF_OBJ): | .output
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(abspath .output/libbpf) \
		DESTDIR=$(abspath .output) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

# 编译 BPF 内核态代码
$(TARGET).bpf.o: $(TARGET).bpf.c | .output
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-c $< -o $@

# 生成 skeleton
$(TARGET).skel.h: $(TARGET).bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# 编译用户态代码
$(TARGET).o: $(TARGET).c $(TARGET).skel.h $(LIBBPF_OBJ)
	$(CC) $(CFLAGS) -c $< -o $@

# 链接
$(TARGET): $(TARGET).o $(LIBBPF_OBJ)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

clean:
	rm -rf .output $(TARGET) *.o *.skel.h