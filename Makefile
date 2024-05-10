ARCH = $(shell uname -m)
CLANG ?= clang
LIBS += -lbpf -lbfd
CFLAGS += -g -O2 -I .
CXXFLAGS += -std=c++20
BPFFLAGS = -target bpf -c -D__${ARCH}__

all: target/hijack

target/hijack: hijack/hijack.skel.h hijack/* hijack-common/*
	${CXX} ${CFLAGS} ${CXXFLAGS} hijack/*.cc ${LIBS} -o target/hijack

hijack/hijack.skel.h: target/hijack.o
	bpftool gen skeleton target/hijack.o > hijack/hijack.skel.h

target/hijack.o: hijack-ebpf/vmlinux.h hijack-ebpf/*.h hijack-ebpf/hijack.c hijack-common/*
	${CLANG} ${CFLAGS} ${BPFFLAGS} hijack-ebpf/hijack.c -o target/hijack.o

hijack-ebpf/vmlinux.h:
	@bpftool version > /dev/null
	@ls /sys/kernel/btf/vmlinux > /dev/null
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > hijack-ebpf/vmlinux.h

clean:
	${RM} hijack-ebpf/vmlinux.h hijack/hijack.skel.h target/*

test: hijack/hijack.skel.h
	${CXX} ${CFLAGS} ${CXXFLAGS} hijack-test/binary-test.cc hijack/{binary.cc,process.cc} ${LIBS} -o target/binary-test && target/binary-test
	${CXX} ${CFLAGS} ${CXXFLAGS} hijack-test/cgroup-mount-path-test.cc hijack/{binary.cc,process.cc,utils.cc} ${LIBS} -o target/cgroup-mount-path-test && target/cgroup-mount-path-test
	

printk:
	cat /sys/kernel/debug/tracing/trace_pipe

.PHONY: all clean test printk
