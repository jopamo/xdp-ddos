CC = clang

CFLAGS := -O3 -Wall -Werror \
		  -D __BPF_TRACING__ \
          -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types \
          -fno-stack-protector -fno-jump-tables -fno-unroll-loops \
          -emit-llvm -g -target bpf

XDP_PROG = xdp
OBJ = $(XDP_PROG).o

.PHONY: all clean

all: $(OBJ)

$(OBJ): $(XDP_PROG).c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)
