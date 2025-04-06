CC = clang

CFLAGS := -O3 -Wall -Werror \
          -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types \
          -fno-stack-protector -fno-jump-tables -fno-unroll-loops \
          -target bpf

ifeq ($(DEBUG),1)
  CFLAGS += -g
endif

XDP_PROG = xdp
OBJ = $(XDP_PROG).o

.PHONY: all clean

all: $(OBJ)

$(OBJ): $(XDP_PROG).c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)
