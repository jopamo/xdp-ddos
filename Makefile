CC = clang
CFLAGS = -O2 -Wall -target bpf -g
LDLIBS = -lelf -lz
XDP_PROG = xdp
OBJ = $(XDP_PROG).o

.PHONY: all clean load unload

all: $(OBJ)

$(OBJ): $(XDP_PROG).c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)
