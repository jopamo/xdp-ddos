CC = gcc
BPF_CC = clang

CFLAGS = -O3 -Wall -Werror
BPF_CFLAGS = -O3 -Wall -Werror \
			 -D __BPF_TRACING__ \
			 -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types \
			 -fno-stack-protector -fno-jump-tables -fno-unroll-loops \
			 -g -target bpf

LIBS = -lbpf

BPF_PROGS = ddos.o drop.o
USER_PROG = add_block

all: $(BPF_PROGS) $(USER_PROG)

ddos.o: ddos.c
	$(BPF_CC) $(BPF_CFLAGS) -c $< -o $@

drop.o: drop.c
	$(BPF_CC) $(BPF_CFLAGS) -c $< -o $@

$(USER_PROG): add_block.c
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

clean:
	rm -f $(BPF_PROGS) $(USER_PROG)

install:
	cp $(USER_PROG) /usr/local/bin/
	cp $(BPF_PROGS) /usr/local/lib/bpf/
