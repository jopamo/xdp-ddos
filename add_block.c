#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

struct lpm_key {
	__u32 prefixlen;
	__u8 data[4];
};

int main(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "Usage: %s <pinned_map_path> <ip> <prefixlen>\n", argv[0]);
		return 1;
	}

	// Open the pinned map by path to get its file descriptor
	int map_fd = bpf_obj_get(argv[1]);
	if (map_fd < 0) {
		fprintf(stderr, "Failed to open pinned map at %s: %s\n", argv[1], strerror(errno));
		return 1;
	}

	struct lpm_key key;
	key.prefixlen = atoi(argv[3]);
	if (inet_pton(AF_INET, argv[2], key.data) != 1) {
		fprintf(stderr, "Invalid IP address: %s\n", argv[2]);
		close(map_fd);
		return 1;
	}

	__u8 value = 0;
	int err = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
	if (err) {
		fprintf(stderr, "Failed to update map: %s\n", strerror(-err));
	} else {
		printf("Added %s/%u to blocklist\n", argv[2], key.prefixlen);
	}

	close(map_fd);
	return err ? 1 : 0;
}
