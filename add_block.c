/*
 * Helper to populate the pinned LPM_TRIE with IPs/CIDR ranges.
 * Build: gcc -O2 -Wall -I/usr/include -lbpf add_block.c -o add_block
 */
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#define CONFIG_FILE "/etc/xdp/block.conf"
#define MAX_LINE 256

struct lpm_key {
	__u32 prefixlen;
	__u32 data; /* __be32 */
};

/* ------------------- Test‑mode scaffolding ------------------- */
static int test_mode = 0;

struct mock_entry {
	char ip[INET_ADDRSTRLEN];
	__u32 prefixlen;
};
static struct mock_entry mock_added[1024];
static int mock_cnt;

/* ------------------- Core helpers ------------------- */
static int add_entry(int map_fd, const char *ip, __u32 prefix)
{
	struct lpm_key key = { .prefixlen = prefix };

	if (inet_pton(AF_INET, ip, &key.data) != 1) {
		fprintf(stderr, "Invalid IPv4 address: %s\n", ip);
		return -1;
	}

	__u8 value = 0;
	int err;

	if (test_mode) {
		snprintf(mock_added[mock_cnt].ip, INET_ADDRSTRLEN, "%s", ip);
		mock_added[mock_cnt++].prefixlen = prefix;
		err = 0;
	} else {
		err = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
		if (err)
			fprintf(stderr, "bpf_map_update_elem failed: %s\n", strerror(errno));
	}

	printf("%s %s/%u\n", err ? "Failed:" : "Added:", ip, prefix);
	return err;
}

static int load_from_cfg(int map_fd, const char *cfg_path)
{
	FILE *fp = fopen(cfg_path ? cfg_path : CONFIG_FILE, "r");
	if (!fp) {
		perror("open config");
		return -1;
	}

	char line[MAX_LINE];
	int added = 0, in_section = 0;

	while (fgets(line, sizeof(line), fp)) {
		char *s = line;
		while (isspace(*s))
			s++;
		char *e = s + strlen(s);
		while (e > s && isspace(*--e))
			*e = '\0';

		if (!*s || *s == '#')
			continue;

		if (*s == '[') { /* [section] */
			in_section = strstr(s, "blocked_ips") != NULL;
			continue;
		}

		if (!in_section)
			continue;

		if ((e = strchr(s, '#')))
			*e = '\0';
		while (*s && isspace(*s))
			s++;
		while (*s && isspace(s[strlen(s) - 1]))
			s[strlen(s) - 1] = '\0';

		char ip[INET_ADDRSTRLEN];
		__u32 pref;
		if (sscanf(s, "%[^/]/%u", ip, &pref) == 2) {
			if (!add_entry(map_fd, ip, pref))
				added++;
		}
	}
	fclose(fp);
	printf("Loaded %d entries\n", added);
	return 0;
}

/* ------------------- Unit tests (optional) ------------------- */
static void reset_mock(void)
{
	mock_cnt = 0;
	memset(mock_added, 0, sizeof(mock_added));
}

static void run_tests(void)
{
	test_mode = 1;
	/* simple asserts */
	reset_mock();
	assert(add_entry(0, "192.0.2.1", 32) == 0 && mock_cnt == 1);

	reset_mock();
	assert(add_entry(0, "999.999.1.1", 24) == -1 && mock_cnt == 0);

	/* config load sanity */
	FILE *tmp = tmpfile();
	assert(tmp);
	fprintf(tmp, "[blocked_ips]\n10.0.0.0/8\n192.168.0.0/16\ninvalid\n");
	fflush(tmp);
	fseek(tmp, 0, SEEK_SET);

	char path[] = "/tmp/blockXXXXXX";
	int fd = mkstemp(path);
	assert(fd != -1);
	FILE *dup = fdopen(fd, "w");
	assert(dup);
	fseek(tmp, 0, SEEK_SET); /* copy tmp‑>dup */
	char buf[64];
	size_t n;
	while ((n = fread(buf, 1, sizeof(buf), tmp)))
		fwrite(buf, 1, n, dup);
	fclose(tmp);
	fclose(dup);

	reset_mock();
	assert(load_from_cfg(0, path) == 0 && mock_cnt == 2);
	unlink(path);

	printf("All unit tests passed.\n");
	test_mode = 0;
}

/* ------------------- main ------------------- */
int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "--test")) {
		run_tests();
		return 0;
	}

	if (argc < 2 || argc > 4) {
		fprintf(stderr,
			"Usage: %s <pinned_map> [<ip> <prefix>]\n"
			"       No IP ⇒ bulk‑load from %s\n",
			argv[0], CONFIG_FILE);
		return 1;
	}

	int map_fd = bpf_obj_get(argv[1]);
	if (map_fd < 0) {
		perror("bpf_obj_get");
		return 1;
	}

	int rc = 0;
	if (argc == 2)
		rc = load_from_cfg(map_fd, NULL);
	else
		rc = add_entry(map_fd, argv[2], atoi(argv[3]));

	close(map_fd);
	return rc;
}
