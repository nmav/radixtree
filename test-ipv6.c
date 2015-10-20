#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "radix.h"

// prints the tree level by level, for debug purposes.
// [%d/%d] indicates the current id, and the id of the parent.
// (%s) indicates an inner node's key.
// id is assigned in the order read from the queue.
// XXX only use this for debugging small (<50key) trees!
static void print_tree(rxt_node * root)
{
    int i, write = 0, read = 0, prev_level = -1;
    rxt_node *queue[100];
    for (i = 0; i < 100; i++)
	queue[i] = NULL;
    root->parent_id = read;
    root->level = 0;
    queue[write++] = root;

    while (read != write) {
	char ip[64] = "";
	char ipv6[16];
	rxt_node *n = queue[read++];
	// insert linebreak if needed

	if (prev_level != n->level) {
	    printf("\n\nlevel %d:\n", n->level);
	    prev_level = n->level;
	}

	memset(ipv6, 0, sizeof(ipv6));
	memcpy(ipv6, n->key, n->ksize);
	inet_ntop(AF_INET6, ipv6, ip, sizeof(ip));

	if (n->color)
	    printf("[size: %d] %s[%d/%d] , ", n->ksize, ip, read, n->parent_id);
	else {
	    if (n->value) {
		printf("%d (%s)[%d/%d] ,", n->pos, ip, read, n->parent_id);
	    } else
		printf("%d (%s)[%d/%d] , ", n->pos, ip, read,
		       n->parent_id);

	    if (n->left) {
		rxt_node *left = n->left;
		left->level = n->level + 1;
		left->parent_id = read;
		queue[write++] = left;
	    }
	    if (n->right) {
		rxt_node *right = n->right;
		right->level = n->level + 1;
		right->parent_id = read;
		queue[write++] = right;
	    }
	}
    }
    printf("\n");
}

static int count_comparisons(rxt_node * root)
{
    if (!root || root->color)
	return 0;
    return root->pos + count_comparisons(root->left) +
	count_comparisons(root->right);
}

static int insert(const char *addr, unsigned prefix, rxt_node * root,
		   char *val)
{
    struct in6_addr in;

    if (inet_pton(AF_INET6, addr, &in) != 1)
	exit(1);
    return rxt_put2(in.s6_addr, prefix / 8, strdup(val), root);
}

static void *get(const char *addr, unsigned prefix, rxt_node * root)
{
    struct in6_addr in;

    if (inet_pton(AF_INET6, addr, &in) != 1)
	exit(1);
    return rxt_get2(in.s6_addr, prefix / 8, root);
}

static rxt_node *get_node(const char *addr, unsigned prefix, rxt_node * root)
{
    struct in6_addr in;

    if (inet_pton(AF_INET6, addr, &in) != 1)
	exit(1);
    return rxt_get_node(in.s6_addr, prefix / 8, root);
}

struct addresses_st {
    const char *address;
    unsigned prefix;
};

static struct addresses_st addresses[] = {
    {.address = "fc44:a988:a40:9600::",
     .prefix = 128},
    {.address = "fc6b:aa00::1",
     .prefix = 128},
    {.address = "fc44:a988:a40:9600::1",
     .prefix = 128},
    {.address = "fc44:a988:a40:9600:0000:ffd2::1",
     .prefix = 128},
    {.address = "fc44:a988:a4::",
     .prefix = 40},
    {.address = "fc44::",
     .prefix = 16},
    {.address = "fd97:16e4:f54e:5fc6:d101:09d2:f2f8:bb29",
     .prefix = 128},
    {.address = "fc44:a988:a40:9600:0000:ffd2::1",
     .prefix = 96},
    {.address = "fc9c:6c27:9cf9:cf80:a0df:93ad:f131:ed76",
     .prefix = 128},
    {.address = "fc0c:94fd:dabe:49aa:752e:aa76:eccc:b33b",
     .prefix = 128},
    {.address = "fce7:c0a7:f570:0584:2277:668e:7763:2905",
     .prefix = 128},
    {.address = "fdbe:63d9:afd4:6694:dd84:738c:8a5c:fd67",
     .prefix = 128},
    {.address = "fde8:b1dc:9bb2:dc8c:b0dc:8d2e:ef41:9c50",
     .prefix = 128},
    {.address = "fc44:a988:a40:9600::",
     .prefix = 56},
    {.address = "fde8:b1dc::",
     .prefix = 24},
    {.address = "fc6b:aa00::",
     .prefix = 24},
    {.address = NULL,
     .prefix = 0}
};

int main(int argc, char **argv)
{
    rxt_node *root = rxt_init(), *n;
    unsigned i;
    const char *v;

    for (i = 0;; i++) {
	if (addresses[i].address == NULL)
	    break;
	if (insert
	    (addresses[i].address, addresses[i].prefix, root,
	     "xx") != 0) {
	    fprintf(stderr, "%d: error in %d\n", i, __LINE__);
	    exit(1);
	}
    }

    print_tree(root);

    /* verify that everything is present */
    for (i = 0;; i++) {
	if (addresses[i].address == NULL)
	    break;
	v = get(addresses[i].address, addresses[i].prefix, root);
	if (v == NULL) {
	    fprintf(stderr, "cannot find %s/%d\n", addresses[i].address,
		    addresses[i].prefix);
	    exit(1);
	}
	if (strcmp(v, "xx") != 0) {
	    fprintf(stderr, "%d: error in %d\n", i, __LINE__);
	    exit(1);
	}
    }

    /* verify that tree recovery works */
    n = get_node("fc44::", 16, root);
    if (n == NULL) {
	    fprintf(stderr, "cannot find %s/%d\n", addresses[i].address,
		    addresses[i].prefix);
	    exit(1);
    }

    n = get_node("fc44:a988:a4::", 40, n);
    if (n == NULL) {
	    fprintf(stderr, "cannot find %s/%d\n", addresses[i].address,
		    addresses[i].prefix);
	    exit(1);
    }

    n = get_node("fc44:a988:a40:9600:0000:ffd2::1", 96, n);
    if (n == NULL) {
	    fprintf(stderr, "cannot find %s/%d\n", addresses[i].address,
		    addresses[i].prefix);
	    exit(1);
    }

    n = get_node("fc44:a988:a40:9600:0000:ffd2::1", 128, n);
    if (n == NULL) {
	    fprintf(stderr, "cannot find %s/%d\n", addresses[i].address,
		    addresses[i].prefix);
	    exit(1);
    }

    /* tree recover test finished */

    printf("---------------\n");
    printf("COMPARISONS: %d\n", count_comparisons(root));

    rxt_free(root);

    return 0;
}
