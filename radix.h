#ifndef RADIXTREE
#define RADIXTREE

#define RADIXTREE_KEYSIZE 128

typedef struct rxt_node {
    int color;
    char *key;
    int ksize;
    void *value;
    int pos; // bit index of the key to compare at (critical position)
    long keycache[RADIXTREE_KEYSIZE/sizeof(long)];
#ifdef RADIXTREE_DEBUG
    int level; // tree level; for debug only
    int parent_id; //for debug only
#endif
    struct rxt_node *parent;
    struct rxt_node *left;
    struct rxt_node *right;
}rxt_node;

int rxt_put(const char*, void *, rxt_node*);
void* rxt_get(const char*, rxt_node*);
void* rxt_delete(const char*, rxt_node*);

int rxt_put2(const void *key, int ksize, void *value, rxt_node *n);
void* rxt_get2(const void*, int ksize, rxt_node*);
void* rxt_delete2(const void*, int ksize, rxt_node*);

/* This allows fast recovery of data when a parent
 * of them was requested before */
rxt_node* rxt_get_node(const void*, int ksize, rxt_node*);

void rxt_free(rxt_node *);
rxt_node *rxt_init();

#endif // RADIXTREE
