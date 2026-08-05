#ifndef TRIE_H
#define TRIE_H

#include <stdint.h>



typedef struct trnode {
	uint8_t		block;

	struct trnode 	*right;
	struct trnode 	*left;
} trnode;

typedef struct {
	trnode *root;
} trtree;

trnode * trnode_init(uint8_t block);
trtree * trtree_init();

trnode * tr_search(trtree *t, uint32_t value, uint8_t deep);
uint8_t tr_insert(trtree *t, uint32_t value, uint8_t deep);
uint8_t tr_remove(trtree *t, uint32_t value, uint8_t deep);
uint8_t blocked(trtree *t, uint32_t value, uint8_t deep);

void tr_free(trnode * node);

#endif
