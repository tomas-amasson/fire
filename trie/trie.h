#ifndef TRIE_H
#define TRIE_H

#include <stdint.h>

#define IN 	0
#define OUT 	1
#define BOTH	2

typedef struct trnode {
	uint8_t		block;
	uint8_t 	ways;

	struct trnode 	*right;
	struct trnode 	*left;
} trnode;

typedef struct {
	trnode *root;
} trtree;

trnode * trnode_init(uint8_t block, uint8_t ways);
trtree * trtree_init();

trnode * tr_search(trtree *t, uint32_t value, uint8_t deep);
uint8_t tr_insert(trtree *t, uint32_t value, uint8_t deep, uint8_t ways);
uint8_t tr_remove(trtree *t, uint32_t value, uint8_t deep);
uint8_t blocked(trtree *t, uint32_t value, uint8_t deep, uint8_t ways);

void tr_free(trnode * node);

#endif
