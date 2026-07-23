#ifndef HASH_H
#define HASH_H

#include <stdint.h>
#include <string.h>

#pragma pack(1)

typedef struct fragment{
	uint16_t offset;
	uint8_t  *data;
	uint8_t  MF;
	uint16_t psize;

	struct fragment * forward;
	struct fragment * backward;
} fragment;


typedef struct hashnode{

	struct hashnode * next;
	
	uint16_t id;
	uint16_t miss;
	uint16_t source;
	uint16_t destin;
	uint8_t	 protocol;

	fragment * box;
} hashnode;


typedef struct {
	uint32_t max;
	hashnode ** array;
} hash;


hashnode *hashn_init(uint16_t id, uint16_t source, uint16_t destin, uint8_t protocol);
void 	free_hashn(hashnode *hn);
hash 	*hash_init(uint32_t max);
void 	go_down(hashnode *hn);
void 	free_hash(hash *h);
void 	add_hashn(hash *h, hashnode *hn);
void 	pop_hashn(hash *h, hashnode *hn);
uint8_t* hash_obtain_package(hashnode *hn);

uint16_t missing(uint16_t lenght, uint16_t miss);

hashnode *search_hn(hash *h, uint16_t id, uint16_t source, uint16_t destin, uint8_t protocol);

fragment * frag_init(uint16_t offset, uint8_t *data, uint8_t MF, uint16_t size);
uint8_t add_frag(hashnode * hn, fragment *fr);


#endif
