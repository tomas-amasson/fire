#ifndef QUEUE_H
#define QUEUE_H

#include <stdint.h>

typedef struct {
	uint8_t **array;
	uint32_t max;
	uint32_t size;

	uint32_t head;
	uint32_t tail;
} queue;


queue* queue_init(uint32_t max);

uint8_t enqueue(queue *q, uint8_t *val);
uint8_t* off_enq(queue *q);
void 	set_tail(queue *q);
uint8_t* dequeue(queue *q);


#endif
