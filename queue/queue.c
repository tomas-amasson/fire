#include "queue.h"
#include <stdlib.h>

queue* queue_init(uint32_t max)
{
	queue *ret = (queue *) malloc(sizeof(queue));
	ret->array = (uint8_t **) malloc(sizeof(uint8_t *) * max);

	ret->max  = max;
	ret->size = 0;
	ret->head = 0;
	ret->tail = 0;

	return ret;
}

uint8_t enqueue(queue *q, uint8_t *val)
{
	if (q->size == q->max)
	{
		return 1;
	}

	q->array[q->tail] = val;
	
	set_tail(q);

	return 0;
}

uint8_t* off_enq(queue *q)
{
	return q->array[q->tail];
}

void set_tail(queue *q)
{
	q->size++;
	
	if (q->tail == q->max - 1)
	{
		q->tail = 0;
	}
	else
	{
		q->tail++;
	}
	
	return ;
}

uint8_t* dequeue(queue *q)
{
	if (q->size == 0)
	{
		return NULL;
	}

	uint8_t *ret = q->array[q->head];
	
	if (q->head == q->max - 1)
	{
		q->head = 0;
	}
	else
	{
		q->head++;
	}

	return ret;
}
