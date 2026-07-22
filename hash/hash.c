#include <stdlib.h>
#include "hash.h"

hashnode *hashn_init(uint16_t id, uint16_t source, uint16_t destin, uint8_t protocol)
{
	hashnode *ret = (hashnode *) malloc(sizeof(hashnode));

	ret->id 	= id;
	ret->source 	= source;
	ret->destin 	= destin;
	ret->protocol 	= protocol;
	ret->miss	= 0;

	ret->box 	= NULL;
	ret->next 	= NULL;

	return ret;
}

void free_hashn(hashnode *hn)
{

	// limpa fragmentos
	fragment * current = hn->box;
	if (current == NULL)
	{
		return ;
	}
		

	fragment * forward = current->forward;

	while (forward != NULL)
	{
		free(current);

		current = forward;
		forward = current->forward;
	}
	free(current);

	free(hn);
	return ;
}


hash * hash_init(uint32_t max)
{
	hash *ret = (hash *) malloc(sizeof(hash));
	ret->array = (hashnode **) calloc(max, sizeof(hashnode *));

	ret->max = max;

	return ret;
}

void free_hash(hash *h)
{
	for (uint32_t i = 0; i < h->max; i++)
	{
		go_down(h->array[i]);
	}

	free(h->array);
	free(h);
	return ;
}

void go_down(hashnode *hn)
{
	if (hn == NULL)
	{
		return ;
	}

	go_down(hn->next);
	free_hashn(hn);

	return ;
}

void add_hashn(hash *h, hashnode * hn)
{	
	uint16_t id = hn->id;

	if (h->array[id] == NULL)
	{
		h->array[id] = hn;
		return ;
	}

	hashnode * tracker = h->array[id];
	while (tracker->next != NULL)
	{
		tracker = tracker->next;
	}

	tracker->next = hn;
	return ;
}

void pop_hashn(hash *h, hashnode *hn)
{
	uint16_t id = hn->id;

	if (h->array[id] == NULL)
	{
		return ;
	}
	
	hashnode * tracker = h->array[id];
	hashnode * target;
	if (tracker == hn)
	{
		h->array[id] = tracker->next;
	}
	
	else
	{
		while (tracker->next != hn && tracker->next != NULL)
		{
			tracker = tracker->next;
		}

		if (tracker->next == NULL)
		{
			return ;
		}

		target = tracker->next;
		tracker->next = target->next;
	}

	free_hashn(target);
	return ;
}


fragment * frag_init(uint16_t offset, uint8_t *data, uint8_t MF, uint16_t size)
{
	fragment *ret = (fragment *) malloc(sizeof(fragment));

	ret->forward 	= NULL;
	ret->backward 	= NULL;

	ret->data 	= data;
	ret->offset 	= offset;
	ret->MF		= MF;
	ret->psize	= size;

	return ret;
}


uint8_t add_frag(hashnode * hn, fragment *fr)
{	
	hn->miss += fr->psize;

	if (!fr->MF)
	{
		hn->miss = missing((fr->offset * 8) + fr->psize, hn->miss);
	}

	if (hn->box == NULL)
	{
		hn->box = fr;
		return 0; 
	}


	fragment *tracker = hn->box;
	uint16_t current = hn->box->offset;

	while (tracker->forward != NULL && fr->offset > current)
	{
		tracker = tracker->forward;
		current = tracker->offset;
	}

	if (fr->offset < current)
	{
		fr->forward = tracker;
		fr->backward = tracker->backward;

		if (tracker->backward != NULL)
		{
			tracker->backward->forward = fr;
		}

		tracker->backward = fr;
	}

	else
	{
		fr->forward 	= tracker->forward;
		fr->backward 	= tracker;

		if (tracker->forward != NULL)
		{
			tracker->forward->backward = fr;
		}

		tracker->forward = fr;
	}

	return hn->miss? 0: 1;
}


hashnode *search_hn(hash *h, uint16_t id, uint16_t source, uint16_t destin, uint8_t protocol)
{
	hashnode *tracker = h->array[id]; 
	
	while (tracker != NULL)
	{
		if (source == tracker->source && destin == tracker->destin && protocol == tracker->protocol)
		{
			return tracker;
		}

		tracker = tracker->next;
	}
	return (hashnode *)NULL;
}

uint16_t missing(uint16_t lenght, uint16_t miss)
{
	return lenght - miss;
}

uint8_t * hash_obtain_package(hashnode *hn)
{
	uint8_t *ret = (uint8_t *) malloc(sizeof(uint8_t));
	uint32_t current = 0;
	uint32_t psize;

	fragment *fr = hn->box;
	psize = fr->psize;

	while (fr)
	{	
		psize = fr->psize;
		ret = realloc(ret, sizeof(uint8_t) * (psize + current));
		

		for (uint32_t i = current; i < psize; i++)
		{
			ret[i] = fr->data[i];
		}

		current += psize;
		fr = fr->forward;
	}

	return ret;
}
