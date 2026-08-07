#include "trie.h"
#include <stdio.h>
#include <stdlib.h>

trnode * trnode_init(uint8_t block, uint8_t ways)
{
	trnode *ret 	= (trnode *) malloc(sizeof(trnode));
	ret->block	= block;
	ret->ways	= ways;

	ret->left	= NULL;
	ret->right	= NULL;

	return ret;
}

trtree * trtree_init()
{
	trtree *ret 	= (trtree *) malloc(sizeof(trtree));
	
	if (!ret)
	{
		return ret;
	}

	ret->root	= trnode_init(0, 2);

	ret->root->left	 = trnode_init(0, 2);
	ret->root->right = trnode_init(0, 2);

	return ret;
}

trnode * tr_search(trtree *t, uint32_t value, uint8_t deep)
{
	trnode *target 	= t->root;
	uint32_t mask 	= 0x1;

	for (uint8_t i = 0; i < deep; i++)
	{
		if (target == NULL)
			break;

		if (value & mask)
			target = target->right;
		else
			target = target->left;

		mask = (mask << 1);
	}

	return target;
}

uint8_t tr_insert(trtree *t, uint32_t value, uint8_t deep, uint8_t ways)
{
	uint32_t mask	= 0x1;
	trnode * target = t->root; 

	for (uint8_t i = 0; i < deep; i++)
	{
		if (value & mask)
		{
			if (target->right == NULL)
			{
				target->right = trnode_init((uint8_t) (i == deep - 1), ways);
				if (target->right == NULL)
				{
					return 1;
				}
			}
			target = target->right;
			printf("1: %d - %d\n", (i == deep - 1), i);
		}
		else
		{
			if (target->left == NULL)
			{
				target->left = trnode_init((uint8_t) (i == deep - 1), ways);
				if (target->left == NULL)
				{
					return 1;
				}
			}
			target = target->left;
			printf("0: %d - %d\n", (i == deep - 1), i);
		}

		mask = (mask << 1);
	}

	target->block = 1;
	target->ways = ways;
	return 0;
}

uint8_t tr_remove(trtree *t, uint32_t value, uint8_t deep)
{
	trnode * ret = tr_search(t, value, deep);

	if (!ret)
	{
		return 1;
	}

	ret->block = 0;
	return 0;
}

uint8_t blocked(trtree *t, uint32_t value, uint8_t deep, uint8_t ways)
{
	trnode *tracker = t->root;

	uint32_t mask = 0x1;

	for (uint8_t i = 0; i < deep; i++)
	{
		if (value & mask)
			tracker = tracker->right;
		else
			tracker = tracker->left;

		mask = (mask << 1);

		if (!tracker)
		{
			return 0;
		}

		else if (tracker->block && (tracker->ways == ways || tracker->ways > 1))
		{
			printf("%d (%b) - till: %b\n", value, value, value & mask); // DEBUG
			return 1;
		}
	}

	return tracker->block && (tracker->ways == ways || tracker->ways > 1);
}

void tr_free(trnode * node)
{
	if (!node)
	{
		return ;
	}

	tr_free(node->left);
	tr_free(node->right);

	free(node);
}

