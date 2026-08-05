#include "tcp.h"

tcp * set_tcp(uint8_t *payload)
{
	tcp *ret = (tcp *) malloc(sizeof(tcp));
	ret->header = (tcphdr *) malloc(sizeof(tcphdr));
	
	ret->header->source = from8to16(payload[0], payload[1]);
	ret->header->destin = from8to16(payload[2], payload[3]);

	ret->header->seqnum = from16to32(from8to16(payload[4], payload[5]), from8to16(payload[6], payload[7]));
	ret->header->acknum = from16to32(from8to16(payload[8], payload[9]), from8to16(payload[10], payload[11]));

	ret->header->offset = 	(payload[12] >> 4) & 0x0F;
	ret->header->reserved = (payload[12] >> 1) & 0x07; // 0000 0111
	ret->header->flags  = 	(uint16_t)(payload[12] & 0x01) << 8| payload[13]; // 1000 0000

	ret->header->winsiz = from8to16(payload[14], payload[15]);
	ret->header->checksum = from8to16(payload[16], payload[17]);
	ret->header->urgptr = from8to16(payload[18], payload[19]);
	
	uint16_t optsiz = (ret->header->offset * 4) - 20;
	if (optsiz)
	{
		ret->header->options = (uint8_t *) malloc(sizeof(uint8_t) * optsiz);
		memcpy(ret->header->options, &payload[20], optsiz);
	}

	else
	{
		ret->header->options = NULL;
	}

	return ret;
}

uint8_t tcp_check(tcp *pack)
{
	uint8_t ret;
	return ret;
}

void tcp_connect(tcp *pack)
{

	return ;
}

void free_tcp(tcp *pack)
{
	free(pack->header->options);
	free(pack->msg);
	free(pack);
}
