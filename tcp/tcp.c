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
	
	int16_t optsiz = (ret->header->offset * 4) - 20;
	if (optsiz > 0)
	{
		ret->header->options = (uint8_t *) malloc(sizeof(uint8_t) * optsiz);
		memcpy(ret->header->options, &payload[20], optsiz);
	}

	else
	{
		ret->header->options = NULL;
	}
	
	ret->msg = &payload[ret->header->offset];

	return ret;
}

tcphdr * tcp_extract(uint8_t *payload)
{
	tcphdr * ret = (void *)payload;

	return ret;
}

uint16_t tcp_check(tcp *pack, ip *info, uint16_t check)
{
	tcphdr *header = pack->header;

	uint16_t flags = (header->offset << 12) | (header->reserved << 9)| header->flags;

	// Fake IP header
	uint32_t sz  = info->tot_lenght - ((uint32_t) info->ihl << 2);

	// Continuous mem
	uint16_t ptroff = 20;
	uint8_t *pseudo = (uint8_t *) malloc(sz);
	memset(pseudo, 0, sz);

	// Starting Value
	uint32_t ret = 0;
	ret += sum16from32((info->from));
	ret += sum16from32((info->to));
	ret += 0x0006;
	ret += (sz);
	
	// Fill buffer
	fill8from16(pseudo, header->source);
	fill8from16(pseudo + 2, header->destin);
	fill8from32(pseudo + 4, header->seqnum);
	fill8from32(pseudo + 8, header->acknum);
	fill8from16(pseudo + 12, flags);
	fill8from16(pseudo + 14, header->winsiz);
	fill8from16(pseudo + 16, check); 
	fill8from16(pseudo + 18, header->urgptr);
	
	if (header->offset * 4 - 20 > 0)
	{
		memcpy(pseudo + 20, header->options, (header->offset * 4 - 20));
		ptroff = header->offset * 4;
	}
	if (sz - ptroff > 0)
	{
		memcpy(pseudo + ptroff, pack->msg, sz - ptroff);
	}
	ret = checksum(pseudo, sz, ret);

	free(pseudo);
	return ret;
}

uint16_t tcp_checksum(uint8_t *msg, uint16_t lenght)
{
	return 0;
}


uint8_t tcp_connect(tcp *pack, uint8_t *tw_stage, uint32_t acknumber, ip *info)
{
	uint8_t flags = pack->header->flags;
	uint8_t stage = *tw_stage;

	// Begining of connection
	if (flags == SYN)
	{
		if (!stage)
		{
			*tw_stage = SYN | ACK;
			uint32_t rand = unix_random();
			if (!rand)
			{
				return 1;
			}

			pack->header->seqnum = endianness32(rand);
			pack->header->acknum++;


			
			uint32_t temp = info->from;
			info->from = info->to;
			info->to   = temp;
			info->ihl   = 5;
			info->tot_lenght = 40; // TCP: 20 bytes
		
			temp = pack->header->source;
			pack->header->source = pack->header->destin;
			pack->header->destin = temp;

			pack->header->offset = 5;

			pack->header->checksum = endianness16(tcp_check(pack, info, 0));

			return 0;
		}

		// Connection Failed, try again.
		else if (pack->header->acknum == acknumber)
		{
			*tw_stage = 0;
			return tcp_connect(pack, tw_stage, acknumber, info);
		}
		else
		{
			return 1;
		}
	}

	else if (flags == ACK && (stage == (SYN | ACK)))
	{
		return 0;
	}

	else
	{
		return 1;
	}

	return 1;
}


void tcp_free(tcp *pack)
{
	if (pack->header->options != NULL)
	{
		free(pack->header->options);
	}
	free(pack->header);
	free(pack);
}

uint32_t unix_random()
{
	uint32_t ret;
	int32_t randfd = open("/dev/urandom", 0, O_RDONLY);
	if (randfd < 0)
	{
		return 0;
	}

	if (read(randfd, &ret, 4) != 4)
	{
		return 0;
	}

	close(randfd);
	return ret;
}
