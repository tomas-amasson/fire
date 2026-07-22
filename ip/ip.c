#include "ip.h"

ip* ip_init(uint8_t *payload)
{
	ip *ret 	= (ip *) malloc(sizeof(ip));

	ret->type  	= (payload[0] & 0xF0) >> 4;
        ret->ihl   	= payload[0] & 0x0F;	
	ret->tos	= payload[1];

	ret->tot_lenght = from8to16(payload[2], payload[3]);
	ret->id         = from8to16(payload[4], payload[5]);

        uint16_t itlfrag   = from8to16(payload[6], payload[7]);
	uint8_t flag	= from16to8(itlfrag); // Top preserved

	// 0100 0000 0000 0000
	// 0100 0000
	ret->MF		= flag & 0x20;
        ret->offset	= itlfrag & 0x1FFF;

	ret->ttl	= payload[8];
        ret->protocol   = payload[9];
	ret->checksum	= from8to16(payload[10], payload[11]);

	ret->from  	= from16to32(from8to16(payload[12], payload[13]), from8to16(payload[14], payload[15]));
        ret->to	  	= from16to32(from8to16(payload[16], payload[17]), from8to16(payload[18], payload[19]));
	
	return ret;
}

uint8_t from16to8(uint16_t a)
{
	uint16_t ret = a >> 8;
	return (uint8_t) ret;
}

uint16_t from8to16(uint8_t a, uint8_t b)
{
        uint16_t ret = ((uint16_t) a << 8) | b;
        return ret;
}

uint32_t from16to32(uint16_t a, uint16_t b)
{
        uint32_t ret = (a << 16) | b;
        return ret;
}
    
