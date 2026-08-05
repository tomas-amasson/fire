#ifndef TCP_H 
#define TCP_H

#pragma pack(1)

#include <stdint.h>
#include <string.h>
#include "../ip/ip.h"

typedef struct {
	uint16_t source;
	uint16_t destin;
	uint32_t seqnum;
	uint32_t acknum;

	uint16_t offset : 4, reserved : 3, flags: 9;
	uint16_t winsiz;
	uint16_t checksum;
	uint16_t urgptr;

	uint8_t *options;
} tcphdr;

typedef struct {
	tcphdr *header;	
	uint8_t *msg;
} tcp;

tcp * set_tcp(uint8_t *payload);
uint8_t tcp_check(tcp *pack);
void tcp_connect(tcp *pack);
void tcp_free(tcp *pack);


#endif
