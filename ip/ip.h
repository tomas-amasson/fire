#ifndef IP_H
#define IP_H

#include <stdint.h>
#include <stdlib.h>

#pragma pack(1)

typedef struct {
	uint8_t type;
	uint8_t ihl;
	uint8_t tos;
	uint16_t tot_lenght;
	uint16_t id;

	uint8_t ttl;
	uint8_t protocol;

	uint16_t offset;
	uint8_t  MF;

	uint16_t checksum;
	uint32_t from;
	uint32_t to;
} ip;

ip* ip_init(uint8_t *payload);

uint8_t from16to8(uint16_t a);
uint16_t from8to16(uint8_t a, uint8_t b);
uint32_t from16to32(uint16_t a, uint16_t b);
void fill8from32(uint8_t *arr, uint32_t b);
void fill8from16(uint8_t *arr, uint16_t b);

#endif
