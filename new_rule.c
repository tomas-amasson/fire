#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <errno.h>

#pragma pack(1)

#define SOCKPATH "rules.sock"

#define IN 	0
#define OUT 	1
#define BOTH	2

typedef struct rules{
	uint8_t op;
	uint8_t lim;
	uint8_t ways;
	uint32_t data;
} rules;


int32_t main(int argc, char *argv[])
{
	if (argc < 5)
	{
		printf("USAGE:\n./rule <op> <type> <newrule> <in/out>");
		return 0;
	}

	char *op	= argv[1];
	char *type 	= argv[2];
	char *block 	= argv[3];
	char *io	= argv[4];
	rules info;
	memset(&info, 0, sizeof(struct rules));

	if (!strcmp(op, "add") || !strcmp(op, "ADD"))
	{
		info.op = 0;
	}
	else if (!strcmp(op, "rem") || !strcmp(op, "REM"))
	{
		info.op = 1;
	}
	else
	{
		printf("<op> can be either ADD or REM\n");
	}

	if (!strcmp(io, "out") || !strcmp(io, "OUT"))
	{
		info.ways = OUT;
	}
	else if (!strcmp(io, "in") || !strcmp(io, "IN"))
	{
		info.ways = IN;
	}
	else if (!strcmp(io, "both") || !strcmp(io, "BOTH"))
	{
		info.ways = BOTH;
	}
	else
	{
		printf("<in/out> can be either IN or OUT or BOTH\n");
	}

	// IP
	if (!strcmp(type, "ip") || !strcmp(type, "IP"))
	{
		uint8_t i = 3;
		block = strtok(block, ".");
		info.data |= atoi(block) << 24;

		for (; i && block; i--)
		{
			block = strtok(NULL, ".");
			info.data |= atoi(block) << ((i - 1) * 8);
		}
		info.lim  = (3 - i) * 8;
	}
	else if (!strcmp(type, "port") || !strcmp(type, "PORT"))
	{
		info.data = atoi(block);
	}
	else
	{
		printf("<type> can be either IP or PORT\n");
		return 0;
	}



	// Send DGRAM
	uint32_t sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		return 1;
	}

	struct sockaddr_un destin;

	memset(&destin, 0, sizeof(destin));
	destin.sun_family = AF_UNIX;
	strncpy(destin.sun_path, SOCKPATH, sizeof(destin.sun_path));
		

	socklen_t lenght = sizeof(destin);

	if (sendto(sockfd, (void *) &info, sizeof(info), 0, (struct sockaddr *) &destin, lenght) < 0)
	{
		printf("%s\n", strerror(errno));
		printf("PACKAGE NOT SENT.\n");
	}
	else
	{
		printf("PACKAGE SENT.\n");
		printf("DATA: lim=%hhd, data=%d, ways=%d\n", info.lim, info.data, info.ways);
	}

	close(sockfd);
	return 0;
}
