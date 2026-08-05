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

typedef struct rules{
	uint8_t lim;
	uint8_t ways;
	uint32_t data;
} rules;


int32_t main(int argc, char *argv[])
{
	if (argc < 3)
	{
		printf("USAGE:\n./rule <type> <newrule>");
		return 0;
	}

	uint8_t type = atoi(argv[1]);

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
		
	rules data = {8, 0, 0x0a000001};

	socklen_t lenght = sizeof(destin);

	if (sendto(sockfd, (void *) &data, sizeof(data), 0, (struct sockaddr *) &destin, lenght) < 0)
	{
		printf("%s\n", strerror(errno));
		printf("PACKAGE NOT SENT.\n");
	}
	else
	{
		printf("PACKAGE SENT.\n");
	}

	close(sockfd);
	return 0;
}
