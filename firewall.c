#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Flags
#define FRAG 		1

// RET values
#define ALTSUM		-1
#define FRAG_END 	0
#define FRAG_CONT 	1

typedef struct {
	uint16_t source;
	uint16_t destin;
	uint16_t lenght;
	uint16_t checksum; /* Opcional, já que não possui callback */
} udp_header;

typedef struct {
	udp_header header;	
	uint8_t *msg; /* Requer demultiplex*/
	unsigned int flags : 1;
} udp;

int tcp_check();
int udp_check(udp *package, uint16_t *done, uint16_t *sum);
int udp_checksum(uint16_t lenght, uint8_t *msg);


int main(int argc, char *argv[])
{
	int ret;
	uint16_t done;
	uint16_t sum;

	uint16_t flags;
	udp_header *header;


	// RECEIVE
	

	// PROTOCOL
	
	// UDP
	if (1)
	{
		uint8_t *msg 	= package->msg;

		// Não houve fragmentação relativa a esse pacote
		if (!(flags & FRAG))
		{
			*header = package->header;
			flags 	= package->flags;
			done 	= 0;
			sum	= 0;
		}
		else
		{
			// MTU limit
			if (header->lenght > 1500)
			{
				flags |= FRAG;
			}
		}

		ret = udp_check(package, &done, &sum);
		
		if (ret == ALTSUM)
		{
			udp_package_loss();
		}
		
		else if (ret == FRAG_END)
		{
			package->flags /= FRAG;
		}
	}

	// RULES


	// RESULT
	return 0;
}



int tcp_check()
{
	return 0;
}

int udp_check(udp *package, uint16_t *done, uint16_t *sum)
{
	udp_header *header 	= package->header;
	uint8_t *msg		= package->msg;
	unsigned int flags	= package->flags;
	uint16_t lenght		= header->lenght;

	int ret;

	// Permite fragmentação de pacotes maiores que a MTU permite
	if (flags & FRAG)
	{
		(*sum) 	+= udp_checksum(lenght - (*sum), msg);
		(*done) += 1500;

		// Fim do checksum
		if ((*done) >= lenght)
		{
			uint16_t checksum = ~(*done);

			if (checksum != header->checksum)
			{
				return -1;
			}

			return FRAG_END;
		}
		return FRAG_CONT;
	}

	// Sem fragmentação
	else
	{
		ret ~= udp_checksum(lenght, msg);
		if (ret != header->checksum)
		{
			return -1;
		}
	}
	return FRAG_END;
}

int udp_checksum(uint16_t lenght, uint8_t *msg)
{
	uint16_t sum = 0;
	lenght = lenght > 1500 ? 1500 : lenght;

	for (int i = 0; i < lenght; i++)
	{
		sum += msg[i];
	}

	return sum;
}
