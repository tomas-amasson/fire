#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <stdint.h>

#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <unistd.h>

#include <pthread.h>
#include "stack/stack.h"
#include "queue/queue.h"
#include "hash/hash.h"
#include "ip/ip.h"

#pragma pack(1)

#define MTU	1500


// RET values

#define MEMERR		1
#define SYSERR		2


#define CORRUPT		1
#define ACCEPT		0

#define NTHREADS	4


typedef struct {
	uint16_t source;
	uint16_t destin;
	uint16_t lenght;
	uint16_t checksum; 
} udp_header;

typedef struct {
	udp_header *header;	
	uint8_t *msg; 
	unsigned int flags : 1;
} udp;

uint32_t set_TUN();
uint8_t  validate_package_thread(uint8_t *payload);
void * start_worker(void *arg);


uint8_t ipv4_check(uint8_t *payload);
uint8_t tcp_check();


udp *set_udp(uint8_t *payload);
uint8_t udp_check(udp *package);
uint16_t udp_checksum(uint16_t lenght, uint8_t *msg);
void udp_package_loss();
void udp_free(udp *pack);

void see_package(uint8_t *msg);
void turn_end(int32_t sig);
uint8_t nodata(uint8_t *head);

// Global

pthread_mutex_t hash_rw = PTHREAD_MUTEX_INITIALIZER;
hash *fr_hash 	= NULL;

queue *tr_queue	= NULL;
pthread_mutex_t q_write = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t	wake	= PTHREAD_COND_INITIALIZER;
pthread_cond_t mwait 	= PTHREAD_COND_INITIALIZER;

uint8_t end;


int main(int argc, char *argv[])
{
	uint32_t ret;
	uint8_t  err;

	
	//Package Volume Control
	end = 0;
	struct sigaction sig;
	sig.sa_handler = turn_end;
	sigaction(SIGUSR1, &sig, NULL);

	// Thread Control
	pthread_t tid[NTHREADS];
	tr_queue = queue_init(200, MTU); // Valor aleatório	
	if (!tr_queue)
	{
		printf("Failed to allocate queue.\n");
		return MEMERR;
	}
					 

	for (uint32_t i = 0; i < NTHREADS; i++)
	{
		pthread_create(&tid[i], NULL, (void *) start_worker, (void *) tr_queue);
	}


	// Fragmentation Control
	fr_hash = hash_init(65536); // 16 bit max (IP ID)
	if (!fr_hash)
	{
		printf("Failed to allocate hash.\n");
		return MEMERR;
	}

	// RECEIVE
	int fd = set_TUN();
	if (fd < 0)
	{
		return SYSERR;
	}

	// Configure TUN
	err = system("sudo ip link set dev tun0 up");
	if (err == 127 || err < 0)
	{
		printf("System error.\n");
		return SYSERR;
	}

	err = system("sudo ip route add 10.0.0.0/24 dev tun0");
	if (err == 127 || err < 0)
	{
		printf("System error.\n");
		return SYSERR;
	}


	while (!end) // kill 10
	{
		pthread_mutex_lock(&q_write);	
		uint8_t *addr = off_enq(tr_queue);
		if (!addr)
		{
			// queue maximum capacity
			while (tr_queue->size == tr_queue->max - 1)
			{
				pthread_cond_wait(&mwait, &q_write);
			}
			pthread_mutex_unlock(&q_write);
			continue;
		}
		pthread_mutex_unlock(&q_write);

		int16_t up = read(fd, (void *) addr, MTU);

		printf("%02x\n", *addr);
		if (up < 0 || nodata(addr))
		{
			continue;
		}

		pthread_mutex_lock(&q_write);
		set_tail(tr_queue);

		pthread_cond_signal(&wake);
		pthread_mutex_unlock(&q_write);
	}	

	printf("EXITING.\n");

	// Kill threads
	for (uint32_t i = 0; i < NTHREADS; i++)
	{
		pthread_mutex_lock(&q_write);
		pthread_cond_signal(&wake);
		pthread_mutex_unlock(&q_write);
	}

	// Wait for threads to exit
	for (uint32_t i = 0; i < NTHREADS; i++)
	{
		pthread_join(tid[i], (void **) &ret);
	}

	// RULES


	// RESULT
	

	// Cleanup
	free_queue(tr_queue);
	free_hash(fr_hash);	


	printf("EXITED.\n");
	return 0;
}

uint32_t set_TUN()
{
	uint32_t fd = open("/dev/net/tun", O_RDWR);
	if (fd == -1)
	{
		perror("Open error.\n");
		return -1;
	}

	struct ifreq ifr;

	memset(&ifr, 0, sizeof(struct ifreq));

	strncpy(ifr.ifr_name, "tun0", IFNAMSIZ);
	
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	uint32_t err = ioctl(fd, TUNSETIFF, (void *) &ifr);

	if (err < 0)
	{
		perror("ioctl error.\n");
		close(fd);
		return -1;
	}

	return fd;
}

void *start_worker(void *arg)
{
	queue *q = arg;
	uint8_t *copy = (uint8_t *) calloc(MTU, sizeof(uint8_t));
	uint8_t ret;

	while (!end)
	{
		pthread_mutex_lock(&q_write);
		while (q->size == 0 && !end)
		{
			pthread_cond_wait(&wake, &q_write);
		}

		if (end)
		{ 
			pthread_mutex_unlock(&q_write);
			break;
		}

		uint8_t * package = dequeue(q);
		if (package == NULL)
		{
			printf("DISCARTED.\n");

			pthread_mutex_unlock(&q_write);
			continue;
		}

		memcpy(copy, package, MTU); // Prevenir corrupção (caso o input seja muito maior que o output)

		pthread_mutex_unlock(&q_write);

		ret = validate_package_thread(copy);
		if (ret == 0)
		{
			// Mais coisas
			see_package(copy);

			continue ;
		}
	}

	free(copy);
	pthread_exit(NULL);
}




/* Thread Funcion */
uint8_t validate_package_thread(uint8_t *payload)
{

	uint8_t last = 0;
	uint8_t ret;
	udp *pack;
	hashnode *target;

	ip *ipp = ip_init(payload);
	printf("ID = %d\n", ipp->id);
	uint8_t *package_start = payload + (ipp->ihl * 4);


	if (ipp->type == 4)
	{
		if (ipv4_check(payload))
		{
			free(ipp);
			return CORRUPT;
		}
	}

	// Houve fragmentação
	if (ipp->MF || ipp->offset > 0)
	{
		pthread_mutex_lock(&hash_rw);
		target = search_hn(fr_hash, ipp->id, ipp->from, ipp->to, ipp->protocol);
		
		if (target == NULL)
		{
			target = hashn_init(ipp->id, ipp->from, ipp->to, ipp->protocol);
			add_hashn(fr_hash, target);

		}

		fragment *fr = frag_init(ipp->offset, package_start, (uint8_t) ipp->MF, ipp->tot_lenght - (ipp->ihl * 4));
		last = add_frag(target, fr);
		
		pthread_mutex_unlock(&hash_rw);

		// Caso não seja o último fragmento larga a mão
		if (!last)
		{
			free(ipp);
			return ACCEPT;
		}
	}
	
	if (last)
	{
		// Desfragmentar
		package_start = hash_obtain_package(target);

	}

	// Validar Protocolo

	if (ipp->protocol == 17) /* UDP */
	{
		pack = set_udp(package_start);
		ret = udp_check(pack);

		udp_free(pack);
	}
	else if (ipp->protocol == 6)
	{
		ret = tcp_check();
	}


	free(ipp);
	return ret;	
}

uint8_t ipv4_check(uint8_t *payload)
{
	uint32_t sum = 0;

	for (uint8_t i = 0; i < 20; i += 2)
	{
		sum += from8to16(payload[i], payload[i + 1]);
	}

	sum += (sum / 65535) - 1;
	sum = ~(sum);
	sum = sum & 0xFFFF;

	return (!sum) ? 0: 1;
}

uint8_t tcp_check()
{
	return 0;
}

udp * set_udp(uint8_t *payload)
{
	udp *ret = (udp *) malloc(sizeof(udp));

	ret->header = (udp_header *) malloc(sizeof(udp_header));

	//Campos de 2 bytes   Campo de 1 byte
	ret->header->source = from8to16(payload[0], payload[1]);
	ret->header->destin = from8to16(payload[2], payload[3]);
	ret->header->lenght = from8to16(payload[4], payload[5]);
	ret->header->checksum = from8to16(payload[6], payload[7]);

	ret->msg = &payload[8];
	return ret;
}

uint8_t udp_check(udp *package)
{
	udp_header *header 	= package->header;
	uint8_t *msg		= package->msg;
	uint16_t lenght		= header->lenght;

	uint32_t ret;

	ret = ~(udp_checksum(lenght, msg));
	if (ret != header->checksum)
	{
		return -1;
	}
	return 0;
}

uint16_t udp_checksum(uint16_t lenght, uint8_t *msg)
{
	uint16_t sum = 0;
	lenght = lenght > 1500 ? 1500 : lenght;

	for (uint32_t i = 0; i < lenght; i++)
	{
		sum += msg[i];
	}

	return sum;
}

void udp_package_loss()
{
	return ;
}


void see_package(uint8_t *msg)
{
	for (uint32_t i = 0; i < 100; i++)
	{
		printf("%02x", msg[i]);
	}
	printf("\n");
}


void turn_end(int32_t sig)
{
	end = 1;
	return ;
}

uint8_t nodata(uint8_t *head)
{

	uint8_t hsiz = head[0] & 0x0F;
	uint16_t len = hsiz? (head[2] << 8) | head[3]: 0;

	return len? 0: 1;
}

void udp_free(udp *pack)
{
	free(pack->header);
	free(pack);
	return ;
}
