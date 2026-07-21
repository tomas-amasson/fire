#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#define MTU	1500


// Flags
#define FRAG 		0x1

#pragma pack(1)

// RET values

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


// Global

pthread_mutex_t hash_rw = PTHREAD_MUTEX_INITIALIZER;
hash *fr_hash 	= NULL;

queue *tr_queue	= NULL;
pthread_mutex_t q_write = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t	wake	= PTHREAD_COND_INITIALIZER;




int main(int argc, char *argv[])
{
	uint32_t ret;

	uint16_t done;
	uint16_t sum;

	uint16_t flags;
	udp_header *header;





	// Thread Control
	pthread_t tid[NTHREADS];
	tr_queue = queue_init(MTU); // Valor aleatório	

	for (int i = 0; i < NTHREADS; i++)
	{
		pthread_create(&tid[i], NULL, (void *) start_worker, (void *) tr_queue);
	}


	// Fragmentation Control
	fr_hash = hash_init(MTU);

	// RECEIVE
	int fd = set_TUN();

	// Configure TUN
	system("sudo ip link set dev tun0 up");
	system("sudo ip route add 10.0.0.0/24 dev tun0");


	while (1) //SIGNAL CTRL + C
	{	
		int16_t up = read(fd, (void *) off_enq(tr_queue), MTU);
		if (!up)
			continue;

		pthread_mutex_lock(&q_write);
		set_tail(tr_queue);

		printf("Thread activated.\n");
		fflush(0);

		pthread_cond_signal(&wake);
		pthread_mutex_unlock(&q_write);
	}	



	// RULES


	// RESULT
	return 0;
}

uint32_t set_TUN()
{
	uint32_t fd = open("/dev/net/tun", O_RDWR);
	if (fd == -1)
	{
		perror("open error.\n");
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
	uint8_t *copy;
	uint8_t ret;

	while (1)
	{
		pthread_mutex_lock(&q_write);
		while (q->size == 0)
		{
			pthread_cond_wait(&wake, &q_write);
		}

		printf("%d is active.\n", (int ) pthread_self());
		fflush(0);

		uint8_t * package = dequeue(q);
		if (package == NULL)
		{
			printf("DISCARTED.\n");
			continue;
		}

		*copy = *package; // Prevenir corrupção (caso o input seja muito maior que o output)

		pthread_mutex_unlock(&q_write);

		ret = validate_package_thread(copy);
		if (ret)
		{
			printf("Package discarted.\n");
		}
	}
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
	uint8_t *package_start = payload + (ipp->ihl * 4);

		

	if (ipp->type == 4)
	{
		if (ipv4_check(payload))
		{
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

	}
	else if (ipp->protocol == 6)
	{
		ret = tcp_check();
	}



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
	unsigned int flags	= package->flags;
	uint16_t lenght		= header->lenght;

	int ret;

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

	for (int i = 0; i < lenght; i++)
	{
		sum += msg[i];
	}

	return sum;
}

void udp_package_loss()
{
	return ;
}

