#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <stdint.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/epoll.h>

#include <pthread.h>
#include "stack/stack.h"
#include "queue/queue.h"
#include "hash/hash.h"
#include "ip/ip.h"
#include "udp/udp.h"
#include "tcp/tcp.h"
#include "trie/trie.h"

#pragma pack(1)

#define MTU	1500
#define STATELESS "statrules.bin"
#define SOCKPATH  "rules.sock"

// RET values

#define MEMERR		1
#define SYSERR		2


#define CORRUPT		3
#define FRAGMENT	2

#define NTHREADS	5
#define THREADRL	1
#define THREADPK	NTHREADS - THREADRL


typedef struct rules{
	uint8_t lim;
	uint8_t ways;
	uint32_t data;
} rules;


uint32_t set_TUN();
void load_stateless();
uint32_t setup_socket();
void save_rules(rules **newr, uint32_t size);

uint8_t  validate_package_thread(uint8_t *payload, void **pack);
void * start_worker(void *arg);
void * start_worker_rule(void *arg);


uint8_t ipv4_check(uint8_t *payload);
uint8_t check_stateless(void *pack, uint8_t protocol);

void tcp_package_loss();
void udp_package_loss();
void package_denied();

void see_package(uint8_t *msg);
void decode(udp *pack);
void turn_end(int32_t sig);
uint8_t nodata(uint8_t *head);

// Global

/* MUTEXES */
pthread_mutex_t hash_rw = PTHREAD_MUTEX_INITIALIZER; 
pthread_mutex_t q_write = PTHREAD_MUTEX_INITIALIZER;

pthread_cond_t	wake	= PTHREAD_COND_INITIALIZER;
pthread_cond_t 	rwake	= PTHREAD_COND_INITIALIZER;

pthread_cond_t mwait 	= PTHREAD_COND_INITIALIZER;
queue *tr_queue	= NULL;

/* FRAG */
hash *fr_hash 	= NULL;

/* RULES */
trtree * port_rules 	= NULL;
trtree * ip_rules	= NULL;
rules **new_rules	= NULL;
uint32_t rules_sz	= 0;

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
		printf("Failed to allocate: queue.\n");
		return MEMERR;
	}
					 

	uint32_t k;
	for (k = 0; k < THREADPK; k++)
	{
		if (pthread_create(&tid[k], NULL, (void *) start_worker, (void *) tr_queue))
		{
			printf("thread initialization failed: worker\nMay cause errors.\n");
		}
	}

	for (uint32_t i = 0; i < THREADRL; i++, k++)
	{
		if (pthread_create(&tid[k], NULL, (void *)start_worker_rule, (void *)tr_queue))
		{
			printf("thread initialization failed: rules\nMay cause errors.\n");
		}
	}


	// Fragmentation Control
	fr_hash = hash_init(65536); // 16 bit max (IP ID)
	if (!fr_hash)
	{
		printf("Failed to allocate: hash.\n");
		return MEMERR;
	}

	// Load Rules 
	port_rules 	= trtree_init();
	ip_rules	= trtree_init();

	new_rules	= (rules **) malloc(sizeof(struct rules *));
	memset(new_rules, 0, sizeof(struct rules *));

	load_stateless();

	uint32_t sockfd = setup_socket();
	if (!sockfd)
	{
		printf("System error: socket create\n");
		return SYSERR;
	}


	// RECEIVE
	uint32_t tunfd = set_TUN();
	if (tunfd < 0)
	{
		printf("System error: TUN create\n");
		return SYSERR;
	}

	// Configure TUN
	err = system("sudo ip link set dev tun0 up");
	if (err == 127 || err < 0)
	{
		printf("System error: configure TUN\n");
		return SYSERR;
	}

	err = system("sudo ip route add 10.0.0.0/24 dev tun0");
	if (err == 127 || err < 0)
	{
		printf("System error: configure TUN\n");
		return SYSERR;
	}

	// Configure epoll

	uint32_t epollfd = epoll_create(1);
	if (epollfd < 0)
	{
		printf("System error: epoll create\n");
		return SYSERR;
	}

	struct epoll_event event;

	event.events = EPOLLIN;
	event.data.fd = tunfd;	
	epoll_ctl(epollfd, EPOLL_CTL_ADD, tunfd, &event);

	event.data.fd = sockfd;
	epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &event);

	struct epoll_event event_list[4];
	
	pthread_mutex_lock(&q_write);
	uint8_t *addr = off_enq(tr_queue);
	pthread_mutex_unlock(&q_write);

	while (!end) // kill 10
	{

		int16_t nevents = epoll_wait(epollfd, event_list, 4, -1);
		for (uint8_t i = 0; i < nevents; i++)
		{
			int16_t up = read(event_list[i].data.fd, (void *) addr, MTU);

			printf("%02x\n", *addr); // DEBUG
			if (up < 0 || (nodata(addr) && event_list[i].data.fd != sockfd))
			{
				continue;
			}

			pthread_mutex_lock(&q_write);
			set_tail(tr_queue);

			if (event_list[i].data.fd == sockfd)
			{
				pthread_cond_signal(&rwake);
			}
			else
			{
				pthread_cond_signal(&wake);
			}
			pthread_mutex_unlock(&q_write);

			// New addr
			pthread_mutex_lock(&q_write);	
			addr = off_enq(tr_queue);
			if (!addr)
			{
				// queue maximum capacity
				while (tr_queue->size == tr_queue->max - 1)
				{
					pthread_cond_wait(&mwait, &q_write);
				}
				pthread_mutex_unlock(&q_write);
			}
			pthread_mutex_unlock(&q_write);
		}
	}	



	// RULES
	
	// Stateless
		// IP
		// Ports
		// Protocol
		// Flags
		
		

	// RESULT
	



	printf("EXITING.\n");

	// Kill threads
	for (uint32_t i = 0; i < THREADPK; i++)
	{
		pthread_mutex_lock(&q_write);
		pthread_cond_signal(&wake);
		pthread_mutex_unlock(&q_write);
	}

	for (uint32_t i = 0; i < THREADRL; i++)
	{
		pthread_mutex_lock(&q_write);
		pthread_cond_signal(&rwake);
		pthread_mutex_unlock(&q_write);
	}

	// Wait for threads to exit
	for (uint32_t i = 0; i < NTHREADS; i++)
	{
		pthread_join(tid[i], (void **) &ret);
	}
	
	// Save applied rules
	save_rules(new_rules, rules_sz);
	for (uint32_t i = 0; i < rules_sz; i++)
	{
		free(new_rules[i]);
	}
	free(new_rules);

	// Cleanup
	free_queue(tr_queue);
	free_hash(fr_hash);	

	tr_free(ip_rules->root);
	free(ip_rules);

	tr_free(port_rules->root);
	free(port_rules);

	close(epollfd);
	close(tunfd);
	close(sockfd);

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

void *start_worker_rule(void *arg)
{
	queue *q = arg;
	uint8_t *copy = (uint8_t *) calloc(sizeof(rules) + 1, sizeof(uint8_t));

	while (!end)
	{
		pthread_mutex_lock(&q_write);
		while (q->size == 0 && !end)
		{
			pthread_cond_wait(&rwake, &q_write);
		}

		if (end)
		{
			pthread_mutex_unlock(&q_write);
			break;
		}
		
		uint8_t *package = dequeue(q);

		if (!package)
		{
			pthread_mutex_unlock(&q_write);
			continue ;
		}

		memcpy(copy, package, sizeof(rules));
		pthread_mutex_unlock(&q_write);

		rules *nr = (rules*) (copy + 1);
		printf("lim: %hhd, ways: %hhd, data: %d\n", nr->lim, nr->ways, nr->data);

		// Action
		if (copy[0])
		{
			if (!nr->lim)
			{
				tr_remove(port_rules, nr->data, 16);
			}
			else
			{
				tr_remove(ip_rules, nr->data, nr->lim);
			}
		}
		else
		{
			// Prevents data corruption
			rules *newr = (rules *) malloc(sizeof(struct rules)); 
			memcpy(newr, nr, sizeof(struct rules));

			new_rules[rules_sz] = newr;
			rules_sz++;
			new_rules = (rules **) realloc(new_rules, sizeof(struct rules *) * rules_sz);

			if (!nr->lim)
			{
				if (tr_insert(port_rules, nr->data, 16, nr->ways))
				{
					printf("RULE ADD FAILED.\n");
					continue ;
				}
				else
				{
					printf("NEW PORT RULE: %d\n", nr->data);
				}
			}
			else
			{
				if (tr_insert(ip_rules, nr->data, nr->lim, nr->ways))
				{
					printf("RULE ADD FAILED.\n");
					continue ;
				}
				else
				{
					printf("NEW IP RULE: ");
					uint8_t it = nr->lim >> 3;
					for (; it; it--)
					{
						if (it != 1)
						{
							printf("%hhd.",  (nr->data >> (32 - it)));
						}
						else
						{
							printf("%hhd %b\n", nr->data, nr->data);
						}
					}
				}
			}
		}
	}

	free(copy);
	pthread_exit(NULL);
}

void *start_worker(void *arg)
{
	queue *q = arg;
	uint8_t *copy = (uint8_t *) calloc(MTU, sizeof(uint8_t));
	uint8_t ret = 0;
	void *pack = NULL;

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

		pack = NULL;
		ret = validate_package_thread(copy, &pack);
		if (ret == 0)
		{
			// Mais coisas
			see_package(copy); // DEBUG
	

			if (check_stateless(pack, 17))
			{
				printf("PACKAGE DENIED.\n");
				package_denied();
			}
			else
			{
				printf("PACKAGE ACCEPTED.\n");
			}
			continue ;
		}
		if (ret == 1)
		{
			printf("Package Protocol not supported.\n");
			free(pack);
		}
		free(pack);
		
	}

	if (pack != NULL)
	{
		free(pack);
	}
	free(copy);
	pthread_exit(NULL);
}




/* Thread Funcion */
uint8_t validate_package_thread(uint8_t *payload, void **pack)
{

	uint8_t last = 0;
	uint8_t ret = 1;
	hashnode *target;

	ip *ipp = ip_init(payload);
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
			printf("FRAGMENT\n"); //DEBUG
			return FRAGMENT;
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
		*pack = set_udp(package_start);
		if (!*pack)
		{
			return CORRUPT;
		}

		ret = udp_check(*pack, ipp->from, ipp->to);
		decode(*pack); // DEBUG
	}
	else if (ipp->protocol == 6)
	{
		tcp *pack;
		ret = tcp_check(pack);
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

	uint16_t add = (uint16_t)(sum >> 16);
	while (add)
	{
		sum = sum & 0xFFFF;
		sum += add;
		add = (uint16_t)(sum >> 16);

	}

	sum = ~(sum) & 0xFFFF;
	return (!sum) ? 0: 1;
}




void udp_package_loss()
{
	return ;
}

void tcp_package_loss()
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



uint8_t check_stateless(void *pack, uint8_t protocol)
{
	trtree *tree = port_rules;

	if (protocol == 6)
	{
		tcp *spec = (tcp *) pack;
		tree = ip_rules;
		return blocked(tree, spec->header->destin, 32, IN) || blocked(tree, spec->header->source, 32, OUT);

	}
	else if (protocol == 17)
	{
		udp *spec = (udp *) pack;
		printf("PORT: %hd\n", spec->header->destin); // DEBUG
		return blocked(tree, spec->header->destin, 32, IN) || blocked(tree, spec->header->source, 32, OUT);
	}

	return 1;

}

void load_stateless()
{
	uint32_t fd = open(STATELESS, O_RDONLY);
	if (fd == -1)
	{
		perror("Read error.\n");
		return ;
	}

	rules fdata;
	while (read(fd, &fdata, sizeof(struct rules)))
	{

		if (!fdata.lim)
		{
			tr_insert(port_rules, fdata.data, 16, fdata.ways);
		}
		else
		{
			tr_insert(ip_rules, fdata.data, fdata.lim, fdata.ways);
		}
	}
	close(fd);

	return ;
}

uint32_t setup_socket()
{

	uint32_t sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		return 0;
	}

	unlink(SOCKPATH);

	struct sockaddr_un addr;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SOCKPATH, sizeof(addr.sun_path));

	socklen_t lenght = sizeof(addr);

	if (bind(sockfd, (struct sockaddr *) &addr, lenght))
	{
		return 0;
	}

	return sockfd;	
}


uint8_t write_statrules(rules fpack)
{
	uint32_t fd = open(STATELESS, O_APPEND);
	if (fd == -1)
	{
		return 1;
	}

	return 0;
}

void package_denied()
{
	return ;
}

void decode(udp *pack)
{
	for (uint32_t i = 0; i < pack->header->lenght; i++)
	{
		printf("%c", pack->msg[i]);
	}	
	printf("\n");
	fflush(0);
}

void save_rules(rules **newr, uint32_t size)
{
	uint32_t rulesfd = open(STATELESS, O_WRONLY | O_APPEND);
	for (uint32_t i = 0; i < size; i++)
	{	
		if (write(rulesfd, (void *)(*newr), sizeof(struct rules)) == -1)
		{
			printf("Rules couldn't be saved.\n");
		}
	}
	close(rulesfd);

	return ;
}
