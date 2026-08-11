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

#define INVALID		3
#define FRAGMENT	2
#define CORRUPT		1
#define ACCEPTED	0

#define NTHREADS	5
#define THREADRL	1
#define THREADPK	NTHREADS - THREADRL
#define RULETYPE	2

typedef struct rules{
	uint8_t op;
	uint8_t lim;
	uint8_t ways;
	uint32_t data;
} rules;


uint32_t set_TUN();
void load_stateless();
uint32_t setup_socket();
uint32_t setup_exit();
void save_rules();

uint8_t  validate_package_thread(uint8_t *payload);
void * start_worker(void *arg);
void * start_worker_rule(void *arg);


uint8_t check_stateless(void *pack, uint8_t protocol);

void tcp_package_loss();
void package_denied();
void send_ahead(ip *pack);

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
	save_rules();

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
	uint8_t *copy = (uint8_t *) calloc(sizeof(rules), sizeof(uint8_t));

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

		rules *nr = (rules*) (copy);
		printf("lim: %hhd, ways: %hhd, data: %d\n", nr->lim, nr->ways, nr->data); // DEBUG

		// Action
		if (nr->op)
		{
			if (!nr->lim)
			{
				tr_remove(port_rules, nr->data, 16, nr->ways, 16);
			}
			else
			{
				tr_remove(ip_rules, nr->data, nr->lim, nr->ways, 32);
			}
		}
		else
		{

			if (!nr->lim)
			{
				if (tr_insert(port_rules, nr->data, 16, nr->ways, 16))
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
				if (tr_insert(ip_rules, nr->data, nr->lim, nr->ways, 32))
				{
					printf("RULE ADD FAILED.\n");
					continue ;
				}
				else
				{
					printf("NEW IP RULE: %hhd.%hhd.%hhd.%hhd/%hd (%b)\n", nr->data >> 24, nr->data >> 16, nr->data >> 8, nr->data, nr->lim, nr->data);
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
		if (ret == ACCEPTED)
		{
			printf("PACKAGE ACCEPTED.\n");
		}
		else if (ret == INVALID)
		{
			printf("INVALID PROTOCOL.\n");
		}
		else if (ret == CORRUPT)
		{
			printf("PACKAGE DENIED.\n");
			// package_denied();
			// tcp_close_connection();
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
	hashnode *target;

	ip *ipp = ip_init(payload);
	uint8_t *package_start = payload + (ipp->ihl * 4);
	void *pack; // Package behind IP protocol
	uint32_t realsz = ipp->tot_lenght - (ipp->ihl * 4);

	// IP validation
	if (ipp->type == 4)
	{
		if (ipv4_check(payload) || check_stateless((void *) ipp, 0))
		{
			free(ipp);
			return CORRUPT;
		}
	}
	else
	{
		free(ipp);
		return INVALID;
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

		// Missing at least one package
		if (last)
		{
			package_start = hash_obtain_package(target);
			realsz = target->expected;
		}
		else
		{
			free(ipp);
			return FRAGMENT;
		}
	}
	
	// Package Protocol Validation
	if (ipp->protocol == 17) /* UDP */
	{
		pack = (udp *) set_udp(package_start);
		if (!pack)
		{
			free(ipp);
			free(package_start);
			return CORRUPT;
		}

		ret = udp_check(pack, ipp->from, ipp->to, realsz);
	}
	else if (ipp->protocol == 6) /* TCP */
	{
		pack = (tcp *) set_tcp(package_start);
		if (!pack)
		{
			free(ipp);
			free(package_start);
			return CORRUPT;
		}

		ret = tcp_check(pack);
	}

	// Stateless Rules Check
	if (check_stateless(pack, ipp->protocol))
	{
		free(ipp);
		udp_free(pack);
		free(package_start);
		return CORRUPT;
	}
	//decode(*pack); // DEBUG

	free(ipp);
	udp_free(pack);
	free(package_start);
	return ret;	
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
	if (!protocol)
	{
		ip *spec = (ip *) pack;

		printf("%b -> %b\n", spec->from, spec->to);
		tree = ip_rules;
		return blocked(tree, spec->to, 32, IN) || blocked(tree, spec->from, 32, OUT);
	}
	else if (protocol == 6)
	{
		tcp *spec = (tcp *) pack;
		tree = ip_rules;
		return blocked(tree, spec->header->destin, 32, IN) || blocked(tree, spec->header->source, 32, OUT);

	}
	else if (protocol == 17)
	{
		udp *spec = (udp *) pack;
		return blocked(tree, spec->header->destin, 16, IN) || blocked(tree, spec->header->source, 16, OUT);
	}

	return 1;

}

void load_stateless()
{
	uint8_t ret;

	uint32_t fd = open(STATELESS, O_RDONLY);
	if (fd == -1)
	{
		perror("Read error.\n");
		return ;
	}

	rules fdata;
	while (read(fd, &fdata, sizeof(struct rules)))
	{
		if (fdata.op)
		{
			printf("%d - %b not blocked\n", fdata.data, fdata.data);
			continue;
		}

		printf("%d - %b : %hhd -> %hd added\n", fdata.data, fdata.data, fdata.ways, fdata.lim);
		if (!fdata.lim)
		{
			ret = tr_insert(port_rules, fdata.data, 16, fdata.ways, 16);
		}
		else
		{
			ret = tr_insert(ip_rules, fdata.data, fdata.lim, fdata.ways, 32);
		}

		if (ret)
		{
			printf("Error while inserting new rule.\n");
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

void save_rules()
{
	uint32_t rulesfd = open(STATELESS, O_WRONLY | O_CREAT | O_TRUNC, 0600);

	trtree *ptr;
	rules buf;

	uint32_t size = ((port_rules->size > ip_rules->size) ? port_rules->size : ip_rules->size);

	// Port Rules

	trnode ** anodes = (trnode **) malloc(sizeof(trnode *) * size);
	uint8_t deep;

	for (uint8_t l = 0; l < RULETYPE; l++)
	{
		switch(l)
		{
			case 0:
				deep = 16;
				ptr = port_rules;
				break;
			case 1:
				deep = 32;
				ptr = ip_rules;
				break;
		}


		uint32_t *rulesl = get_nodes(ptr, anodes, deep);

		for (uint32_t i = 0; i < ptr->size; i++)
		{	
			if (!rulesl[i] && !anodes[i])
			{
				continue;
			}

			buf.op	 = 0;
			buf.lim	 = l? anodes[i]->deep: 0;
			buf.ways = anodes[i]->ways;
			buf.data = rulesl[i];

			if (write(rulesfd, &buf, sizeof(struct rules)) == -1)
			{
				printf("Rules couldn't be saved.\n");
			}
			else
			{
				printf("Rule: %d:%hhd -> %hd saved\n", buf.data, buf.op, buf.lim); // DEBUG
			}
		}

		free(rulesl);
	}

	free(anodes);
	close(rulesfd);

	return ;
}

uint32_t setup_exit() // PARA INTERIOR SÓ ESCREVER EM TUNFD
{
	uint32_t exitfd = socket(AF_UNIX, SOCK_RAW, 0);
	if (exitfd < 0)
	{
		return 0;
	}
	
	struct sockaddr_un exaddr;

	exaddr.sun_family = AF_UNIX;
	
	if (bind(exitfd, (struct sockaddr *) &exaddr, sizeof(exaddr)))
	{
	}
	
	return exitfd;
}

void send_ahead(ip *pack)
{
	
	if (pack->to & 0xA000000) // Mesmo ip da máquina = enviado para uma port
	{
				
	}

	else // Ip de fora, deve ser enviado para outra máquina
	{
	}
	
	return ;
}
