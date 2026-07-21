#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main() {
    // 1. Configurações do destino
    char *ip_destino = "10.0.0.5";
    int porta_destino = 8080;
    char *mensagem = "ola, teste";
    
    int sock;
    struct sockaddr_in destino;

    // 2. Criação do Socket
    // AF_INET = Família IPv4 (Garante que o primeiro byte será 0x45)
    // SOCK_DGRAM = Datagrama UDP (Garante que o campo protocolo será 17)
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Erro ao criar o socket");
        return 1;
    }

    // 3. Zera a estrutura e configura os dados do destino
    memset(&destino, 0, sizeof(destino));
    destino.sin_family = AF_INET;
    
    // htons = Host TO Network Short (Lembra da inversão do Endianness? 
    // Isso garante que a porta seja enviada na ordem certa para a rede)
    destino.sin_port = htons(porta_destino);
    
    // Converte a string do IP ("10.0.0.5") para o formato binário de 32 bits
    if (inet_pton(AF_INET, ip_destino, &destino.sin_addr) <= 0) {
        perror("Erro ao converter o endereço IP");
        close(sock);
        return 1;
    }

    printf("Enviando mensagem para %s:%d...\n", ip_destino, porta_destino);

    // 4. Dispara o pacote para o Kernel do Linux
    int bytes_enviados = sendto(sock, mensagem, strlen(mensagem), 0,
                                (struct sockaddr *)&destino, sizeof(destino));

    if (bytes_enviados < 0) {
        perror("Erro ao enviar o pacote");
    } else {
        printf("Sucesso! %d bytes de dados entregues ao Kernel.\n", bytes_enviados);
    }

    // 5. Fecha o socket
    close(sock);
    return 0;
}
