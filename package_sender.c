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
    char *mensagem = "O efeito estufa é um fenômeno natural, no qual os gases da atmosfera do planeta Terra retém o calor do Sol para manter a temperatura ideal para a vida. Esse efeito, porém, pode ser maléfico quando eles se acumulam em níveis excessivos e assim, causam o aquecimento global com consequências catastróficas. Tal calamidade persiste e ainda é ignorada, tanto pela dependência dos combustíveis fósseis, quanto pela dificuldade de implementação de fontes de energia renováveis. Primeiramente, a queima de derivados do petróleo é uma grande vilã, pois emite imensas quantidades de CO2, um dos gases do efeito estufa. Nesse contexto, depender dessa alternativa para mover transportes e ser fonte de energia agrava a situação, porém, apesar dos alertas e de acordo com o IPCC, nos últimos anos, tem sido cada vez mais usada. Isso evidencia a grande submissão das cadeias globais a esse método, o que se mostra um grande obstáculo para que o quadro atual seja visto com seriedade pelas autoridades e que sejam tomadas as medidas necessárias para sua reversão. Por outro lado, outras fontes de energia, como eólica e solar, que são tidas como substitutas eficazes para os combustíveis fósseis, ainda enfrentam grandes barreiras em sua implementação maciça. Segundo a revista Forbes, os custos elevados de investimento e infraestrutura e a necessidade de grandes espaços para construção de parques solares e eólicos, provocaram uma elevação expressiva no valor das tarifas energéticas, além de causar poluição visual e sonora nos ambientes. Fato esse, que afasta o engajamento das empresas de energia e da sociedade na causa. Portanto, para estimular essas empresas a investirem em novos projetos e fazer com que o problema discutido seja levado a sério pela sociedade, o governo federal deve subsidiá-las, para estimular o uso de energias renováveis, por meio do redirecionamento de verbas do Ministério de Minas e Energia, esse recurso seria usado para incentivar as empresas a desenvolverem parques de produção de energia limpa, bem como em campanhas educacionais, através de folhetos e mídias digitais, para informar a população sobre o aquecimento global. Assim, o Brasil faria sua parte para manter a temperatura do planeta estável.";
    
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
