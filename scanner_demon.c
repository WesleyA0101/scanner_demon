#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <pcap.h>
#include <netdb.h>

#define RED "\033[91m"
#define GREEN "\033[92m"
#define YELLLOW "\033[93m"
#define BLUE "\033[94m"
#define RESET "\033[0m"

void print_banner(){
    //Banner gerado na IA	
    printf("__________________¶________________¶\n");
    printf("_________________¶¶________________¶¶\n");
    printf("_______________¶¶¶__________________¶¶¶\n");
    printf("_____________¶¶¶¶____________________¶¶¶¶\n");
    printf("____________¶¶¶¶¶____________________¶¶¶¶¶\n");
    printf("___________¶¶¶¶¶______________________¶¶¶¶¶\n");
    printf("__________¶¶¶¶¶¶______________________¶¶¶¶¶¶\n");
    printf("__________¶¶¶¶¶¶¶__¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶__¶¶¶¶¶¶¶\n");
    printf("__________¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶\n");
    printf("___________¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶\n");
    printf("____________¶¶¶¶¶¶¶¶____¶¶¶¶¶¶____¶¶¶¶¶¶¶¶\n");
    printf("___¶________¶¶¶¶¶¶¶______¶¶¶¶______¶¶¶¶¶¶¶\n");
    printf("___¶_______¶¶¶¶¶¶¶¶___O_¶¶¶¶¶__O__¶¶¶¶¶¶¶¶\n");
    printf("__¶¶¶______¶¶¶¶¶¶¶¶¶____¶¶¶¶¶¶____¶¶¶¶¶¶¶¶¶\n");
    printf("__¶¶¶_____¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶\n");
    printf("_¶¶¶¶¶____¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶__¶¶\n");
    printf("_¶¶¶¶¶____¶¶¶__¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶__¶¶¶\n");
    printf("___¶¶_____¶¶¶__¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶__¶¶¶\n");
    printf("___¶¶______¶¶¶_____¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶_____¶¶\n");
    printf("____¶¶______¶¶________¶¶¶¶¶¶¶¶¶¶_______¶¶\n");
    printf("_____¶¶______¶¶¶_______________________¶\n");
    printf("_____¶¶________¶¶____¶¶¶¶¶¶¶¶¶¶¶______¶\n");
    printf("______¶¶________¶¶¶_____¶¶¶¶¶¶¶¶¶¶¶__¶\n");
    printf("_______¶¶__________¶¶¶_____¶¶¶¶¶¶¶¶¶¶\n");
    printf("_________¶¶___________¶¶¶¶¶__¶¶¶¶¶¶¶¶¶\n");
    printf("_____________________________¶¶¶¶¶¶¶¶¶¶\n");
    printf("______________________________¶¶¶¶¶¶¶¶¶\n");
    printf("_______________________________¶¶¶¶¶¶¶\n");
    printf("------------------Created by WesleyA0101\n");

}

void show_help(){
    printf("USO: ./scanner <IP> <Porta_inicial> <Porta_final\n\n>"
           GREEN  "Opções: " RESET "\n"
           "<IP> - Endereço IP do alvo.\n"   
	
   );

}

void generat_html_report(const char* results){
    FILE *f = fopen("Relatório.html", "w");
    if(f == NULL){
        perror("Erro ao abrir arquivo de relatório");
	exit(1);
    }

    time_t now = time(NULL);
    fprintf(f, "<html><body>");
    fprintf(f, "<h1>Relatório de escaneamento</h1>");
    fprintf(f, "<p>Data: %s</p>",  ctime(&now));
    fprintf(f, "<h2>Resultados</h2>");
    fprintf(f, "<pre>%s</pre>", results );
    fprintf(f, "</body></html>");
    fclose(f);

}

//Escanear portas
void *scan_port(void *args){
    struct{
         char *target_ip;
	     int port;
    } *data = (void *)args;

    struct sockaddr_in sa;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    char result[256];

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(data->target_ip);
    sa.sin_port = htons(data->port);

    if(connect(sock, (struct sockaddr*)&sa, sizeof(sa)) == 0){
        snprintf(result, sizeof(result), GREEN "[*] Porta %d está aberta" RESET, data->port);
	    printf("%s\n", result);
    
    }else{
        snprintf(result, sizeof(result), RED "[*] Porta %d está fechada" RESET, data->port);
	printf("%s\n", result);
    }
    close(sock);
    free(data);
    return NULL;
}

void port_scanner(char *target_ip, int start_port, int end_port){
    pthread_t threads[end_port - start_port + 1];
    for(int i = start_port; i <= end_port; i++){
        struct{
	    char *target_ip;
	    int port;
	} *args = malloc(sizeof(*args));
	args->target_ip = target_ip;
	args->port = i;

	pthread_create(&threads[i - start_port], NULL, scan_port, args);
    
    }
    for(int i = 0; i < end_port - start_port + 1; i++){
        pthread_join(threads[i], NULL);
    }


}

//Capturando os pacotes
void packet_sniffer(const char *interface){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if(handle == NULL){
        fprintf(stderr, "Erro ao abrir o dispositivo: %s", errbuf);
	return;
    }

    printf("Iniciando o sniffer na interface %s...\n", errbuf);
    FILE *output_file = fopen("Captured_packets.pcap", "wb");

    if(output_file == NULL){
        fprintf(stderr, "Erro ao criar arquivo de captura.\n");
	    pcap_close(handle);
	    return;
    }


    struct pcap_pkthdr header;
    const u_char*packet;

    while(1){
        packet = pcap_next(handle, &header);
	if(packet== NULL) continue;

	//Processa o pacote
	struct iphdr *ip_header = (struct iphdr *)(packet + 14);
	struct sockaddr_in source, dest;
	source.sin_addr.s_addr = ip_header->saddr;
	dest.sin_addr.s_addr = ip_header->daddr;

	printf("Pacote capturado: %s -> %s | Tamanho: %d bytes\n", inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr), header.len);

	fwrite(packet, sizeof(u_char), header.len, output_file);
	fflush(output_file);
    
    
    }

    fclose(output_file);
    pcap_close(handle);


}

//Descobrir hosts na rede
void discover_hosts(const char *ip_range){
    char command[256];
    snprintf(command, sizeof(command), "ping -c 1 -W 1 %s > /dev/null 2>&1", ip_range);

    if(system(command) == 0){
        printf(GREEN "[*] IP %s está ativo\n" RESET, ip_range);
    
    }else{
        printf(RED "[*] IP %s está inativo\n" RESET, ip_range);
    }

}

//Função principal
int main(int argc, char *argv[]){
    printf("Carregando");
    for(int i = 0; i < 3; i++){
        printf(".");
	fflush(stdout);
	sleep(1);
    }
    printf("\n");
    print_banner();

    int choice;
    printf("Escolha uma das opções: \n\n");
    printf("1. Capturar pacotes\n");
    printf("2. Verificação de hosts\n");
    printf("3. Verificação de portas e serviços\n");
    printf("Digite sua escolha: ");
    scanf("%d", &choice);

    switch(choice){
         case 1: {
	     char interface[10];
             printf("Digite a interface de rede (ex: eth0 ou wlan0): ");
             scanf("%s", interface);
             packet_sniffer(interface);	     
             break; 
	}
	 case 2: {
	     char ip[16];
	     printf("Digite o IP ou intervalo (ex: 192.168.1.1): ");
	     scanf("%s", ip);
	     discover_hosts(ip);
	     break;
	}
	 case 3: {
	     char ip[16];
             int start_port, end_port;

	     printf("Digite o IP para escanear: ");
	     scanf("%s", ip);
	     printf("Digite a porta inicial: ");
	     scanf("%d", &start_port);
	     printf("Digite a porta final: ");
	     scanf("%d", &end_port);

	     printf("Escaneando portas de %d a %d...\n", start_port, end_port);
	     port_scanner(ip, start_port, end_port);

	     char report_data[256];
	     snprintf(report_data, sizeof(report_data), "Scan de %d a %d completo.", start_port, end_port);
	     generat_html_report(report_data);
	     break;
		 
         }
	 default:
	     printf(RED "Escolha inválida!" RESET "\n");
         break;     
    }
    
    return 0;

}



