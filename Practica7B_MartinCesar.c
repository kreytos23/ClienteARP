#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<linux/if_ether.h>
#include<net/if.h>
#include<netinet/in.h>
#include<linux/ip.h>
#include<net/if_arp.h>
#include<arpa/inet.h>

typedef struct msg_ARP{
	unsigned char destinoEthernet[6];      /*Dirección de difusión 0xFF*/
	unsigned char origenEthernet[6];       /*Dirección MAC del transmisor*/
	unsigned short tipoEthernet;             /*Tipo de mensaje en la trama Ethernet*/
	unsigned short tipoHardware;           /*Tipo de hardware utilizado para difundir el mensaje ARP (Ethernet)*/
	unsigned short tipoProtocolo;          /*Tipo de protocolo de red utilizado para difundir el mensaje ARP (IP)*/
	unsigned char longitudHardware;  /*Tamaño de direcciones de hardware (6bytes)*/
	unsigned char longitudProtocolo;  /*Tamaño de direcciones del protocolo (4bytes)*/
	unsigned short tipoMensaje;          /* Solicitud o respuesta*/
	unsigned char origenMAC[6];         /*Dirección MAC del transmisor*/
	unsigned char origenIP[4];             /*Dirección IP del transmisor*/
	unsigned char destinoMAC[6];  /*Dirección MAC del receptor (dirección solicitada)*/
	unsigned char destinoIP[4];         /*Dirección IP del receptor (dato de entrada)*/
} msg_ARP;

int n1 = 0, n2 = 0, n3 = 3, n4 = 0;
int ipTotal = 0;
int k = 0;

char nomTarj[20] = {};
char seccionIp[3] = {0};

unsigned char destinoIPAux[4];
unsigned char MACAddr[6] = {0};
unsigned char IPAddr[6] = {0};

msg_ARP msgARP;
msg_ARP aux;
msg_ARP msgARP1;

int main(){
	printf("Cesar Sadrak Martin Moreno\n\n");
	printf("\n\t----Cliente ARP---\n\n");
	printf("Nombre de tarjeta de red: ");
	fflush(stdin);
	scanf("%s",nomTarj);

	printf("\nNumero de direcciones a analizar: ");
   	fflush(stdin);
	scanf("%d",&ipTotal);
	
	char ip_dest[ipTotal][16];
	
    for (int i = 0; i < ipTotal; i++) {
        bzero(ip_dest[i],16);
        printf("\nDireccion %d: ", i+1);
        scanf("%s", ip_dest[i]);
    }
	

	for(k = 0;k < ipTotal; k++){
		char ipAnalizar[16];
		strcpy(ipAnalizar,ip_dest[k]);

		printf("\n\n\t---Inicia Petición ARP para: %s ---\n\n", ipAnalizar);

		n1 = 0;
		n2 = 0;
		n3 = 0;
		n4 = 0;
		for ( n1=0 ; n1 <= strlen(ipAnalizar); n1++) {
			if (ipAnalizar[n1] == '.' || ipAnalizar[n1] == '\0') {
				n3 = n1 - n2;
				bzero(seccionIp, 3);
				strncpy(seccionIp, &ipAnalizar[n2], n3);
				destinoIPAux[n4] = (unsigned char) atoi(seccionIp);
				n2 = n1 + 1;
				n4++;
			}
		}
		struct ifreq ifr1;
		memset(&ifr1, 0, sizeof(struct ifreq));

		int optval;
		int socket_packet;
		if ((socket_packet = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_ARP))) < 0) {
			printf("ERROR: Socket no abierto, %d\n", socket_packet);
			exit(1);
		}

		setsockopt(socket_packet, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval));

		strncpy(ifr1.ifr_name, nomTarj, IFNAMSIZ);
		if (ioctl(socket_packet, SIOCGIFFLAGS, &ifr1) == -1) {
			perror("ERROR: Dispositico no reservado");
			exit(1);
		}
		ifr1.ifr_flags |= IFF_PROMISC;
		if (ioctl(socket_packet, SIOCSIFFLAGS, &ifr1) == -1) {
			perror("ERROR: No se configur? modo promiscuo");
			exit(1);
		}

		if (ioctl(socket_packet, SIOCGIFADDR, &ifr1) != 0) {
			perror("ERROR: Direcci?n MAC no obtenida");
			exit(1);
		}

		memcpy(IPAddr, ifr1.ifr_addr.sa_data, 6);

		if (ioctl(socket_packet, SIOCGIFHWADDR, &ifr1) != 0) {
			perror("ERROR: Direcci?n MAC no obtenida");
			exit(1);
		}

		memcpy(MACAddr, ifr1.ifr_hwaddr.sa_data, 6);
		
		for (int i = 0; i < 6; i++) msgARP.destinoEthernet[i] = 0xFF;

		for (int i = 0; i < 6; i++) msgARP.origenEthernet[i] = MACAddr[i];

		msgARP.tipoEthernet = htons(ETH_P_ARP);
		msgARP.tipoHardware = htons(ARPHRD_ETHER);
		msgARP.tipoProtocolo = htons(ETH_P_IP);
		msgARP.longitudHardware = 6;
		msgARP.longitudProtocolo = 4;
		msgARP.tipoMensaje = htons(ARPOP_REQUEST);

		for (int i = 0; i < 6; i++) msgARP.origenMAC[i] = MACAddr[i];

		for (int i = 0; i < 4; i++) msgARP.origenIP[i] = IPAddr[i + 2];

		for (int i = 0; i < 6; i++) msgARP.destinoMAC[i] = 0x00;

		for (int i = 0; i < 4; i++) msgARP.destinoIP[i] = destinoIPAux[i];
		
		
		printf("\n---Se creo el paquete ARP---\n");
		
		printf("\n\tDestino Ethernet: ");
		for(int i=0; i < 6; i++){
			printf("%02x",msgARP.destinoEthernet[i]);
			if(i != 5){
				printf(":");
			}
		}
		printf("\n\tOrigen Ethernet: ");
		for(int i=0; i < 6; i++){
			printf("%02x",msgARP.origenEthernet[i]);
			if(i != 5){
				printf(":");
			}
		}
		printf("\n\tTipo Ethernet: ");
		printf("0x%04x ",htons(msgARP.tipoEthernet));
		
		printf("\n\tTipo Hardware: ");
		printf("%d ",htons(msgARP.tipoHardware));
		
		printf("\n\tTipo Protocolo: ");
		printf("0x%04x ",htons(msgARP.tipoProtocolo));
		
		printf("\n\tLongitud Hardware: ");
		printf("%d ",msgARP.longitudHardware);
		
		printf("\n\tLongitud Protocolo: ");
		printf("%d ",msgARP.longitudProtocolo);
		
		printf("\n\tMensaje de tipo: ");
		printf("%d ",htons(msgARP.tipoMensaje));
		
		printf("\n\tDireccion de Hardware del Transmisor: ");
		for(int i=0; i < 6; i++){
			printf("%02x",msgARP.origenMAC[i]);
			if(i != 5){
				printf(":");
			}
		}

		printf("\n\tDireccion IP del Transmisor: ");
		for(int i=0; i < 4; i++){
			printf("%d",msgARP.origenIP[i]);
			if(i != 3){
				printf(".");
			}
		}
		printf("\n\tDireccion de Hardware del Destino: ");
		for(int i=0; i < 6; i++){
			printf("%02x",msgARP.destinoMAC[i]);
			if(i != 5){
				printf(":");
			}
		}
		
		printf("\n\tDireccion IP del Destino: ");
		for(int i=0; i < 4; i++){
			printf("%d",msgARP.destinoIP[i]);
			if(i != 3){
				printf(".");
			}
		} 
		
		printf("\n");
		
		struct sockaddr addr;
		strncpy(addr.sa_data, nomTarj, sizeof(addr.sa_data));
		int n = sizeof(addr);
		int intSend = sendto(socket_packet,&msgARP,sizeof(msgARP),0,&addr,n);

		if(intSend <= 0){
			printf("Error en send to\n");
			close(socket_packet);
			exit(1);
		}
		
		printf("\n");
		int ttlPaquete = 10;
		do{
			printf("Esperando Respuesta del destino...\n");
			recvfrom(socket_packet,&msgARP1,sizeof(msgARP1),0,NULL,NULL);
			aux = msgARP1;
			if(ttlPaquete == 0){
				printf("\nTTL agotado para direccion solicitada\n");
				break;
			}
			ttlPaquete--;
		}while(!(htons(aux.tipoMensaje) == 2 && aux.origenIP[3] == msgARP.destinoIP[3] && aux.origenIP[2] == msgARP.destinoIP[2]));
		
		close(socket_packet);
		
		if(ttlPaquete != 0){
			printf("\n\tDireccion Hardware solicitada: ");
			for(int i=0; i < 6; i++){
				printf("%02x",aux.origenMAC[i]);
				if(i != 5){
					printf(":");
				}
			}
			printf("\n\n\n");
			}
	}

	return 0;
}