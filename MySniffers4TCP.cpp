#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <iostream>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

#define BUFFER_SIZE 65535
#define PATH "./data.txt"

using namespace std;

class Timer {
public:
    Timer():tpStart(std::chrono::high_resolution_clock::now()),tpStop(tpStart)
    {
    }
    
    void start(){
        tpStart = std::chrono::high_resolution_clock::now();
    }
    
    void stop(){
        tpStop = std::chrono::high_resolution_clock::now();
    }
    
    template <typename span>
    int delta() const{
        return (int)(std::chrono::duration_cast<span>(std::chrono::high_resolution_clock::now() - tpStart).count());
    }
    
private:
    std::chrono::time_point<std::chrono::high_resolution_clock> tpStart;
    std::chrono::time_point<std::chrono::high_resolution_clock> tpStop;
};

class Sniffer4TCP {
public:
    Sniffer4TCP(char* path, unsigned int bSize):bufferSize(bSize)
    {
        strncpy(database_path, path, 1024);
        buffer = (unsigned char *)malloc(bufferSize);
        payload = (unsigned char *)malloc(bufferSize);

    	sock = socket (AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if(sock == -1){
            cout << "Failed to create socket" << endl;
            exit(1);
        }
    }

    void StartSniffer(int time_limit, int count_limit){
        loopTimer.start();
        
        for(int count=0; (loopTimer.delta<std::chrono::seconds>() < time_limit) && (count < count_limit); count++){
            ReadPacket();
            AnalysisPacket();
            RecordPacket();
        }
    }

    void ReadPacket(){
        packetSize = recvfrom(sock, buffer, bufferSize, 0, NULL, NULL);
    }

    void AnalysisPacket(){
        struct ethhdr *eth = (struct ethhdr *)buffer;
        printf("Ethernet Header\n");
        printf("Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
        printf("Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
        printf("Protocol : %d\n",eth->h_proto);
        
        struct iphdr *ip_packet = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        headerSize = ip_packet->ihl*4;
        payloadSize = packetSize - (ip_packet->ihl*4 + sizeof(struct ethhdr) + sizeof(struct iphdr));
        packetId = ntohs(ip_packet->id);
        memset(&source_socket_address, 0, sizeof(source_socket_address));
        source_socket_address.sin_addr.s_addr = ip_packet->saddr;
        memset(&dest_socket_address, 0, sizeof(dest_socket_address));
        dest_socket_address.sin_addr.s_addr = ip_packet->daddr;
        printf("Incoming Packet ID: %d\n", packetId);
        printf("Packet Size (bytes): %d\n",packetSize);
        printf("Header Size (bytes): %d\n",headerSize);
        printf("Payload Size (bytes): %d\n", payloadSize);
        printf("Source Address: %s\n", (char *)inet_ntoa(source_socket_address.sin_addr));
        printf("Destination Address: %s\n", (char *)inet_ntoa(dest_socket_address.sin_addr));
        unsigned char *data = (buffer + ip_packet->ihl*4 + sizeof(struct ethhdr) + sizeof(struct iphdr));
        
        printf("Payload:\n");
        for(int i=0; i<payloadSize; i++){
            payload[i] = data[i];

            printf(" %02X",payload[i]);
            if ((i + 1) % 16 == 0)
                printf("\n");
        }
        printf("\n");

    }

    void RecordPacket(){
        database = fopen(database_path, "a");
        if(NULL == database){
            cout << "Open file failure!" << endl;
            exit(1);
        }

        for(int i=0; i<payloadSize ;i++){
            fprintf(database, " %02X", payload[i]);
        }
        fprintf(database, "\n");
        
        fclose(database);
    }

private:
    struct sockaddr_in source_socket_address, dest_socket_address;    
    unsigned char *buffer;
    unsigned char *payload;
    unsigned int bufferSize;
    unsigned int packetSize;
    unsigned int headerSize;
    unsigned int payloadSize;
    unsigned int packetId;
    unsigned int count_limit;
    int sock;
    char database_path[1024];
    FILE *database;
    Timer loopTimer;

};

int main(int argc, char *argv[]){
    
    if(argc < 3){
        cout << "Please input time limit & count limit!";
        return 1;
    }

    Sniffer4TCP sniffer(PATH, BUFFER_SIZE);
    sniffer.StartSniffer(atoi(argv[1]), atoi(argv[2]));

    return 0;
}
