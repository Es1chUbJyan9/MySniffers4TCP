#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <iostream>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>

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
    Sniffer4TCP(char* path, unsigned int bSize):bufferSize(bSize),countLimit()
    {
        strncpy(database_path, path, 1024);
        buffer = (unsigned char *)malloc(bufferSize);
        payload = (unsigned char *)malloc(bufferSize);

        sock = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
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
        packet_size = recvfrom(sock, buffer, bufferSize, 0, NULL, NULL);
    }

    void AnalysisPacket(){
        struct iphdr *ip_packet = (struct iphdr *)buffer;
        packetSize = ntohs(ip_packet->tot_len);
        headerSize = (int)ip_packet->ihl;
        payloadSize = packetSize - headerSize;
        packetId = ntohs(ip_packet->id);

        struct sockaddr_in source_socket_address, dest_socket_address;
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

        for (int i=0; i < packetSize; i++){
            printf(" %02x",buffer[i]);
            if ((i + 1) % 16 == 0){
                printf("\n");
            }
        }
        printf("\n\n");  
        
        for(int i=0; i<payloadSize; i++){
            payload[i] = buffer[i+headerSize];
        }
    }

    void RecordPacket(){
        database = fopen(database_path, "a");
        if(NULL == database){
            cout << "Open file failure!" << endl;
            exit(1);
        }

        fprintf(database, "Packet_ID %u:", packetId);
        for(int i=0; i<payloadSize ;i++){
            fprintf(database, " %02x", payload[i]);
        }
        fprintf(database, "\n");
        
        fclose(database);
    }

private:
    struct sockaddr_in source_socket_address, dest_socket_address;    
    int packet_size;
    unsigned char *buffer;
    unsigned char *payload;
    unsigned int bufferSize;
    unsigned int packetSize;
    unsigned int headerSize;
    unsigned int payloadSize;
    unsigned int packetId;
    unsigned int countLimit;
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
