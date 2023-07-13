// Client
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#include "pq.h"

#define PORT 6067
#define NSB  1024
#define FCLIENT 0 // and FSERVER 1

extern unsigned long long cyclesAES;
extern unsigned long long cyclesNH;
extern unsigned long long cyclesDil;

//argv[1] = dilithium || argv[1] = newhope
//argv[2] = 0 no sign || argv[2] = 1 server cert verify || argv[2] = 2 both verify
int main(int argc, char const *argv[]) {
    int sock = 0, lenval, opt2, cs;
    struct sockaddr_in serv_addr;
    char sbuffer[NSB] = {0};
    char opt[NSB];

    if (argc < 2) {
        printf("USO: ./program opts1 opts2\n");
        return -1;
    }

    memcpy(opt, argv[1], strlen(argv[1]));
    //memcpy(opt2, argv[2], strlen(argv[2]));
    opt2 = atoi(argv[2]);

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    
    //if(inet_pton(AF_INET, "148.204.66.129", &serv_addr.sin_addr)<=0)
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    send(sock, opt, strlen(opt), 0);
    send(sock, &opt2, sizeof(opt2), 0);

    unsigned long long initCycles = rdtsc();
    TLS(sock, opt, opt2, FCLIENT); //TLS func -> pq.c
    unsigned long long totalCycles = rdtsc() - initCycles;

    cs = shutdown(sock, 2);
    fflush(stdout);
    opt[0] = '\0';

    // apend regist to log file
    switch (opt2) {
        default:
        case 0:
            mfiles("./No-Dilitium", cyclesDil, cyclesNH, cyclesAES, totalCycles);
            break;
        case 1:
            mfiles("./Single-Dilitium", cyclesDil, cyclesNH, cyclesAES, totalCycles);
            break;
        case 2:
            mfiles("./Double-Dilitium", cyclesDil, cyclesNH, cyclesAES, totalCycles);
            break;
    }
    return 0;
}
