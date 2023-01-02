#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int main(int argc, char const *argv[])
{
    
    int tcp_socket = socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in adr;
    adr.sin_family = AF_INET;
    adr.sin_port = htons(80);
    adr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(tcp_socket,(struct sockaddr*)&adr,sizeof(adr)) < 0)
    {
        printf("error bind\n");
        close(tcp_socket);
        return -1;
    }
    
    if (listen(tcp_socket, 1000) < 0)
    {
        printf("error listen\n");
        close(tcp_socket);
        return -1;
    }
    printf("listening\n");
    struct sockaddr_in client;
    int size = sizeof(struct sockaddr_in);
    int client_socket;
    if (client_socket = accept(tcp_socket,(struct sockaddr*)&adr,(socklen_t*)&size) < 0)
    {
        close(tcp_socket);
        printf("error accept\n");
        return -1;
    }
    printf("connected to port %d\n",ntohs(adr.sin_port));
    char buf[1024] = {0};
    if (read(client_socket,buf,1024) < 0)
    {
        close(tcp_socket);
        close(client_socket);
        printf("error recv\n");
        return -1;
    }
    printf("%s\n",buf);
    close(tcp_socket);
    close(client_socket);
    return 0;
}



