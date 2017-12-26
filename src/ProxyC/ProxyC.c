#include<stdio.h>  
#include <stdlib.h>
#include<poll.h>  
#include<netdb.h>
#include<sys/types.h>  
#include<sys/socket.h>  
#include<arpa/inet.h>  
#include<unistd.h>  
#include<string.h>  
#include<errno.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>

  
//#define ADDR "192.168.32.144"  
//#define PORT 8080  
//#define ADDR_APACHE "18.216.47.167"  
//#define PORT_APACHE 8080


//                              ProxyC                             ProxyF
//                 |-------|---------|---------|            |-------|---------|--------| 
//                 | local | encrypt |         |            | server|         |        |
//    local        |listen | ---->   |         |  GreatWall | listen| decrypt |        |
//    machine <--->|       |         |         | <--------->|       |-------->|(google)|
//                 |client1| decrypt | remote1 |            |remote1|<--------| web1   |
//                 |client2| <------ | remote2 |            |remote2|  encrypt| web2   |
//                 |-------|---------|---------|            |-------|---------|--------|

#define DEBUG            1
#define BUFFER_SIZE      65535
#define MAX_CONNECTION_COUNT 128

struct proxy_connection
{
    int  client_socket, remote_socket;
    char client_ip[16], remote_ip[16];
    int  client_port,   remote_port;
    char client_buf[BUFFER_SIZE], remote_buf[BUFFER_SIZE];
    int  client_buf_len, remote_buf_len;
};
struct proxy_connection *pconnections[MAX_CONNECTION_COUNT];

int log_info(char *fmt, ... )
{
    time_t timep; 
    int     n;
    va_list args;
    FILE *f;
    char strtime[128], *p;

    f = fopen("log_c.txt", "a+");

    time (&timep); 
    sprintf(strtime, "%s", ctime(&timep));
    p = strtime + strlen(strtime) - 1;
    while(*p == '\n' || *p == '\r')
    {
        *p = '\0';
        p--;
    }
    fprintf(f, "[%s]",strtime);

    va_start(args, fmt);
    n = vfprintf(f, fmt, args);
    va_end(args);

    fclose(f);
    return n;    
}
  
int main(int argc, char* argv[])  
{  
    char key[7];
    int length;
    int i, j, ret=0;  
    fd_set  rdfs;
    struct sockaddr_in remoteaddr,localaddr,clientaddr;  
    socklen_t clientlen = sizeof(clientaddr);  
    int    remote , local, client;  
    
    
    if(argc != 5)
    {
        printf("Usage: %s LocalIp LocalPort RemoteIp RemotePort\n", argv[0]);
        return -1;
    }
  
    localaddr.sin_family       = AF_INET;  
    localaddr.sin_addr.s_addr  = inet_addr(argv[1]);  
    localaddr.sin_port         = htons(atoi(argv[2]));  

    remoteaddr.sin_family      = AF_INET;  
    remoteaddr.sin_addr.s_addr = inet_addr(argv[3]);
    remoteaddr.sin_port        = htons(atoi(argv[4]));  
  

    local     = socket(AF_INET,SOCK_STREAM,0);  
    bind(local,(struct sockaddr*)&localaddr,sizeof(localaddr));  
    ret = listen(local, 5);  
    if(ret < 0)
    {
    	printf("Failed to listen on %s:%s errno=%d\n", argv[1], argv[2], errno);
    	return -1;
    }

    for( i = 0; i < MAX_CONNECTION_COUNT; i++)
    {
        pconnections[i] = NULL;
    }

    while(1)  
    {  
        int max_fd = -1;
        FD_ZERO(&rdfs);
        FD_SET(local, &rdfs);
        max_fd = local;
        for(i = 0; i < MAX_CONNECTION_COUNT; i++)
        {
            if(pconnections[i] != NULL)
            {
                FD_SET(pconnections[i]->client_socket, &rdfs);
                max_fd = pconnections[i]->client_socket > max_fd ? pconnections[i]->client_socket : max_fd;
                FD_SET(pconnections[i]->remote_socket, &rdfs);
                max_fd = pconnections[i]->remote_socket > max_fd ? pconnections[i]->remote_socket : max_fd;
            }
        }
        ret = select(max_fd + 1,&rdfs,NULL, NULL, NULL);
        if(ret<0)  
        {  
            printf("select error \n");  
        }
        else if(ret == 0)
        {
            printf("time out\n");
        }
        else
        {
            if(FD_ISSET(local, &rdfs))  
            {  
                client = accept(local,(struct sockaddr*)&clientaddr,&clientlen);
                if(client > 0)
                {
                    for(i = 0; i < MAX_CONNECTION_COUNT; i++)
                    {
                        if(pconnections[i] == NULL)
                        {
                            pconnections[i] = (struct proxy_connection*)malloc(sizeof(struct proxy_connection));
                            pconnections[i]->client_socket        = client;
                            strcpy(pconnections[i]->client_ip,inet_ntoa(clientaddr.sin_addr));
                            pconnections[i]->client_port   = ntohs(clientaddr.sin_port);
                            pconnections[i]->client_buf_len = 0;
                            break;
                        }
                    }
                    if(i == MAX_CONNECTION_COUNT)
                    {
                        log_info("ERR: failed to connect to the server, too many connections\n");
                        close(client);
                    }
                    else
                    {
                        log_info("Connected to %s:%d\n",inet_ntoa(clientaddr.sin_addr),  
                                ntohs(clientaddr.sin_port));
                        
                        remote = socket(AF_INET,SOCK_STREAM,0);  
                        ret    = connect(remote,(struct sockaddr*)&remoteaddr,sizeof(remoteaddr));
                        if (ret < 0)
                        {
    	                      log_info("Connecting to remote server failed, errno = %d.\n", errno);
    	                      free(pconnections[i]);
    	                      pconnections[i] = NULL;
    	                      close(client);
                        }
                        else
                        {
                            pconnections[i]->remote_socket = remote;
                            pconnections[i]->remote_port   = ntohs(remoteaddr.sin_port);
                            strcpy(pconnections[i]->remote_ip,inet_ntoa(remoteaddr.sin_addr));
                            pconnections[i]->remote_buf_len = 0;
                        }
                    }
                }
            }
            else
            {
                for(i = 0; i < MAX_CONNECTION_COUNT; i++)
                {
                    if(pconnections[i] == NULL)
                    {
                        continue;
                    }
                    if(FD_ISSET(pconnections[i]->client_socket, &rdfs))
                    {//read from client, encrypt and then send it to remote
                    	  memset(pconnections[i]->client_buf, 0, BUFFER_SIZE);
                        length = recv(pconnections[i]->client_socket, pconnections[i]->client_buf + 8, BUFFER_SIZE - 8, 0);
                        log_info("\n%s\n", pconnections[i]->client_buf + 8);
                        if(length < 0)
                        {
                            log_info("error receive data %d\n", i);
                        }
                        else if(length == 0) //connection closed
                        {
        	                  log_info("socket %s: %d closed!\n", pconnections[i]->client_ip, pconnections[i]->client_port);
        	                  close(pconnections[i]->client_socket);
        	                  close(pconnections[i]->remote_socket);
        	                  free(pconnections[i]);
        	                  pconnections[i] = NULL;
        	                  continue;
                        }
                        else
                        {
                            strcpy(key, "abcd");        
                            memcpy(pconnections[i]->client_buf, &length, 4);
                            memcpy(pconnections[i]->client_buf + 4, key, 4);
                            for(j = 0; j < length; j++)
                            {
        	                      pconnections[i]->client_buf[j + 8] ^= key[j % 4];
                            }
                            if(send(pconnections[i]->remote_socket, pconnections[i]->client_buf, length + 8, 0) < 0)
                            {
        	                      log_info("error sending data to %s:%d\n" , pconnections[i]->remote_ip, pconnections[i]->remote_port);
                            }
                        }
                    }
                    if(FD_ISSET(pconnections[i]->remote_socket, &rdfs))
                    {//read from remote, decrypt and then send it to client
                        length = recv(pconnections[i]->remote_socket, pconnections[i]->remote_buf + pconnections[i]->remote_buf_len, BUFFER_SIZE - pconnections[i]->remote_buf_len, 0);
                        if(length < 0)
                        {
                            log_info("error receive data %d\n", i);
                        }
                        else if(length == 0) //connection closed
                        {
        	                  log_info("socket %s, %d closed!\n", pconnections[i]->remote_ip, pconnections[i]->remote_port);
        	                  close(pconnections[i]->client_socket);
        	                  close(pconnections[i]->remote_socket);
        	                  free(pconnections[i]);
        	                  pconnections[i] = NULL;
        	                  continue;
                        }
                        else
                        {
                            pconnections[i]->remote_buf_len += length;
                            memcpy(&length, pconnections[i]->remote_buf, 4);
                            while(length + 8 <= pconnections[i]->remote_buf_len)
                            {
                                memcpy(key, pconnections[i]->remote_buf + 4, 4);
                                key[4] = '\0';
                                for(j = 0; j < length; j++)
                                {
        	                          pconnections[i]->remote_buf[j + 8] ^= key[j % 4];
                                }
                                pconnections[i]->remote_buf[length + 8] = '\0';
                                log_info("\n%s\n", pconnections[i]->remote_buf + 8);
                                if(send(pconnections[i]->client_socket, pconnections[i]->remote_buf + 8, length, 0) < 0)
                                {
        	                          log_info("error sending data to %s:%d\n" , pconnections[i]->client_ip, pconnections[i]->client_port);
                                }
                                memmove(pconnections[i]->remote_buf, pconnections[i]->remote_buf + length + 8, pconnections[i]->remote_buf_len - length - 8);
                                pconnections[i]->remote_buf_len -= length + 8;
                                if(pconnections[i]->remote_buf_len <= 0)
                                {
                                    break;
                                }
                                else
                                {
                                    memcpy(&length, pconnections[i]->remote_buf, 4);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    printf("Exited! \n");
    close(local);
    return 0;  
}  
