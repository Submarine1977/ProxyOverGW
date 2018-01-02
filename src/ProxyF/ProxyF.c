#include<stdio.h>
#include<stdlib.h>
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

//                              ProxyC                             ProxyF
//                 |-------|---------|---------|            |-------|---------|--------| 
//                 | local | encrypt |         |            | server|         |        |
//    local        |listen | ---->   |         |  GreatWall | listen| decrypt |        |
//    machine <--->|       |         |         | <--------->|       |-------->|(google)|
//                 |client1| decrypt | remote1 |            |remote1|<--------| web1   |
//                 |client2| <------ | remote2 |            |remote2|  encrypt| web2   |
//                 |-------|---------|---------|            |-------|---------|--------|
  
#define DEBUG            0
#define BUFFER_SIZE      65535
#define MAX_CONNECTION_COUNT 128
 
#define CONNECTION_STATUS_INIT 0
#define CONNECTION_STATUS_AUTH 1
#define CONNECTION_STATUS_CONN 2

struct proxy_connection
{
    int  web_socket, remote_socket;
    char web_ip[16], remote_ip[16];
    int  web_port,   remote_port;
    char web_buf[BUFFER_SIZE], remote_buf[BUFFER_SIZE], message_buf[1024];
    int  web_buf_len, remote_buf_len, message_buf_len;
    char status;
};
struct proxy_connection *pconnections[MAX_CONNECTION_COUNT];

int min(int x, int y)
{
    return x < y? x:y;
}
int log_info(char *fmt, ... )
{
    time_t timep; 
    int     n;
    va_list args;
    FILE *f;
    char strtime[128], *p;

    f = fopen("log_f.txt", "a+");

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

void dumpbuffer(char *buffer, int length, char* filename, ...)
{
    va_list args;
    int i, j, n;
    char str[16];
    char name[128];

    if(DEBUG == 0)
    {
        return;
    }

    va_start(args, filename);
    n = vsprintf(name, filename, args);
    va_end(args);
    
    FILE *f;
    f = fopen(name, "a+");
    for(i = 0; i < length; i++)
    {
        sprintf(str, "%02x", buffer[i]);
        fprintf(f, "%s ", str + strlen(str) - 2);
        if((i + 1) % 32 == 0)
        {
            fprintf(f, "  ");
            for(j = i - 31; j <= i; j++)
            {
                if( (buffer[j] >= 'a' && buffer[j] <= 'z') ||
                	  (buffer[j] >= 'A' && buffer[j] <= 'Z') ||
                	  (buffer[j] >= '0' && buffer[j] <= '9'))
                {
                    fprintf(f, "%c", buffer[j]);
                }
                else
                {
                    fprintf(f, ".");
                }
            }
            fprintf(f, "\n");
        }
    }
    if( (i + 1) %32 != 0 )
    {
        do
        {
            fprintf(f, "   ");	
            i++;
        }
        while((i + 1) % 32 != 0);
        fprintf(f, "  ");
        for(j = i - 31; j < length; j++)
        {
            if( (buffer[j] >= 'a' && buffer[j] <= 'z') ||
        	      (buffer[j] >= 'A' && buffer[j] <= 'Z') ||
        	      (buffer[j] >= '0' && buffer[j] <= '9'))
            {
                fprintf(f, "%c", buffer[j]);
            }
            else
            {
                fprintf(f, ".");
            }
        }
    }
    fprintf(f, "\n");
    fclose(f);
};

void encrypt_message(char *buffer, int length, char*  key)
{
   int i, t = strlen(key);
   for(i = 0; i < length; i++)
   {
      buffer[i] ^= key[i%t];
   }
}
void decrypt_message(char *buffer, int length, char*  key)
{
   int i, t = strlen(key);
   for(i = 0; i < length; i++)
   {
      buffer[i] ^= key[i%t];
   }
}

//+----+----------+----------+
//|VER | NMETHODS | METHODS  |
//+----+----------+----------+
//| 1  |    1     | 1 to 255 |
//+----+----------+----------+
//-1 wrong
//0  message not complete
//1  succeeded
int parse_auth_message(char * buffer, int length, char *number_methods, char* methods)
{
    if(length < 2)
    {
        return 0;
    }
    if(buffer[0] != 5)
    {
        log_info("error sock5 auth_message btye[0] = %d\n", buffer[0]);
        return -1;
    }
    if(length < 2 + (unsigned char)buffer[1])
    {
        return 0;
    }
    else if(length > 2 + (unsigned char)buffer[1])
    {
        log_info("error sock5 auth_message, message is too long\n");
        return -1;
    }
    else
    {
        if(NULL != number_methods)
        {
            *number_methods = buffer[1];
        } 
        if(NULL != methods)
        {
            memcpy(methods, buffer + 2, (unsigned char)buffer[1]);
        }
        return 1;
    }
}
//+----+-----+-------+------+----------+----------+
//|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//+----+-----+-------+------+----------+----------+
//| 1  |  1  | X'00' |  1   | Variable |    2     |
//+----+-----+-------+------+----------+----------+
//-1 wrong
//0  message not complete
//1  succeeded
int parse_conn_message(char * buffer, int length, char* cmd, struct sockaddr_in *addr)
{
    int t;
    char hostname[128];
    struct hostent *host;
    if(length < 6)
    {
        return 0;
    }
    if(buffer[0] != 5)
    {
        log_info("error sock5 conn_message btye[0] = %d\n", buffer[0]);
        return -1;
    }
    *cmd = buffer[1];
    if(buffer[3] == 1)//IPV4
    {
        if(length == 10)
        {
            addr->sin_family = AF_INET;  
            memcpy(&addr->sin_addr, buffer + 4, 4);
            memcpy(&addr->sin_port, buffer + 8, 2);
            return 1;
        }
        else if(length < 10)
        {
            return 0;
        }
        else
        {
            log_info("error sock5 conn_message, message is too long\n");
            return -1;
        }
    }
    else if(buffer[3] == 3)//Domain name
    {
        t = (unsigned char)buffer[4];
        if(length == 7 + t)
        {
            memcpy(hostname, buffer + 5, t);
            hostname[t] = '\0';
            host = gethostbyname(hostname); 
            if(host == NULL)
            {
                log_info("error sock5 conn_message, hostname is wrong %s\n", hostname);
                return -1;
            }
            else
            {
                addr->sin_family = AF_INET;  
                addr->sin_addr   = *((struct in_addr*)host->h_addr); 
                memcpy(&addr->sin_port, buffer + t + 5, 2);
                return 1;
            }
        }
        else if( length < 7 + t)
        {
            return 0;
        }
        else
        {
            log_info("error sock5 conn_message, message is too long\n");
            return -1;
        }
    }
    else if(buffer[3] == 4)//ip v6
    {
        log_info("error sock5 conn_message, not support ip v6\n");
        return -1;
    }
    return -1;
}

void send_message(int socket, char* buffer, int length, char* ip, int port)
{
    int ret;
    if((ret = send(socket, buffer, length, 0)) < 0)
    {
        log_info("error sending data to (%s:%d)\n" , ip, port);
    }
    else if(ret < length)
    {
        log_info("error sending data to (%s:%d)--not all data was sent\n" , ip, port);
    }
    else
    {
        dumpbuffer(buffer, length, "send_web_f_%s_%d.txt", ip, port);
        log_info("%d bytes was sent to (%s:%d)\n", length, ip, port);
    }
}

int main(int argc, char *argv[])  
{  
    char key[7];
    int length;
    int i, j, ret=0;  
    fd_set  rdfs;
    struct sockaddr_in remoteaddr,serveraddr,webaddr;  
    socklen_t remotelen = sizeof(remoteaddr);  
    int    remote , server, web;  
    
    
    if(argc != 2)
    {
        printf("Usage: %s Port\n", argv[0]);
        return -1;
    }
  
    serveraddr.sin_family=AF_INET;  
    serveraddr.sin_addr.s_addr=htonl(INADDR_ANY);  
    serveraddr.sin_port=htons(atoi(argv[1]));
      
    server=socket(AF_INET,SOCK_STREAM,0);  
    bind(server,(struct sockaddr*)&serveraddr,sizeof(serveraddr));  
    ret = listen(server,5); 
    if(ret < 0)
    {
    	printf("Failed to listen on %s errno=%d\n", argv[1], errno);
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
        FD_SET(server, &rdfs);
        max_fd = server;
        for(i = 0; i < MAX_CONNECTION_COUNT; i++)
        {
            if(pconnections[i] != NULL)
            {
                FD_SET(pconnections[i]->remote_socket, &rdfs);
                max_fd = pconnections[i]->remote_socket > max_fd ? pconnections[i]->remote_socket : max_fd;
                if(pconnections[i]->web_socket > 0)
                {
                    FD_SET(pconnections[i]->web_socket, &rdfs);
                    max_fd = pconnections[i]->web_socket > max_fd ? pconnections[i]->web_socket : max_fd;
                }
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
            if(FD_ISSET(server, &rdfs))  
            {  
                remote = accept(server,(struct sockaddr*)&remoteaddr,&remotelen);
                if(remote > 0)
                {
                    for(i = 0; i < MAX_CONNECTION_COUNT; i++)
                    {
                        if(pconnections[i] == NULL)
                        {
                            pconnections[i] = (struct proxy_connection*)malloc(sizeof(struct proxy_connection));
                            pconnections[i]->remote_socket  = remote;
                            strcpy(pconnections[i]->remote_ip,inet_ntoa(remoteaddr.sin_addr));
                            pconnections[i]->remote_port    = ntohs(remoteaddr.sin_port);
                            pconnections[i]->remote_buf_len = 0;
                            pconnections[i]->status         = CONNECTION_STATUS_INIT;
                            break;
                        }
                    }
                    if(i == MAX_CONNECTION_COUNT)
                    {
                        log_info("ERR: failed to connect to the server, too many connections\n");
                        close(remote);
                    }
                    else
                    {
                        log_info("Connected to %s:%d\n",inet_ntoa(remoteaddr.sin_addr),  
                                ntohs(remoteaddr.sin_port));
                        pconnections[i]->web_socket  = -1;
                        pconnections[i]->web_buf_len = 0;
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
                    if(pconnections[i]->web_socket > 0 && FD_ISSET(pconnections[i]->web_socket, &rdfs))
                    {//read from web, encrypt and then send it to remote
                        memset(pconnections[i]->web_buf, 0, BUFFER_SIZE);
                        length = recv(pconnections[i]->web_socket, pconnections[i]->web_buf + 8, BUFFER_SIZE - 8, 0);
                        dumpbuffer(pconnections[i]->web_buf + 8, length, "recv_web_f_%s_%d", pconnections[i]->web_ip, pconnections[i]->web_port);
                        log_info("%d bytes received from website %s:%d\n", length, pconnections[i]->web_ip, pconnections[i]->web_port);
                        if(length < 0)
                        {
                            log_info("error receive data %d\n", i);
                        }
                        else if(length == 0) //connection closed
                        {
        	                  log_info("socket %s: %d closed!\n", pconnections[i]->web_ip, pconnections[i]->web_port);
        	                  close(pconnections[i]->web_socket);
        	                  close(pconnections[i]->remote_socket);
        	                  free(pconnections[i]);
        	                  pconnections[i] = NULL;
        	                  continue;
                        }
                        else
                        {
                            strcpy(key, "1234");
                            memcpy(pconnections[i]->web_buf, &length, 4);
                            memcpy(pconnections[i]->web_buf + 4, key, 4);
                            encrypt_message(pconnections[i]->web_buf + 8, length, key);
                            send_message(pconnections[i]->remote_socket, pconnections[i]->web_buf, length + 8, pconnections[i]->remote_ip, pconnections[i]->remote_port);
                        }
                    }
                    if(FD_ISSET(pconnections[i]->remote_socket, &rdfs))
                    {//read from remote, decrypt and then send it to web
                        length = recv(pconnections[i]->remote_socket, pconnections[i]->remote_buf + pconnections[i]->remote_buf_len, BUFFER_SIZE - pconnections[i]->remote_buf_len, 0);
                        dumpbuffer(pconnections[i]->remote_buf + pconnections[i]->remote_buf_len, length, "recv_remote_f_%s_%d.txt", pconnections[i]->remote_ip, pconnections[i]->remote_port);
                        log_info("%d bytes received from proxyc %s:%d\n", length, pconnections[i]->remote_ip, pconnections[i]->remote_port);
                        if(length < 0)
                        {
                            log_info("error receive data from proxyc %d\n", i);
                        }
                        else if(length == 0) //connection closed
                        {
        	                  log_info("proxyc socket %s:%d closed!\n", pconnections[i]->remote_ip, pconnections[i]->remote_port);
        	                  if(pconnections[i]->web_socket > 0)
        	                  {
        	                      close(pconnections[i]->web_socket);
        	                  }
        	                  close(pconnections[i]->remote_socket);
        	                  free(pconnections[i]);
        	                  pconnections[i] = NULL;
        	                  continue;
                        }
                        else
                        {
                            pconnections[i]->remote_buf_len += length;
                            memcpy(&length, pconnections[i]->remote_buf, 4);
                            log_info("Content length = %d\n", length);
                            while(length + 8 <= pconnections[i]->remote_buf_len)
                            {
                                memcpy(key, pconnections[i]->remote_buf + 4, 4);
                                key[4] = '\0';
                                log_info("Key = %s\n", key);
                                decrypt_message(pconnections[i]->remote_buf + 8, length, key);
                                
                                log_info("pconnections[%d]->status = %d\n", i, pconnections[i]->status);
                                if(pconnections[i]->status == CONNECTION_STATUS_INIT)
                                {   
                                    memcpy(pconnections[i]->message_buf + pconnections[i]->message_buf_len, pconnections[i]->remote_buf + 8, min(length, 1024 - pconnections[i]->message_buf_len));
                                    pconnections[i]->message_buf_len += min(length, 1024 - pconnections[i]->message_buf_len);
                                    ret = parse_auth_message(pconnections[i]->message_buf, pconnections[i]->message_buf_len, NULL, NULL);
                                    if(ret == -1)
                                    {//wrong message clear message buffer.
                                        pconnections[i]->message_buf_len = 0;
                                    }
                                    else if(ret == 1) //correct message
                                    {
                                        pconnections[i]->status = CONNECTION_STATUS_AUTH;
                                        //send message(0x0500) to proxyc
                                        // +----+--------+
                                        // |VER | METHOD |
                                        // +----+--------+
                                        // | 1  |   1    |
                                        // +----+--------+
                                        j = 2;
                                        strcpy(key, "1234");        
                                        memcpy(pconnections[i]->web_buf,     &j, 4);
                                        memcpy(pconnections[i]->web_buf + 4, key, 4);
                                        pconnections[i]->web_buf[8] = 5;
                                        pconnections[i]->web_buf[9] = 0;
                                        encrypt_message(pconnections[i]->web_buf + 8, j, key);
                                        send_message(pconnections[i]->remote_socket, pconnections[i]->web_buf, j + 8, pconnections[i]->remote_ip, pconnections[i]->remote_port);
                                        pconnections[i]->message_buf_len = 0;
                                    }
                                    //else ret == 0, waiting for the complete message
                                    //{
                                    //   do nothing here
                                    //}
                                }
                                else if(pconnections[i]->status == CONNECTION_STATUS_AUTH)
                                {
                                    memcpy(pconnections[i]->message_buf + pconnections[i]->message_buf_len, pconnections[i]->remote_buf + 8, min(length, 1024 - pconnections[i]->message_buf_len));
                                    pconnections[i]->message_buf_len += min(length, 1024 - pconnections[i]->message_buf_len);
                                    char   cmd;
                                    ret = parse_conn_message(pconnections[i]->message_buf, pconnections[i]->message_buf_len, &cmd, &webaddr);
                                    if(ret == -1)
                                    {//wrong message clear message buffer.
                                    	  log_info("wrong socks message:\n");
                                    	  dumpbuffer(pconnections[i]->message_buf, pconnections[i]->message_buf_len, "log_f.txt");
                                        pconnections[i]->message_buf_len = 0;
                                    }
                                    else if(ret == 1) //correct message
                                    {
                                        //send message(0x0500) to proxyc
                                        //+----+-----+-------+------+----------+----------+
                                        //|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
                                        //+----+-----+-------+------+----------+----------+
                                        //| 1  |  1  | X'00' |  1   | Variable |    2     |
                                        //+----+-----+-------+------+----------+----------+
                                        web = socket(AF_INET,SOCK_STREAM,0);  
                                        ret = connect(web,(struct sockaddr*)&webaddr,sizeof(webaddr)); 

                                        strcpy(key, "1234");        
                                        memcpy(pconnections[i]->web_buf + 4, key, 4);
                                        j = 10;
                                        memcpy(pconnections[i]->web_buf,     &j, 4);
                                        pconnections[i]->web_buf[8]  = 5;  //VER
                                        pconnections[i]->web_buf[10] = 0; //RSV
                                        pconnections[i]->web_buf[11] = 1;

                                        if(ret != 0) 
                                        { 
                                            log_info("failed to connect to the website: ret = %d,errno = %d, cmd = %d, host = %s, port = %d\n", 
                                                       ret, errno, cmd, inet_ntoa(webaddr.sin_addr), ntohs(webaddr.sin_port)); 
                                            pconnections[i]->web_buf[9] = 1; //REP
                                        } 
                                        else
                                        {
                                            log_info("connect to the website: host = %s, port = %d\n", inet_ntoa(webaddr.sin_addr), ntohs(webaddr.sin_port)); 
                                            strcpy(pconnections[i]->web_ip,inet_ntoa(webaddr.sin_addr)); 
                                            pconnections[i]->web_port   = ntohs(webaddr.sin_port); 
                                            pconnections[i]->web_socket = web; 
                                            pconnections[i]->web_buf[9] = 0; //REP
                                            memcpy(pconnections[i]->web_buf + 12, &webaddr.sin_addr, 4);
                                            memcpy(pconnections[i]->web_buf + 16, &webaddr.sin_port, 2);
                                            pconnections[i]->status = CONNECTION_STATUS_CONN;
                                        }
                                        encrypt_message(pconnections[i]->web_buf + 8, j, key);
                                        send_message(pconnections[i]->remote_socket, pconnections[i]->web_buf, j + 8, pconnections[i]->remote_ip, pconnections[i]->remote_port);
                                        pconnections[i]->message_buf_len = 0;
                                    }
                                    //else ret == 0, waiting for the complete message
                                    //{
                                    //   do nothing here
                                    //}
                                }
                                else //pconnections[i]->status == CONNECTION_STATUS_CONN
                                {
                                    send_message(pconnections[i]->web_socket, pconnections[i]->remote_buf + 8, length, pconnections[i]->web_ip, pconnections[i]->web_port);
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
    close(server);
    return 0;  
}  
