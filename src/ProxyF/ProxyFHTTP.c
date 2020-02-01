//#define WINDOWS
#include<stdio.h>  
#include <stdlib.h>
#include<sys/types.h>  
#include<string.h>  
#include<errno.h>
#include <time.h>
#include <stdarg.h>
#ifndef WINDOWS
#include<poll.h>  
#include<netdb.h>
#include<sys/socket.h>  
#include<arpa/inet.h>  
#include<unistd.h>  
#include <sys/time.h>
#define BOOL unsigned char
#define TRUE 1
#define FALSE 0
#else
#include <winsock.h>
#pragma comment(lib, "ws2_32.lib")
#endif


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
#define CONNECTION_STATUS_CONN 1

char global_buf[BUFFER_SIZE];

struct proxy_connection
{
    int  web_socket, remote_socket;
    char web_ip[16], remote_ip[16];
    int  web_port,   remote_port;
    char web_buf[BUFFER_SIZE], remote_buf[BUFFER_SIZE], message_buf[BUFFER_SIZE];
    int  web_buf_len, remote_buf_len, message_buf_len;
    char status;
};
struct proxy_connection *pconnections[MAX_CONNECTION_COUNT];

#ifndef WINDOWS
int min(int x, int y)
{
    return x < y ? x : y;
}
#endif // !WINDOWS

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


void send_message(int socket, char* buffer, int length, char* web_remote, char* ip, int port)
{
    int ret;
#ifndef WINDOWS                                
    if ((ret = send(socket, buffer, length, MSG_NOSIGNAL)) < 0)
#else
    if ((ret = send(socket, buffer, length, 0)) < 0)
#endif
    {
        log_info("error sending data to (%s:%d)\n" , ip, port);
    }
    else if(ret < length)
    {
        log_info("error sending data to (%s:%d)--not all data was sent\n" , ip, port);
    }
    else
    {
        dumpbuffer(buffer, length, "send_%s_f_%s_%d.txt", web_remote, ip, port);
        log_info("%d bytes was sent to (%s:%d)\n", length, ip, port);
    }
}

struct http_header {
    char method[16];
    char url[1024];
    char host[1024];
    char cookie[1024 * 10];
};

//HTTP HEADER
//CONNECT www.baidu.com:443 HTTP / 1.0
//User - Agent : Mozilla / 5.0 (Windows NT 10.0; Win64; x64) AppleWebKit / 537.36 (KHTML, like Gecko) Chrome / 70.0.3538.102 Safari / 537.36 Edge / 18.18362
//Content - Length: 0
//Host : www.baidu.com
//Proxy - Connection : Keep - Alive
//Pragma : no - cache

int parse_http_head(char* buffer, struct http_header* header, BOOL* bHttps)
{
    char* p;
    char* ptr;
    const char* delim = "\r\n";
#ifndef WINDOWS
    p = strtok_r(buffer, delim, &ptr);
#else
    p = strtok_s(buffer, delim, &ptr);
#endif
    if (p == NULL)
    {
        return -1;
    }
    if (p[0] == 'G') 
    {  //GET方式
        memcpy(header->method, "GET", 3);
        header->method[3] = '\0';
        memcpy(header->url, &p[4], strlen(p) - 13);  //url的长度
        header->url[strlen(p) - 13] = '\0';
        *bHttps = FALSE;
    }
    else if (p[0] == 'P') 
    {  //POST方式
        memcpy(header->method, "POST", 4);
        header->method[4] = '\0';
        memcpy(header->url, &p[5], strlen(p) - 14);
        header->url[strlen(p) - 14] = '\0';
        *bHttps = FALSE;
    }
    else if (p[0] == 'C')
    { //CONNECT
        memcpy(header->method, "CONNECT", 7);
        header->method[7] = '\0';
        memcpy(header->url, &p[8], strlen(p) - 17);
        header->url[strlen(p) - 17] = '\0';
        *bHttps = TRUE;
    }
    else
    {
        return -1;
    }
#ifndef WINDOWS
    p = strtok_r(NULL, delim, &ptr);
#else
    p = strtok_s(NULL, delim, &ptr);
#endif

    while (p) 
    {
        switch (p[0]) 
        {
        case 'H':  //host
            memcpy(header->host, &p[6], strlen(p) - 6);
            header->host[strlen(p) - 6] = '\0';
            break;
        case 'C': //cookie
            if (strlen(p) > 8) {
                char h[8];
                memset(h, 0, sizeof(h));
                memcpy(h, p, 6);
                if (!strcmp(h, "Cookie")) {
                    memcpy(header->cookie, &p[8], strlen(p) - 8);
                    header->cookie[strlen(p) - 8] = '\0';
                }
            }
            break;
        default:
            break;
        }
#ifndef WINDOWS
        p = strtok_r(NULL, delim, &ptr);
#else
        p = strtok_s(NULL, delim, &ptr);
#endif
        if (p == NULL || strlen(p) <= 0)
        {
            return ptr - buffer;
        }
    }
    return 0;
}

int parse_conn_message(char* buffer, int length, struct sockaddr_in* addr, BOOL *bHttps)
{
    int ret;
    strcpy(global_buf, buffer);
    struct http_header header;
    ret = parse_http_head(global_buf, &header, bHttps);
    if (ret <= 0)
    {
        return ret;
    }
    char *host, *port;
    host = header.host;
    port = strchr(host, ':');
    if (port != NULL)
    {
        *port = '\0';
        port++;
    }
    else if(header.method[0] == 'C')
    {
        port = strchr(header.url, ':');
        if (port != NULL)
        {
            port++;
        }
    }

    struct hostent* hostent = gethostbyname(header.host);
    if (!hostent) 
    {
        return -1;
    }
    struct in_addr inAddr = *((struct in_addr*)*hostent->h_addr_list);
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(inet_ntoa(inAddr));
    if (port != NULL)
    {
        addr->sin_port = htons(atoi(port));
    }
    else
    {
        addr->sin_port = htons(80);
    }
    return ret;
}


int main(int argc, char *argv[])  
{  
    char key[7];
    int length;
    int i, ret=0;  
    fd_set  rdfs;
    struct sockaddr_in remoteaddr,serveraddr,webaddr;  
#ifndef WINDOWS
    socklen_t remotelen = sizeof(remoteaddr);
#else
    int remotelen = sizeof(remoteaddr);
#endif // !WINDOWS
    int    remote , server, web;  
    int    port = 7777;
    
    
    if(argc != 2)
    {
        printf("Usage: %s Port\n", argv[0]);
        return -1;
    }

#ifdef WINDOWS
    WSADATA wsaData;
    int err = WSAStartup(0x202, &wsaData);   
    if (err != 0)
    {
        return 0;
    }
    else if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)   //initial socket
    {
        WSACleanup();
        return 0;
    }
#endif

    port = atoi(argv[1]);
    serveraddr.sin_family=AF_INET;  
    serveraddr.sin_addr.s_addr=htonl(INADDR_ANY);  
    serveraddr.sin_port=htons(port);
      
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
                            pconnections[i]->remote_port     = ntohs(remoteaddr.sin_port);
                            pconnections[i]->remote_buf_len  = 0;
                            pconnections[i]->status          = CONNECTION_STATUS_INIT;
                            pconnections[i]->message_buf_len = 0;
                            pconnections[i]->web_buf_len     = 0;
                            break;
                        }
                    }
                    if(i == MAX_CONNECTION_COUNT)
                    {
                        log_info("ERR: failed to connect to the server, too many connections\n");
#ifndef WINDOWS
                        close(remote);
#else
                        closesocket(remote);
#endif
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
                        dumpbuffer(pconnections[i]->web_buf + 8, length, "recv_web_f_%s_%d.log", pconnections[i]->web_ip, pconnections[i]->web_port);
                        log_info("%d bytes received from website %s:%d\n", length, pconnections[i]->web_ip, pconnections[i]->web_port);
                        if(length < 0)
                        {
                            log_info("error receive data %d\n", i);
                        }
                        else if(length == 0) //connection closed
                        {
        	                  log_info("socket %s: %d closed!\n", pconnections[i]->web_ip, pconnections[i]->web_port);
#ifndef WINDOWS
                              close(pconnections[i]->web_socket);
                              close(pconnections[i]->remote_socket);
#else
                              closesocket(pconnections[i]->web_socket);
                              closesocket(pconnections[i]->remote_socket);
#endif
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
                            send_message(pconnections[i]->remote_socket, pconnections[i]->web_buf, length + 8, "remote", pconnections[i]->remote_ip, pconnections[i]->remote_port);
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
#ifndef WINDOWS
                              if(pconnections[i]->web_socket > 0)
        	                  {
        	                      close(pconnections[i]->web_socket);
        	                  }
        	                  close(pconnections[i]->remote_socket);
#else
                              if (pconnections[i]->web_socket > 0)
                              {
                                  closesocket(pconnections[i]->web_socket);
                              }
                              closesocket(pconnections[i]->remote_socket);
#endif
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
                                    int bklen = pconnections[i]->message_buf_len, usedlen, remainlen;
                                    BOOL bHttps = FALSE;
                                    memcpy(pconnections[i]->message_buf + pconnections[i]->message_buf_len,
                                           pconnections[i]->remote_buf + 8, 
                                           min(length, sizeof(pconnections[i]->message_buf) - pconnections[i]->message_buf_len));
                                    pconnections[i]->message_buf_len += min(length, sizeof(pconnections[i]->message_buf) - pconnections[i]->message_buf_len);
                                    
                                    pconnections[i]->message_buf[pconnections[i]->message_buf_len] = 0;
                                    //log_info("start parsing header\n %s\n", pconnections[i]->message_buf);

                                    ret = parse_conn_message(pconnections[i]->message_buf, pconnections[i]->message_buf_len, &webaddr, &bHttps);

                                    //log_info("finish parsing header ret = %d\n", ret);
                                    
                                    if(ret == -1)
                                    {//wrong message clear message buffer.
                                    	log_info("wrong socks message:\n");
                                    	dumpbuffer(pconnections[i]->message_buf, pconnections[i]->message_buf_len, "log_f.txt");
                                        pconnections[i]->message_buf_len = 0;
                                    }
                                    else if(ret > 0) //correct message
                                    {
                                        usedlen   = ret    - bklen;
                                        remainlen = length - usedlen;
                                        web = socket(AF_INET,SOCK_STREAM,0);  
                                        ret = connect(web,(struct sockaddr*)&webaddr,sizeof(webaddr)); 

                                        if(ret != 0) 
                                        { 
                                            log_info("failed to connect to the website: ret = %d,errno = %d, host = %s, port = %d\n", 
                                                       ret, errno, inet_ntoa(webaddr.sin_addr), ntohs(webaddr.sin_port)); 
                                        } 
                                        else
                                        {
                                            log_info("connect to the website: host = %s, port = %d\n", inet_ntoa(webaddr.sin_addr), ntohs(webaddr.sin_port)); 
                                            strcpy(pconnections[i]->web_ip,inet_ntoa(webaddr.sin_addr)); 
                                            pconnections[i]->web_port   = ntohs(webaddr.sin_port); 
                                            pconnections[i]->web_socket = web; 
                                            pconnections[i]->status = CONNECTION_STATUS_CONN;
                                            if (bHttps)
                                            {
                                                char* response = "HTTP/1.1 200 Connection Established\r\n\r\n";
                                                int j = strlen(response);
                                                strcpy(key, "1234");
                                                memcpy(pconnections[i]->web_buf, &j, 4);
                                                memcpy(pconnections[i]->web_buf + 4, key, 4);
                                                memcpy(pconnections[i]->web_buf + 8, response, j);
                                                encrypt_message(pconnections[i]->web_buf + 8, j, key);
                                                send_message(pconnections[i]->remote_socket, pconnections[i]->web_buf, j + 8, "remote", pconnections[i]->remote_ip, pconnections[i]->remote_port);
                                            }
                                            else
                                            {
                                                send_message(pconnections[i]->web_socket, pconnections[i]->message_buf, pconnections[i]->message_buf_len, "web", pconnections[i]->web_ip, pconnections[i]->web_port);
                                            }
                                            if (remainlen > 0)
                                            {
                                                send_message(pconnections[i]->web_socket, pconnections[i]->remote_buf + 8 + usedlen, remainlen, "web", pconnections[i]->web_ip, pconnections[i]->web_port);
                                            }
                                        }
                                        pconnections[i]->message_buf_len = 0;
                                    }
                                    //else ret == 0, waiting for the complete message
                                    //{
                                    //   do nothing here
                                    //}
                                }
                                else //pconnections[i]->status == CONNECTION_STATUS_CONN
                                {
                                    send_message(pconnections[i]->web_socket, pconnections[i]->remote_buf + 8, length, "web", pconnections[i]->web_ip, pconnections[i]->web_port);
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
#ifndef WINDOWS
    close(server);
#else
    closesocket(server);
#endif
    return 0;  
}  
