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
  
#define DEBUG            1
#define BUFFER_SIZE      65535
#define MAX_CONNECTION_COUNT 128
 
struct proxy_connection
{
    int  web_socket, remote_socket;
    char web_ip[16], remote_ip[16];
    int  web_port,   remote_port;
    char web_buf[BUFFER_SIZE], remote_buf[BUFFER_SIZE];
    int  web_buf_len, remote_buf_len;
    char http_header[4096];
};
struct proxy_connection *pconnections[MAX_CONNECTION_COUNT];

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

int get_hostname(char* buf,  char *hostname, int *port)
{
	int i = 0;
	*port = 80;
	char *str;
	str = strstr(buf, "Host:");
	str += strlen("Host:");
	while(*str == ' ')
	{
		str ++;
	}
	while(*str != '\r' && *str != '\n')
	{
		hostname[i++] = *str++;
	}
	hostname[i] = '\0';
	
	str = strstr(hostname, ":");
	if(NULL != str)
	{
		*str = '\0';
		*port = atoi(str + 1);
	}
	return 1;
};

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
                            pconnections[i]->http_header[0] = '\0';
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
                        pconnections[i]->web_socket = -1;
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
                        log_info("%s\n", pconnections[i]->web_buf + 8);
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
                            for(j = 0; j < length; j++)
                            {
        	                      pconnections[i]->web_buf[j + 8] ^= key[j % 4];
                            }
                            if(send(pconnections[i]->remote_socket, pconnections[i]->web_buf, length + 8, 0) < 0)
                            {
        	                      log_info("error sending data to %s:%d\n" , pconnections[i]->remote_ip, pconnections[i]->remote_port);
                            }
                        }
                    }
                    if(FD_ISSET(pconnections[i]->remote_socket, &rdfs))
                    {//read from remote, decrypt and then send it to web
                        length = recv(pconnections[i]->remote_socket, pconnections[i]->remote_buf + pconnections[i]->remote_buf_len, BUFFER_SIZE - pconnections[i]->remote_buf_len, 0);
                        if(length < 0)
                        {
                            log_info("error receive data %d\n", i);
                        }
                        else if(length == 0) //connection closed
                        {
        	                  log_info("socket %s, %d closed!\n", pconnections[i]->remote_ip, pconnections[i]->remote_port);
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
                            log_info("%d bytes received from China proxy!\n", length);
                            memcpy(&length, pconnections[i]->remote_buf, 4);
                            log_info("Content length = %d\n", length);
                            while(length + 8 <= pconnections[i]->remote_buf_len)
                            {
                                memcpy(key, pconnections[i]->remote_buf + 4, 4);
                                key[4] = '\0';
                                log_info("Key = %s\n", key);
                                for(j = 0; j < length; j++)
                                {
        	                          pconnections[i]->remote_buf[j + 8] ^= key[j % 4];
                                }
                                
                                log_info("pconnections[%d]->web_socket = %d\n", i, pconnections[i]->web_socket);
                                
                                if(pconnections[i]->web_socket == -1)
                                {//get header
                                    j = 0;
                                    char *str;
                                    str = pconnections[i]->http_header + strlen(pconnections[i]->http_header);
                                    while(str - pconnections[i]->http_header < 4095)
                                    {
                                        *str = pconnections[i]->remote_buf[j + 8];
                                        *(str + 1) = '\0';
                                        str++;
                                        j++;
                                        if(str - pconnections[i]->http_header > 4)
                                        {
                                            if(strncmp(str - 4, "\r\n\r\n", 4) == 0)
                                            {
                                                break;
                                            }
                                        }
                                        if(j >= length)
                                        {
                                            break;
                                        }
                                    }
                                    if(str - pconnections[i]->http_header > 4 && strncmp(str - 4, "\r\n\r\n", 4) == 0)//got the header
                                    {
                                    	  //connect to the web server
                                    	  char hostname[512];
                                    	  int  port;
                                    	  struct hostent *host;
                                    	  
                                    	  log_info("Header = %s\n", pconnections[i]->http_header);
                                    	  
			                                  webaddr.sin_family = AF_INET;  
			                                  web = socket(AF_INET,SOCK_STREAM,0);  
                                        get_hostname(pconnections[i]->http_header, hostname, &port);
                                        host = gethostbyname(hostname);
                                        webaddr.sin_port = htons(port);
                                        webaddr.sin_addr = *((struct in_addr*)host->h_addr);
                                        ret = connect(web,(struct sockaddr*)&webaddr,sizeof(webaddr));
                                        if(ret != 0)
                                        {
                                            log_info("failed to connect to the website: ret = %d,errno = %d\n", ret, errno);
                                            close(pconnections[i]->remote_socket);
                                            free(pconnections[i]);
                                            pconnections[i] = NULL;
                                            break;
                                        }
                                        //send header	
                                        strcpy(pconnections[i]->web_ip,inet_ntoa(webaddr.sin_addr));
                                        pconnections[i]->web_port = ntohs(webaddr.sin_port);
                                        pconnections[i]->web_socket = web;
                                        log_info("Connected to %s:%d\n", pconnections[i]->web_ip, pconnections[i]->web_port);
                                        log_info("header length = %d, str - pconnections[i]->http_header = %d, length =%d, j = %d\n", 
                                                  strlen(pconnections[i]->http_header), str - pconnections[i]->http_header, length, j);                                        
                                        if(send(pconnections[i]->web_socket, pconnections[i]->http_header, str - pconnections[i]->http_header, 0) < 0)
                                        {
        	                                  log_info("error sending data to %s:%d\n" , pconnections[i]->web_ip, pconnections[i]->web_port);
                                        }
                                        //send remaining content
                                        if(send(pconnections[i]->web_socket, pconnections[i]->remote_buf + j, length - j, 0) < 0)
                                        {
        	                                  log_info("error sending data to %s:%d\n" , pconnections[i]->web_ip, pconnections[i]->web_port);
                                        }
                                    }
                                    else //not get the server
                                    {
                                    	  //header buffer is full
                                        if(str - pconnections[i]->http_header > 4095)
                                        {
                                            log_info("error wrong header: %s\n", pconnections[i]->http_header);
                                            close(pconnections[i]->remote_socket);
                                            free(pconnections[i]);
                                            pconnections[i] = NULL;
                                        }
                                    }
                                }
                                else
                                {
                                    if(send(pconnections[i]->web_socket, pconnections[i]->remote_buf, length + 8, 0) < 0)
                                    {
        	                              log_info("error sending data to %s:%d\n" , pconnections[i]->web_ip, pconnections[i]->web_port);
                                    }
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
