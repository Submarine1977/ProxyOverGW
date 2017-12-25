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
  
#define PORT 8080  
#define SIZE 1024 
 
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

int main()  
{  
    int ret=0; 
    int i, n;
    int maxsocket;  
    int apa,ser,cli;  
    char buf[SIZE]={0};
    char hostname[1024];
    int  port;
    char apabuf[SIZE]={0};  
    struct pollfd fds[5]={0};  
    struct hostent *host;
    int connected;
    
    struct sockaddr_in apaaddr,seraddr,cliaddr;  
    socklen_t clilen=sizeof(cliaddr);  
  
    seraddr.sin_family=AF_INET;  
    seraddr.sin_addr.s_addr=htonl(INADDR_ANY);  
    seraddr.sin_port=htons(PORT);  
    ser=socket(AF_INET,SOCK_STREAM,0);  
    bind(ser,(struct sockaddr*)&seraddr,sizeof(seraddr));  
    fds[0].fd=ser;  
    fds[0].events=POLLIN;  
    listen(fds[0].fd,5); 

start:    
    memset(buf,0,SIZE);  
    memset(apabuf,0,SIZE);  
    ret=poll(fds,sizeof(fds)/sizeof(fds[0]),-1);  
    if(ret<0)  
    {  
        printf("poll error\n");  
    }  
    if(fds[0].revents&POLLIN)  
    {  
        cli=accept(fds[0].fd,(struct sockaddr*)&cliaddr,&clilen);

        printf("connect to %s:%d\n",inet_ntoa(cliaddr.sin_addr),  
                ntohs(cliaddr.sin_port));
        
        ////////////////////////////////////////////////////
        //get encrypted HTTP Request                      //
        //length      -- 2 bytes, length of content       //
        //encrypt key -- 6 bytes                          //
        //content     -- no more than 1016 bytes          //
        //if length < 1016, the block is the last block.  //
        ////////////////////////////////////////////////////
		    short  length;
		    char   key[7];
		    host = NULL;
        connected = 0;
        
		    while(1)
		    {
			    do
			    { 
            n = 0;
						memset(buf, 0, SIZE);
            while (n < SIZE)
            {
            	i = recv(cli,buf + n,SIZE - n,0);
            	if(i == 0)
            	{
            		printf("connection break %s:%d\n", inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port));
            		close(cli);
            		goto start;
            	}
            	if(i > 0)
            	{
            		n += i;
            	}
            }
				    memcpy(&length, buf, 2);
				    memcpy(key, buf + 2, 6);
				    key[6] = '\0';
				    printf("from %s:%d, length = %d, key = %s\n", inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port), length, key);
				    for(i = 0; i < length; i++)
				    {
				    	buf[i + 8] ^= key[i % 6];
				    }
				    if(host == NULL)
				    {
					    apaaddr.sin_family=AF_INET;  
					    apa=socket(AF_INET,SOCK_STREAM,0);  
	            get_hostname(buf + 8, hostname, &port);
	            host = gethostbyname(hostname);
	            apaaddr.sin_port = htons(port);
	            apaaddr.sin_addr = *((struct in_addr*)host->h_addr);
	            printf("\nhostname = %s, port = %d\n", hostname, port);
	            ret = connect(apa,(struct sockaddr*)&apaaddr,sizeof(apaaddr));
	            if(ret != 0)
	            {
	            	printf("%d,%d\n", ret, errno);
	            }
              connected = 1;
				    }
            send(apa,buf + 8,length,0);
            printf("11111--%s\n", buf + 8);
			    }while(length >= 1016);

          do
          {
						length = 0;
						char *header, *content_length;
						int totallength = 0;
						char *keep_alive;
						memset(apabuf, 0, SIZE);
						do
						{
              printf("2222\n");
							i = recv(apa,apabuf + 8 + length, SIZE - 8 - length, 0);
              printf("3333\n");
							if(i == 0)
							{
								connected = 0;
            		printf("connection break %s:%d\n", hostname, port);
								break;
							}
              length += i;
              printf("2222---%s\n", apabuf + 8);
              
            } while( (header = strstr(apabuf + 8, "\r\n\r\n")) == NULL);
            
            printf("%s\n", apabuf + 8);
            
            keep_alive = strstr(apabuf + 8, "Keep-Alive:");
            
            if(i != 0 && (content_length = strstr(apabuf + 8, "Content-Length:")) != NULL)
            {
            	totallength = header + strlen("\r\n\r\n")- (apabuf + 8) + atoi(content_length + strlen("Content-Length:"));
	          	printf("totallength = %d,length = %d\n", totallength, length);
	            
	            totallength -= length;
	            if(totallength == 0)
	            {
		            printf("from %s:%d, length = %d\n", hostname, port, length);
								memcpy(apabuf, &length, 2);
								strcpy(key, "123456");
							  memcpy(apabuf + 2, key, 6);
						    for(i = 0; i < length; i ++)
						    {
							    apabuf[i + 8] ^= key[i % 6];
						    }
		            send(cli,apabuf,SIZE,0);  
	          		memset(apabuf, 0, SIZE);
	            	length = 0;
	            }
	            while(totallength > 0)
	            {
	            	while(length < 1016)
	            	{
									i = recv(apa,apabuf + 8 + length, SIZE - 8 - length, 0);
									if(i == 0)
									{
								    connected = 0;
										break;
									}
		              length += i;
	            		totallength -= i;
	            		if(totallength <= 0)
	            		{
	            			break;
	            		}
	            	}
		            printf("from %s:%d, length = %d\n", hostname, port, length);
								memcpy(apabuf, &length, 2);
								strcpy(key, "123456");
							  memcpy(apabuf + 2, key, 6);
						    for(i = 0; i < length; i ++)
						    {
							    apabuf[i + 8] ^= key[i % 6];
						    }
		            send(cli,apabuf,SIZE,0);  
	          		memset(apabuf, 0, SIZE);
	            	length = 0;
	            }
	          }
	          else if(strstr(apabuf + 8, "Transfer-Encoding: chunked") != NULL)
	          {
	          	char end[5];
	          	memset(end, sizeof(end), 0);
	          	if(apabuf + length > header + sizeof("\r\n\r\n"))
	          	{
	          		memcpy(end, apabuf + length - 4, 4);
	          	}
	          	while(strcmp(end, "\r\n\r\n") != 0)
	          	{
	            	while(length < 1016)
	            	{
									i = recv(apa,apabuf + 8 + length, SIZE - 8 - length, 0);
									if(i == 0)
									{
										connected = 0;
                    break;
									}
		              length += i;
		              if(length >= 4)
		              {
			          		memcpy(end, apabuf + 8 + length - 4, 4);
		              }
		              else if(length == 3)
		              {
		              	end[0] = end [3];
			          		memcpy(end + 1, apabuf + 8 + length - 3, 3);
		              }
		              else if(length == 2)
		              {
		              	end[0] = end [2];
		              	end[1] = end [3];
			          		memcpy(end + 2, apabuf + 8 + length - 2, 2);
		              }
		              else if(length == 1)
		              {
		              	end[0] = end [1];
		              	end[1] = end [2];
		              	end[2] = end [3];
			          		memcpy(end + 3, apabuf + 8 + length - 1, 1);
		              }
		              if(strcmp(end, "\r\n\r\n") == 0)
		              {
		              	break;
		              }
	            	}
		            printf("from %s:%d, length = %d\n", hostname, port, length);
								memcpy(apabuf, &length, 2);
								strcpy(key, "123456");
							  memcpy(apabuf + 2, key, 6);
							  printf("%s", apabuf+8);
						    for(i = 0; i < length; i ++)
						    {
							    apabuf[i + 8] ^= key[i % 6];
						    }
		            send(cli,apabuf,SIZE,0);  
	          		memset(apabuf, 0, SIZE);
	            	length = 0;
	          	}
	          }
	          else
	          {
	          	if(length != 0)
	          	{
	          		memset(apabuf, 0, SIZE);
		            printf("from %s:%d, length = %d\n", hostname, port, length);
								memcpy(apabuf, &length, 2);
								strcpy(key, "123456");
							  memcpy(apabuf + 2, key, 6);
						    for(i = 0; i < length; i ++)
						    {
							    apabuf[i + 8] ^= key[i % 6];
						    }
		            send(cli,apabuf,SIZE,0);  
	          	}
	          }
	          if(keep_alive == NULL || connected == 0)
	          {
	          	if(connected)
	          	{
	          		close(apa);
	          		connected = 0;
	          	}
	          	host = NULL;
	          }
          }while(connected);
        }
    }  
    return 0;  
}  
