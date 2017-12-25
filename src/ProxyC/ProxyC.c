#include<stdio.h>  
#include<poll.h>  
#include<netdb.h>
#include<sys/types.h>  
#include<sys/socket.h>  
#include<arpa/inet.h>  
#include<unistd.h>  
#include<string.h>  
#include<errno.h>

  
#define ADDR "192.168.32.144"  
#define PORT 8080  

#define ADDR_APACHE "18.216.47.167"  
#define PORT_APACHE 8080
#define SIZE 1024
  
int main()  
{  
	  int i, n;
    int ret=0;  
    int length;
    char key[7];
    int maxsocket;
    int apa,ser,cli;  
    char buf[SIZE]={0};  
    char apabuf[SIZE]={0};  
    struct pollfd fds[5]={0};  
    struct sockaddr_in apaaddr,seraddr,cliaddr;  
    socklen_t clilen=sizeof(cliaddr);  
  
    apaaddr.sin_family=AF_INET;  
    apaaddr.sin_addr.s_addr=inet_addr(ADDR_APACHE);  
    apaaddr.sin_port=htons(PORT_APACHE);  
  
    seraddr.sin_family=AF_INET;  
    seraddr.sin_addr.s_addr=inet_addr(ADDR);  
    seraddr.sin_port=htons(PORT);  
  
start:  
    apa=socket(AF_INET,SOCK_STREAM,0);  
    printf("Connecting to foreign proxy server %s:%d... \n", ADDR_APACHE, PORT_APACHE);
    ret = connect(apa,(struct sockaddr*)&apaaddr,sizeof(apaaddr));  
    while (ret < 0)
    {
    	printf("Connecting failed, errno = %d, try again 5 seconds later.\n", errno);
    	sleep(5);
	    ret = connect(apa,(struct sockaddr*)&apaaddr,sizeof(apaaddr));  
    }


    ser=socket(AF_INET,SOCK_STREAM,0);  
    bind(ser,(struct sockaddr*)&seraddr,sizeof(seraddr));  
    fds[0].fd=ser;  
    fds[0].events=POLLIN;
    ret = listen(fds[0].fd,5);  
    if(ret < 0)
    {
    	printf("Failed to listen on %s:%d errno=%d\n", ADDR, PORT, errno);
    	return 1;
    }
    printf("Listening ... \n");

    while(1)  
    {  
        memset(buf,0,SIZE);  
        memset(apabuf,0,SIZE);  
        ret=poll(fds,sizeof(fds)/sizeof(fds[0]),-1);  
        if(ret<0)  
        {  
            printf("poll error\n");  
            break;  
        }  
        if(fds[0].revents&POLLIN)  
        {  
            cli=accept(fds[0].fd,(struct sockaddr*)&cliaddr,&clilen);
            if( -1 == cli) 
            {
            	continue;
            }
            printf("connect to %s:%d\n",inet_ntoa(cliaddr.sin_addr),  
                    ntohs(cliaddr.sin_port));  
            
            i = recv(cli,buf + 8 ,SIZE - 8, 0);

            if(i < 0) //error
            {
            	printf("error receive data %d\n", i);
            	continue;
            }
            else if(i == 0) // connection break
            {
            	printf("socket %s, %d closed!\n", inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port));
            	continue;
            }
            
            length = i;
            printf("%d bytes received\n", length);
            printf("%s\n", buf + 8);
    
            strcpy(key, "abcdef");        
            memcpy(buf, &length, 2);
            memcpy(buf + 2, key, 6);
            for(i = 0; i < length; i++)
            {
            	buf[i + 8] ^= key[i % 6];
            }
            if(send(apa,buf,SIZE,0) < 0)
            {
            	printf("error sending data to %s:%d\n" , ADDR_APACHE, PORT_APACHE);
            }
            
            do
            {
	            n = 0;
							memset(apabuf, 0, SIZE);
	            while (n < SIZE)
	            {
	            	i = recv(apa,apabuf + n,SIZE - n, 0);
	            	if(i == 0)
	            	{
	            		printf("connection break %s:%d\n", ADDR_APACHE, PORT_APACHE);
	            		close(cli);
	            		goto start;
	            	}
	            	if(i > 0)
	            	{
	            		n += i;
	            	}
	            }
	     
	            memcpy(&length, apabuf, 2);
	            memcpy(key, apabuf + 2, 6);
	            printf("length = %d, key = %s\n", length, key);
	            for(i = 0; i < length; i++)
	            {
	            	apabuf[i + 8] ^= key[i % 6];
	            	printf("%c", apabuf[i + 8]);
	            }
	            if(send(cli,apabuf + 8, length, 0) < 0)
	            {
	            	printf("error senting content to %s:%d", inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port));
	            }
	          }while(length == SIZE - 8);
        }  
    }
    close(apa);
    printf("Exited! \n");
    return 0;  
}  
