/*
Member 1: Sourabh Soumyakanta Das
Roll: 20CS30051
Member 2: Shiladitya De
Roll: 20CS30061
*/

// Includes
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>

#define buf_sz 100
#define data_buf 200
#define res_buf 1500
#define EXT_SZ 50
#define RES_SIZE 1000

/*
Function Name: nullcat
Arguments: destination string (des), source string (src), the pointer from where the writing should begin (init), no. of characters to be copied (len)
It concatenates two strings irrespective of null characters
*/
void nullcat(char *des, char *src, int init, int len)
{
    for(int i = init; i < init + len; i++)
    {
        des[i] = src[i - init];
    }
}
/*
Function Name: get_file_len
Arguments: file address
Returns the content-length of the file
*/
int get_file_len(char *addr) 
{
    FILE *fp = fopen(addr, "r");
    if (fp == NULL)
    {
        printf("File Not Found!\n");
        return -1;
    }
    fseek(fp, 0L, SEEK_END);
    int res = ftell(fp);
    fclose(fp);
    return res;
}

/*
Function Name: Send_content
Arguments: Socket File Descriptor, Address of the file
Sends the content of the file in chunks
*/
void send_content(int newsockfd, char *addr) 
{
    FILE *fp = fopen(addr, "r");
    if (fp == NULL)
    {
        printf("File Not Found!\n");
        return;
    }
    char *buf = (char*)malloc(buf_sz);
    int fd = fileno(fp);
    for(int i = 0; i<buf_sz; i++)buf[i] = '\0';
    int x = 0;
    while ((x = read(fd, buf, buf_sz)) != 0)
    {
        send(newsockfd, buf, x, 0);
        for(int i = 0; i<buf_sz; i++)buf[i] = '\0';
    }
    fclose(fp);
    free(buf);
}

/*
Function Name: recieve file
Arguments: Socket File Descriptor, address of the file, length of the content, array of the content that came with headers, length of this content
Receives the data in chunks and writes them to the file.
*/
int recieve_file(int newsockfd, char *addr, long int len, char *init, int initlen)
{
    FILE *fp = fopen(addr, "w");
    if (fp == NULL)
    {
        printf("File Not Found!\n");
        return -1;
    }
    int fd = fileno(fp);
    write(fd, init, initlen);
    char *buf = (char*)malloc(buf_sz);
    for (int i = 0; i < buf_sz; i++)
        buf[i] = '\0';
    int flg = 2;
    long int fl = 0;
    while (1)
    {
        int y = recv(newsockfd, buf, buf_sz - 1, 0); // receiving data
        if (y == 0)
            break;
        int i = 0;
        write(fd, buf, y); // Write is used to write even null characters which fprintf does not do.
        fl += y;
        if (fl >= len)
            flg = 0;
        if (flg == 0)
            break;
        if (y == 0)
            break;
        for (int i = 0; i < buf_sz; i++)
            buf[i] = '\0';
    }
    close(fd); // Closes file_descriptor
    fclose(fp);
    free(buf);
    return flg;
}

/*
Function Name: recieve
Arguments: Socket File Descriptor, pointer to the receiving array, pointer to where the content starts, size of the content that came with headers
Receives the headers along with some content.
*/
int recieve(int newsockfd, char *str, char *np, int *k)
{
    char *buf = (char*)malloc(buf_sz);
    for (int i = 0; i < buf_sz; i++)
        buf[i] = '\0';
    int flg = 2;
    int tot= 0;
    char *ptr;
    while (1)
    {
        int y = recv(newsockfd, buf, buf_sz - 1, 0); // receiving data
        if (y == 0)
        {
            break;
        }
        int x = tot + y;
        if(x >= res_buf - 2)
        {
            flg = -1;
            break;
        }
        nullcat(str, buf, tot, y);
        tot += y;
        int i = 0;
        int l = strlen(str);
        if (l >= 4)
        {
            char *p = strstr(str, "\r\n\r\n");
            if (p != NULL)
            {
                flg = 0;
                ptr = p+4;
            }
        }
        if (flg == 0)
            break;
        for (int i = 0; i < buf_sz; i++)
            buf[i] = '\0';
    }
    if(flg == -1) return -1;
    *k = tot - (ptr - str);
    memcpy(np, ptr, *k);
    *ptr = '\0';
    free(buf);
    return flg;
}

/*
Function Name: strim
Arguments: string
Trims whitespace characters from beginning and end of the string
*/
char* strim(char* str)  
{
  char *end;
  while(isspace((unsigned char)*str)) str++;
  if(*str == 0)
    return str;
  end = str + strlen(str) - 1;
  while(end > str && isspace((unsigned char)*end)) end--;
  end[1] = '\0';
  return str;
}


int main()
{
	int	sockfd, newsockfd, y;
	int	clilen;
	struct sockaddr_in cli_addr, serv_addr;

	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("Cannot create socket\n");
		exit(0);
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(20000);

	if(bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
	{
		printf("Unable to bind local address\n");
		exit(0);
	}

	listen(sockfd, 5);
	
	while(1)
	{
		clilen = sizeof(cli_addr);
		newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen) ;

		if(newsockfd < 0)
		{
			printf("Accept error\n");
			exit(0);
		}

		if(fork() == 0)	// Forking for concurrency
		{
			close(sockfd);

            // Memory allocation for various strings
            char *method = (char*)malloc(5);
            char *url = (char*)malloc(data_buf);
            char *version = (char*)malloc(data_buf);
            char *type = (char*)malloc(data_buf);
            char *buf = (char*)malloc(res_buf);
            char *time_data = (char*)malloc(data_buf);
            char *data = (char*)malloc(data_buf);
            char *path = (char*)malloc(data_buf);
            char *status_data = (char*)malloc(data_buf);
            char *clen = (char*)malloc(data_buf);
            char *token, *temp_token;
            int status = 200;

            // Initialisation of strings
            strcpy(time_data, "");
            strcpy(type, "");
            strcpy(clen, "");
            strcpy(version, "");
            strcpy(method, "");
            strcpy(url, "");

            for(int i = 0; i<res_buf; i++) buf[i] = '\0';
            char *l = (char*)malloc(RES_SIZE);
            for(int i = 0; i<RES_SIZE; i++) l[i] = '\0';
            int is = 0;
            if(recieve(newsockfd, buf, l, &is) == -1) status = 400;    // Recieving of headers from client
            printf("Request by the client: \n");
            printf("%s", buf);
            char *rest_data = buf;  // Storing it to a different pointer for tokenisation
            
            // Tokenising the request line
            while(token = strtok(rest_data, "\n"))
            {
                if(strstr(token, "\r") == NULL)
                {
                    status = 400;
                    break;
                }
                rest_data = strtok(NULL, "");
                if(token[0] == '\r')
                {
                    status = 400;
                    break;
                }
                token = strtok(token, "\r");
                
                if(temp_token = strtok(token, " ")) strcpy(method, temp_token);
                else
                {
                    status = 400;
                    break;
                }
                if(temp_token = strtok(NULL, " ")) strcpy(url, temp_token);
                else
                {
                    status = 400;
                    break;
                }
                if(temp_token = strtok(NULL, "")) strcpy(version, temp_token);
                else
                {
                    status = 400;
                    break;
                }
                break;
            }

            // Error checking in request line
            if(strcmp(version, "HTTP/1.1") != 0) status = 400;
            if(strcmp(method, "GET") != 0 && strcmp(method, "PUT") != 0) status = 400;

            // Obtaining accept types from url received
            int j = 0;
            char *temp = (char*)malloc(EXT_SZ);
            for(int i = 0; i < EXT_SZ; i++) temp[i] = '\0';
            for (int i = strlen(url)-1; url[i] != '.' && url[i] != '/' && i>=0; i--)
            {
                temp[j++] = url[i];
            }
            temp[j] = '\0';
            char *cont_type = (char*)malloc(EXT_SZ), *temp3 = (char*)malloc(EXT_SZ);
            if (strcmp(temp, "fdp") == 0)
            {
                sprintf(cont_type, "application/pdf");
                sprintf(temp3, "application");
            }
            else if (strcmp(temp, "lmth") == 0)
            {
                sprintf(cont_type, "text/html");
                sprintf(temp3, "text");
            }
            else if ((strcmp(temp, "gepj") == 0) || (strcmp(temp, "gpj") == 0))
            {
                sprintf(cont_type, "image/jpeg");
                sprintf(temp3, "image");
            }
            else
            {
                sprintf(cont_type, "text/*");
                sprintf(temp3, "text");
            }

            // Converting header to lower case for normalisation
            for (int i = 0; i < strlen(rest_data); i++)
                rest_data[i] = (char)tolower(rest_data[i]);
            

            // Header parsing
            if(strstr(rest_data, "\r\n\r\n") != NULL && status == 200)
            {
                while(token = strtok(rest_data, "\n"))
                {
                    rest_data = strtok(NULL, "");
                    if(strstr(token, "\r") == NULL )
                    {
                        status = 400;
                        break;
                    }
                    if(strcmp(token, "\r") == 0) break;
                    if(strstr(token, ":") == NULL)
                    {
                        status = 400;
                        break;
                    }
                    if(token[0] == '\r')
                    {
                        status = 400;
                        break;
                    }
                    token = strtok(token, "\r");
                    if(token[0] == ':')
                    {
                        status = 400;
                        break;
                    }
                    temp_token = strtok(token, ":");

                    char *tg = strim(temp_token);
                    temp_token = tg;

                    if(strcmp(temp_token, "") == 0)
                    {
                        status = 400;
                        break;
                    }
                    else if(strcmp(temp_token, "accept") == 0)
                    {
                        token = strtok(NULL, "");
                        if(token != NULL)
                        {
                            char *th = strim(token);
                            token = th;
                            if(strcmp(token, "") != 0) strcpy(type, token);
                        }
                    }
                    else if(strcmp(temp_token, "if-modified-since") == 0)
                    {
                        token = strtok(NULL, "");
                        if(token != NULL)
                        {
                            char *tp = strim(token);
                            token = tp;
                            if(strcmp(token, "") != 0) strcpy(time_data, token);
                        }
                    }
                    else if(strcmp(temp_token, "content-length") == 0)
                    {
                        token = strtok(NULL, "");
                        if(token != NULL)
                        {
                            char *tn = strim(token);
                            token = tn;
                            if(strcmp(token, "") == 0)
                            {
                                status = 400;
                                break;
                            }
                            strcpy(clen, token);
                        }
                        else
                        {
                            status = 400;
                            break;
                        }
                    }
                }
            }
            else status = 400;

            // Accept type comparison for syntax checking
            if(strcmp(method, "PUT") == 0 && strcmp(clen, "") == 0) status = 400;
            if(strcmp(type, "") == 0) strcpy(type, cont_type);
            else{
                char *temp4 = (char*)malloc(EXT_SZ);
                strcpy(temp4, type);
                char *tok2, *tok3;
                tok2 = strtok(temp4, "/");
                tok3 = strtok(NULL, "");
                if(strcmp(tok3, "*") == 0){
                    if(strcmp(tok2, "*") != 0 && strcmp(temp3, tok2) != 0) status = 400;
                    else strcpy(type, cont_type);
                }
                else{
                    if(strcmp(cont_type, type) != 0) status = 400;
                }
                free(temp4);
            }

            // Obtaining file path from url and checking for 404 errors
            getcwd(path, data_buf);
            strcat(path, url);
            if(strcmp(method, "GET") == 0)
            {
                FILE *fp = fopen(path, "r");
                if(fp == NULL) status = 404;
                else fclose(fp);
            }

            // If-Modified-Since and file Last-Modified comparison for setting errors
            if(status != 404 && status != 400 && strcmp(time_data, "") != 0 && strcmp(method, "GET") == 0)
            {
                struct stat attr;
                stat(path, &attr);
                struct tm* tm1 = localtime(&attr.st_mtime);
                struct tm* tm2 = (struct tm*)malloc(sizeof(struct tm));
                int year;
                char* day = (char*)malloc(4);
                char* mon = (char*)malloc(4);
                if(sscanf(time_data, " %s %d %s %d %d:%d:%d GMT",
                    day, &tm2->tm_mday, mon, &year, &tm2->tm_hour, &tm2->tm_min, &tm2->tm_sec) != 7) status = 400;
                
                if(strcmp(day, "sun,") != 0 && strcmp(day, "mon,") != 0 && strcmp(day, "tue,") != 0 && strcmp(day, "wed,") != 0
                && strcmp(day, "thu,") != 0 && strcmp(day, "fri,") != 0 && strcmp(day, "sat,") != 0) status = 400;

                if(strcmp(mon, "jan") == 0) tm2->tm_mon = 0;
                else if(strcmp(mon, "feb") == 0) tm2->tm_mon = 1;
                else if(strcmp(mon, "mar") == 0) tm2->tm_mon = 2;
                else if(strcmp(mon, "apr") == 0) tm2->tm_mon = 3;
                else if(strcmp(mon, "may") == 0) tm2->tm_mon = 4;
                else if(strcmp(mon, "jun") == 0) tm2->tm_mon = 5;
                else if(strcmp(mon, "jul") == 0) tm2->tm_mon = 6;
                else if(strcmp(mon, "aug") == 0) tm2->tm_mon = 7;
                else if(strcmp(mon, "sep") == 0) tm2->tm_mon = 8;
                else if(strcmp(mon, "oct") == 0) tm2->tm_mon = 9;
                else if(strcmp(mon, "nov") == 0) tm2->tm_mon = 10;
                else if(strcmp(mon, "dec") == 0) tm2->tm_mon = 11;
                else status = 400;
                free(day);
                free(mon);
                tm2->tm_year = year - 1900;
                time_t t1 = mktime(tm1);
                time_t t2 = mktime(tm2);
                if(status != 400 && difftime(t2, t1) > 0) status = 403;
                free(tm2);
            }

            switch(status)
            {
                case 200: strcpy(status_data, "OK"); break;
                case 400: strcpy(status_data, "Bad Request"); break;
                case 403: strcpy(status_data, "Forbidden"); break;
                case 404: strcpy(status_data, "Not Found"); break;
            }

            // Recieving file content if valid
            if(strcmp(method, "PUT") == 0 && status == 200)
            {
                FILE *fp = fopen(path, "w");
                if(fp == NULL) status = 403;
                fclose(fp);
                if(status == 200)
                    recieve_file(newsockfd, path ,atoi(clen)-is, l, is);
            }

            // Sending response header to client
            printf("Response to the client: \n");
            sprintf(buf, "%s %d %s\r\n", "HTTP/1.1", status, status_data);
            printf("%s %d %s\n", "HTTP/1.1", status, status_data);
            send(newsockfd, buf, strlen(buf), 0);
            if(strcmp(method, "GET") == 0 && status == 200)
            {
                time_t ct = time(0);
                struct tm *t = gmtime(&ct);
                t->tm_mday += 3;
                mktime(t);
                strftime(time_data, data_buf, "%a, %d %b %G %T GMT", t);
                sprintf(buf, "expires: %s\r\n", time_data);
                printf("expires: %s\n", time_data);
                send(newsockfd, buf, strlen(buf), 0);
                sprintf(buf, "cache-control: no-store\r\n");
                printf("cache-control: no-store\n");
                send(newsockfd, buf, strlen(buf), 0);
                sprintf(buf, "content-language: en-us\r\n");
                printf("content-language: en-us\n");
                send(newsockfd, buf, strlen(buf), 0);
                sprintf(buf, "content-length: %d\r\n", get_file_len(path));
                printf("content-length: %d\n", get_file_len(path));
                send(newsockfd, buf, strlen(buf), 0);
                sprintf(buf, "content-type: %s\r\n", type);
                printf("content-type: %s\n", type);
                send(newsockfd, buf, strlen(buf), 0);
                if(status != 404)
                {
                    struct stat attr;
                    stat(path, &attr);
                    t = localtime(&attr.st_mtime);
                    strftime(time_data, data_buf, "%a, %d %b %G %T GMT", t);
                }
                else strcpy(time_data, "");
                sprintf(buf, "last-modified: %s\r\n", time_data);
                printf("last-modified: %s\n", time_data);
                send(newsockfd, buf, strlen(buf), 0);
            }
            sprintf(buf, "\r\n");
            printf("\n");
            send(newsockfd, buf, strlen(buf), 0);

            // Sending requested file content if valid
            if(strcmp(method, "GET") == 0 && status == 200) send_content(newsockfd, path);

            // Access Log file maintenance for client communication
            FILE *fp = fopen("AccessLog.txt", "a");
            if(fp == NULL)
            {
                printf("Can't open file AccessLog.txt\n");
            }
            else
            {
                time_t ct = time(0);
                struct tm *t = localtime(&ct);
                fprintf(fp, "%02d%02d%02d:%02d%02d%02d:%s:%d:%s:%s\n",
                    t->tm_mday, t->tm_mon + 1, t->tm_year - 100, t->tm_hour, t->tm_min, t->tm_sec, inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port), method, url);
                fclose(fp);
            }

            // Freeing all the allocated memory
            free(method);
            free(url);
            free(version);
            free(type);
            free(time_data);
            free(path);
            free(status_data);
            free(cont_type);
            free(temp3);
            free(data);
            free(clen);
            free(buf);
            free(temp);
			close(newsockfd);
			exit(0);
		}

		close(newsockfd);
	}
	return 0;
}