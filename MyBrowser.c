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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <time.h>
#include <sys/poll.h>
#include <sys/wait.h>
#define MAX_SIZE 250
#define DIR_SIZE 500
#define RES_SIZE 1000
#define MSG_SZ 100
#define SEND_SZ 5000
#define MAX_FL_SZ 10000
#define TIMEOUT 3000

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
long int get_file_len(char *addr)
{
    FILE *fp = fopen(addr, "r");

    if (fp == NULL)
    {
        printf("File Not Found!\n");
        return -1;
    }

    fseek(fp, 0L, SEEK_END);

    long int res = ftell(fp);

    fclose(fp);
    return res;
}

/*
Function name: get_file_name
Arguments: Address Breadcrumb
Returns just the file name (i.e. /home/docs/a1.pdf gives a1.pdf)
*/

char *get_file_name(char *addr)
{
    char *token, *res;
    token = strtok(addr, "/");
    while (token != NULL)
    {
        if (token != NULL)
        {
            res = token;
            token = strtok(NULL, "/");
        }
    }
    return res;
}

/*
Function Name: send_serv
Arguments: Socket File Descriptor, message
It sends the Message request to the server in chunks 
*/
void send_serv(int newsockfd, char *str)
{
    int ptr = 0, flg = 0;
    int end_ptr = strlen(str);
    char *msg = (char*)malloc(MSG_SZ);
    int cnt = 0;
    while (1)
    {
        cnt = 0;
        for (int i = 0; i < MSG_SZ; i++)
        {
            if (str[i + ptr] == '\0')
            {
                flg = 1;
                break;
            }
            msg[i] = str[i + ptr];
            cnt++;
        }

        ptr += cnt;
        send(newsockfd, msg, cnt, 0);
        if (flg == 1)
            break;
    }
    free(msg);
}

/*
Function Name: recieve
Arguments: Socket File Descriptor, pointer to the receiving array, pointer to where the content starts, size of the content that came with headers
Receives the headers along with some content.
*/
int recieve(int newsockfd, char *str, char *np, int *k)
{
    char *buf = (char*)malloc(MSG_SZ);
    for (int i = 0; i < MSG_SZ; i++)
        buf[i] = '\0';
    int flg = 2;
    int tot= 0;
    char *ptr;
    while (1)
    {
        int y = recv(newsockfd, buf, MSG_SZ - 1, 0); // receiving data
        if (y == 0)
        {
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
                *p = '\0';
            }
        }
        if (flg == 0)
            break;
        for (int i = 0; i < MSG_SZ; i++)
            buf[i] = '\0';
    }
    *k = tot - strlen(str) - 4;
    memcpy(np, ptr, *k);
    free(buf);
    return flg;
}

/*Function Name: response_parse
Arguments: result array for storing the headers, pointer to content length to store the content length
Parses the headers and returns the status
*/
int response_parse(char *res, long int *conlen)
{
    for (int i = 0; i < strlen(res); i++)
        res[i] = (char)tolower(res[i]);
    char *token1, *token2;
    token1 = strtok(res, "\n");
    token2 = strtok(NULL, "\n");
    long int clen = 0;
    while (token2 != NULL)
    {
        if (strncmp(token2, "content-length:", 15) == 0)
        {
            sscanf(token2 + 15, "%ld", &clen);
            break;
        }
        token2 = strtok(NULL, "\n");
    }

    char *token;
    token = strtok(token1, " ");
    token = strtok(NULL, " ");
    int stat = atoi(token);
    *conlen = clen;
    return stat;
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
    char *buf = (char*)malloc(MSG_SZ);
    for (int i = 0; i < MSG_SZ; i++)
        buf[i] = '\0';
    int flg = 2;
    long int fl = 0;
    while (1)
    {
        int y = recv(newsockfd, buf, MSG_SZ - 1, 0); // receiving data
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
        for (int i = 0; i < MSG_SZ; i++)
            buf[i] = '\0';
    }
    close(fd); // Closes file_descriptor
    fclose(fp);
    free(buf);
    return flg;
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
    char *buf = (char*)malloc(MSG_SZ);
    int fd = fileno(fp);
    for(int i = 0; i<MSG_SZ; i++)buf[i] = '\0';
    int x = 0;
    while ((x = read(fd, buf, MSG_SZ)) != 0) // Read is used to take care of null characters
    {
        send(newsockfd, buf, x, 0);
        for(int i = 0; i<MSG_SZ; i++)buf[i] = '\0';
    }
    close(fd); // closing the file descriptors
    fclose(fp);
    free(buf);
}

int main()
{
    char *input = (char *)malloc(MAX_SIZE * sizeof(char)); // For taking input
    while (1)
    {
        fflush(stdin);
        char** tokens = (char**)malloc(4*sizeof(char*));
        for(int i = 0; i < 4; i++) tokens[i] = (char*)malloc(200);
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 200; j++)
            {
                tokens[i][j] = '\0';
            }
        }
        for (int i = 0; i < MAX_SIZE; i++) input[i] = '\0';
        printf("MyOwnBrowser > ");
        fgets(input, MAX_SIZE, stdin); // Taking the input
        if(input[0] == '\n') // If user accidentally presses enter
        {
            continue;
        }
        input[strlen(input) - 1] = '\0';
        if (strcmp(input, "exit") == 0) // If exit is pressed 
            exit(0);
        char *token1 = NULL, *token2 = NULL, *token3 = NULL, *token4 = NULL, *token;
        int c = 0;
        // Tokenizations to get the method, files, address breadcrumb, protocol, IP, port
        token1 = strtok(input, " ");
        token2 = strtok(NULL, " ");
        token3 = strtok(NULL, " ");
        token = strtok(token2, "/");
        sprintf(tokens[0], "%s", token);
        token = strtok(NULL, ":");
        token4 = strtok(NULL, "");
        if(token4) sprintf(tokens[3], "%s", token4);
        else strcpy(tokens[3], "");
        token = strtok(token, "/");
        sprintf(tokens[1], "%s", token);
        if(token = strtok(NULL, "")) sprintf(tokens[2], "%s", token);
        else strcpy(tokens[2], "");

        // Error Handlings:
        if(tokens[2][strlen(tokens[2]) - 1] == '/')tokens[2][strlen(tokens[2]) - 1] = '\0';
        if ((strcmp(token1, "GET") != 0) && (strcmp(token1, "PUT") != 0))
        {
            printf("Error in method specified\n");
            continue;
        }

        if ((strcmp(token1, "PUT") == 0) && (token3 == NULL))
        {
            printf("PUT method has no files supplied\n");
            continue;
        }

        if (strcmp(tokens[0], "http:") != 0)
        {
            printf("The protocol is not http\n");
            continue;
        }

        // Establishing Connections
        int sockfd;
        struct sockaddr_in serv_addr;
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            perror("Unable to create socket\n");
            exit(0);
        }

        serv_addr.sin_family = AF_INET;
        inet_aton(tokens[1], &serv_addr.sin_addr);
        if (strlen(tokens[3]) == 0)
            sprintf(tokens[3], "80");
        serv_addr.sin_port = htons(atoi(tokens[3]));

        if ((connect(sockfd, (struct sockaddr *)&serv_addr,
                     sizeof(serv_addr))) < 0)
        {
            perror("Unable to connect to server\n");
            exit(0);
        }
        struct pollfd pfd[1]; // For poll
        pfd[0].fd = sockfd;
        pfd[0].events = POLLIN;

        int cmd = 0;
        if (strcmp(token1, "PUT") == 0) // cmd = 0 if GET else 1 for PUT
            cmd = 1;

        char temp[5];
        char *tok2 = (char*)malloc(DIR_SIZE);
        tok2[0] = '/';
        for (int i = 1; i < DIR_SIZE; i++)
            tok2[i] = '\0';
        strcat(tok2, tokens[2]);
        if (cmd)
        {
            char temp2[strlen(token3)];
            strcpy(temp2, token3);
            if (strcmp(token1, "PUT") == 0)
            {
                strcat(tok2, "/");
                strcat(tok2, get_file_name(temp2));
            }
        }
        int j = 0;
        if (!cmd) // Getting the file type
        {
            for (int i = strlen(tok2) - 1; tok2[i] != '.' && tok2[i] != '/'; i--)
            {
                temp[j++] = tok2[i];
            }
            temp[j] = '\0';
        }
        else
        {
            for (int i = strlen(token3) - 1; token3[i] != '.' && i >= 0; i--)
            {
                temp[j++] = token3[i];
            }
            temp[j] = '\0';
        }
        char *cont_type = (char*)malloc(DIR_SIZE);
        if (strcmp(temp, "fdp") == 0) // Setting up the file type
            sprintf(cont_type, "application/pdf");
        else if (strcmp(temp, "lmth") == 0)
            sprintf(cont_type, "text/html");
        else if ((strcmp(temp, "gepj") == 0) || (strcmp(temp, "gpj") == 0))
            sprintf(cont_type, "image/jpeg");
        else
            sprintf(cont_type, "text/*");

        time_t ct = time(0); // Getting the current time
        struct tm *t = gmtime(&ct);
        mktime(t);
        char *pre_day = (char*)malloc(MAX_SIZE), *ims = (char*)malloc(MAX_SIZE); // pre_day is present day, ims is if modifies since date
        strftime(pre_day, MAX_SIZE, "%a, %d %b %G %T GMT", t);
        t->tm_mday -= 2;
        mktime(t);
        strftime(ims, MAX_SIZE, "%a, %d %b %G %T GMT", t);

        long int cont_len = 0;
        if (cmd)
        {
            cont_len = get_file_len(token3); // Getting content length in case of PUT
        }
        if(tok2[0] == '/' && tok2[1] == '/'){  // Some degenerate cases (like if / is there then the address breadcrumb will have // so removing /)
            char *tok3 = (char*)malloc(DIR_SIZE);
            for(int i = 0; i<DIR_SIZE; i++)tok3[i] = '\0';
            strcat(tok3, tok2+1);
            strcpy(tok2, tok3);
            free(tok3);
        }
        char *send_file = (char *)malloc(SEND_SZ * sizeof(char));
        if (!cmd)
        {
            // Packing the requests in a string
            sprintf(send_file, "GET %s HTTP/1.1\r\n", tok2);
            sprintf(send_file + strlen(send_file), "host: %s:%s\r\n", tokens[1], tokens[3]);
            sprintf(send_file + strlen(send_file), "connection: close\r\n");
            sprintf(send_file + strlen(send_file), "date: %s\r\n", pre_day);
            sprintf(send_file + strlen(send_file), "accept: %s\r\n", cont_type);
            sprintf(send_file + strlen(send_file), "accept-language: en-us, en\r\n");
            sprintf(send_file + strlen(send_file), "if-modified-since: %s\r\n", ims);
            sprintf(send_file + strlen(send_file), "\r\n");
        }

        else
        {
            sprintf(send_file, "PUT %s HTTP/1.1\r\n", tok2);
            sprintf(send_file + strlen(send_file), "host: %s:%s\r\n", tokens[1], tokens[3]);
            sprintf(send_file + strlen(send_file), "connection: close\r\n");
            sprintf(send_file + strlen(send_file), "date: %s\r\n", pre_day);
            sprintf(send_file + strlen(send_file), "content-language: en-us\r\n");
            sprintf(send_file + strlen(send_file), "content-length: %ld\r\n", cont_len);
            sprintf(send_file + strlen(send_file), "content-type: %s\r\n", cont_type);
            sprintf(send_file + strlen(send_file), "\r\n");
        }
        printf("Request: \n%s", send_file);
        send_serv(sockfd, send_file); // Sending the request
        if (cmd)
        {
            send_content(sockfd, token3); // Sending content if method is "PUT"
        }
        int flg = 0;
        char *msg = (char*)malloc(RES_SIZE);
        int ret = poll(pfd, 1, TIMEOUT); // polls TIMEOUT 3000
        if (ret < 0)
        { // If ret < 0 poll failed
            perror("Poll Failed\n");
            close(sockfd);
            exit(1);
        }
        else if (ret == 0) // If ret == 0 timeout
        {
            close(sockfd);
            continue;
        }
        char *l = (char*)malloc(RES_SIZE);
        for(int i = 0; i<RES_SIZE; i++) l[i] = '\0';
        int is = 0;
        flg = recieve(sockfd, msg, l, &is); // Receiving the response
        printf("Response: \n%s\n", msg); 
        int status = 500;
        long int conlen = -1;
        status = response_parse(msg, &conlen); // Parsing the response
        if ((conlen <= 0) && (strcmp(token1, "GET") == 0) && status < 300)
        {
            printf("Invalid content length\n");
            close(sockfd);
            continue;
        }
        conlen -= is; // subtracting the already arrived content's length
        if (((status == 200) || (status == 201)))
        {
            if(!cmd)
            {
                char addr[100];
                char *fname = get_file_name(tokens[2]);  // For receiving the content
                sprintf(addr, "%s", fname);
                int r = poll(pfd, 1, TIMEOUT);
                if (r < 0)
                { // If r < 0 poll failed
                    perror("Poll Failed\n");
                    close(sockfd);
                    exit(1);
                }
                else if (r == 0) // If r == 0 timeout
                {
                    close(sockfd);
                    continue;
                }
                flg = recieve_file(sockfd, addr, conlen, l, is);
                if (fork() == 0) // Once file is received file  it is opened
                {
                    if (strcmp(temp, "fdp") == 0)
                    {
                        char *args[] = {"xdg-open", fname, NULL};
                        execvp("xdg-open", args);
                    }
                    else if (strcmp(temp, "lmth") == 0)
                    {
                        char *args[] = {"firefox", fname, NULL};
                        execvp("firefox", args);
                    }
                    else if ((strcmp(temp, "gepj") == 0) || (strcmp(temp, "gpj") == 0))
                    {
                        char *args[] = {"xdg-open", fname, NULL};
                        execvp("xdg-open", args);
                    }
                    else
                    {
                        char *args[] = {"gedit", fname, NULL};
                        execvp("gedit", args);
                    }
                    exit(0);
                }
                wait(NULL);
            }
            
        }
        // Printing the error status
        else if (status == 400)
        {
            printf("400 : Bad Request\n");
        }
        else if (status == 403)
        {
            printf("403 : Forbidden\n");
        }
        else if (status == 404)
        {
            printf("404 : Not Found\n");
        }
        else
        {
            printf("%d : Unknown Error\n", status);
        }
        close(sockfd); // Closing the connection
        free(send_file); // freeing memory
        free(tok2);
        free(cont_type);
        free(pre_day);
        free(ims);
        free(msg);
        free(l);
        for(int i = 0; i < 4; i++) free(tokens[i]);
        free(tokens);
        printf("\n");
    }
    free(input); // freeing input
    return 0;
}
