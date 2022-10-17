// The 'client.c' code goes here.
#include<stdio.h>
#include<unistd.h>
#include "Md5.c"  // Feel free to include any other .c files that you need in the 'Client Domain'.
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>

#define BUF_SIZE 1024
#define MaxLine 1024

typedef struct client { 
    int fd;
    char buf[BUF_SIZE];
    int nbuf;
    int stop;
} client_t;

// struct dirent *readdir(DIR *dirp);
/* Cite from textbook Computer System: A Programmers Perspective, page 941*/
struct dirent2 {
ino_t d_ino; /* inode number */
char d_name[256]; /* Filename */
};

/* Cite from textbook Computer System: A Programmers Perspective, page 1021*/
struct addrinfo2 {
int ai_flags; /* Hints argument flags */
int ai_family; /* First arg to socket function */
int ai_socktype; /* Second arg to socket function */
int ai_protocol; /* Third arg to socket function */
char *ai_canonname; /* Canonical hostname */
size_t ai_addrlen; /* Size of ai_addr struct */
struct sockaddr *ai_addr; /* Ptr to socket address structure */
struct addrinfo *ai_next; /* Ptr to next item in linked list */
};

/* Cite from textbook Computer System: A Programmers Perspective, page 1021*/
typedef struct {
int *buf; /* Buffer array */
int n; /* Maximum number of slots */
int front; /* buf[(front+1)%n] is first item */
int rear; /* buf[rear%n] is last item */
int mutex; /* Protects accesses to buf */
int slots; /* Counts available slots */
int items; /* Counts available items */
} sbuf_t;


/* Cite from textbook Computer System: A Programmers Perspective, page 969*/
/* IP socket address structure */
struct sockaddr_in2 {
uint16_t sin_family; /* Protocol family (always AF_INET) */
uint16_t sin_port; /* Port number in network byte order */
struct in_addr sin_addr; /* IP address in network byte order */
unsigned char sin_zero[8]; /* Pad to sizeof(struct sockaddr) */
};
/* Generic socket address structure (for connect, bind, and accept) */
struct sockaddr2 {
uint16_t sa_family; /* Protocol family */
char sa_data[14]; /* Address data */
};

/* Cite from textbook Computer System: A Programmers Perspective, page 935*/
int writen2(int fd, const char *usrbuf, int n) { 
    int nleft = n;
    int nwritten;
    const char *bufp = usrbuf;
    while (nleft > 0) {
        nwritten = write(fd, bufp, nleft);
        if (nwritten <= 0) {
            if (errno == EINTR)
                nwritten = 0;
            else
                return -1;
        }
        nleft -= nwritten;
        bufp += nwritten;
    }
    if (nleft == 0)
        return n;
    else
        return n - nleft; // nleft now zero
}

int readn(int fd, char *buf, int len) {
    int nleft = len;
    int nread;
    char *ptr = buf;
    while (nleft > 0) {
        if ((nread = read(fd, ptr, nleft)) < 0) {
            if (errno == EINTR)
                nread = 0;
            else
                return -1;
        } else if (nread == 0)
            break;
        nleft -= nread;
        ptr += nread;
    }
    return len - nleft;
}


/* Cite from textbook Computer System: A Programmers Perspective, page 935*/
int read2(int fd, char *usrbuf, int n) {
    int nleft = n;
    char* bufp = usrbuf;
    nleft = read(fd, bufp, nleft);
    while (nleft < 0) {
        if (errno == EINTR){
            continue;
        }else{
            return -1;
        }
    }
    return nleft;
}

int read_line(client_t* client, char *command) {
    int i;
    int nread;
    int check = 1;
    int nbuf;
    while (check) {
        i = 0;
        nbuf = client->nbuf;
        while (i < nbuf && client->buf[i] != '\n'){
            i++;
        }
        if (i == client->nbuf) {
            nread = read2(client->fd, client->buf + client->nbuf, BUF_SIZE - client->nbuf);
            if (nread <= 0) {
                return nread;
            }
            client->nbuf += nread;
        } else {
            memcpy(command, client->buf, i+1);
            command[i+1] = '\0';
            client->nbuf -= i + 1;
            if (client->nbuf > 0) {
                memmove(client->buf, client->buf + i + 1, client->nbuf);
            }
            break;
        }
    }
    return 1;
}

int read_int(client_t* client, unsigned int *num) {
    int nread = 0;
    while (client->nbuf < 4) {
        nread = read2(client->fd, client->buf + client->nbuf, BUF_SIZE - client->nbuf);
        if (nread <= 0) {
            return nread;
        }
        client->nbuf += nread;
    }

    memcpy(num, client->buf, 4);
    client->nbuf -= 4;
    if (client->nbuf > 0) {
        memmove(client->buf, client->buf + 4, client->nbuf);
    }
    *num = ntohl(*num);
    return 1;
}

int read_bytes(client_t* client, unsigned char* bytes, int len) {
    int nread = 0;
    while (client->nbuf < len) {
        nread = read2(client->fd, client->buf + client->nbuf, BUF_SIZE - client->nbuf);
        if (nread <= 0) {
            return nread;
        }
        client->nbuf += nread;
    }
    memcpy(bytes, client->buf, len);
    client->nbuf -= len;
    if (client->nbuf > 0) {
        memmove(client->buf, client->buf + len, client->nbuf);
    }
    return 1;
}

int download(client_t* client, char* filename) {
    char msg[BUF_SIZE];
    int ret = read_line(client, msg);
    if (strncmp(msg, "OK\n", strlen("OK\n")) != 0) {
        printf("%s", msg);
        return 1;
    }
    char path[BUF_SIZE];
    snprintf(path, BUF_SIZE, "%s/%s", "Local Directory", filename);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC);
    unsigned int size = 0;
    read_int(client, &size);

    int nwrite;
    unsigned int size_bytes = size;
    while (size > 0) {
        if (client->nbuf > 0) {
            nwrite = size > client->nbuf ? client->nbuf : size;
            writen2(fd, client->buf, nwrite);
            if (nwrite < client->nbuf) {
                memmove(client->buf, client->buf + nwrite, client->nbuf - nwrite);
            }
            size -= nwrite;
            client->nbuf -= nwrite;
        }
        if (size > 0) {
            int nread = size > BUF_SIZE - client->nbuf ? BUF_SIZE - client->nbuf : size;
            int n = read(client->fd, client->buf + client->nbuf, nread);
            client->nbuf += n;
        }
    }
    printf("%u bytes downloaded successfully.\n", size_bytes);
    return 1;
}

int upload(client_t* client, char* filename, char* line) {
    char path[BUF_SIZE];
    snprintf(path, BUF_SIZE, "%s/%s", "Local Directory", filename);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("File [%s] could not be found in local directory.\n", filename);
        return 1;
    }
    writen2(client->fd, line, strlen(line));

    char msg[BUF_SIZE];
    read_line(client, msg);
    struct stat st;
    fstat(fd, &st);
    unsigned int size = htonl(st.st_size);
    writen2(client->fd, (char*)&size, 4);
    int nread;
    while ((nread = read(fd, msg, BUF_SIZE)) > 0) {
        writen2(client->fd, msg, nread);
    }
    printf("%lld bytes uploaded successfully.\n", st.st_size);
    return 1;
}

int delete2(client_t* client, const char* filename) {
    char msg[BUF_SIZE];
    read_line(client, msg);
    if (strncmp(msg, "OK\n", strlen("OK\n")) != 0) {
        printf("%s", msg);
        return 1;
    }
    printf("File deleted successfully.\n");
    return 1;
}

int append(client_t* client, const char* filename, FILE* fp) {
    char msg[BUF_SIZE];
    int ret = read_line(client, msg);
    if (strncmp(msg, "OK\n", strlen("OK\n")) != 0) {
        printf("%s", msg);
        return 1;
    }
    int check = 0;
    while (!check) {
        printf("Appending> "); fflush(stdout);
        fgets(msg, BUF_SIZE, fp);
        printf("%s", msg);
        if (strncmp(msg, "pause", 5) == 0) {
            int num = atoi(msg + 5);
            sleep(num);
            continue;
        } else {
            if (strcmp(msg, "close\n") == 0) {
                check = 1;
            }
            writen2(client->fd, msg, strlen(msg));
        }
        read_line(client, msg);
    }
    return 1;
}

int syscheck(client_t* client, const char* filename) {
    char msg[BUF_SIZE];
    read_line(client, msg);
    printf("Sync Check Report:\n");
    char path[BUF_SIZE];
    snprintf(path, BUF_SIZE, "%s/%s", "Local Directory", filename);
    unsigned char ldigest[16];
    int i;
    for(i = 0; i < 16; i++){
        ldigest[i] = 0;
    }
    struct stat st;
    if (stat(path, &st) == 0) {
        printf("- Local Directory:\n");
        printf("-- File Size: %llu bytes.\n", st.st_size);
        MD5File(path, ldigest);
    }
    unsigned int len = 0;
    read_int(client, &len);
    unsigned int size = 0;
    read_int(client, &size);
    unsigned char rdigest[16];
    read_bytes(client, rdigest, 16);
    unsigned int status = 0;
    read_int(client, &status);
    printf("- Remote Directory:\n");
    printf("-- File Size: %u bytes.\n", size);
    int check = 1;
    for (i = 0; i < 16; i++) {
        if (ldigest[i] != rdigest[i]) {
            check = 0;
            break;
        }
    }
    if (check == 1) {
        printf("-- Sync Status: synced.\n");
    } else {
        printf("-- Sync Status: unsynced.\n");
    }
    if(status == 1){
        printf("-- Lock Status: %s.\n", "locked");
    }else{
        printf("-- Lock Status: %s.\n", "unlocked");
    }
    return 1;
}

/* Cite from textbook Computer System: A Programmers Perspective, page 979*/
int open_clientfd(const char* ip, const char* port) {
    int clientfd; // clientfd
    struct addrinfo hints, *listp, *p; 
    memset(&hints, 0, sizeof(struct addrinfo)); // size fo hints
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_ADDRCONFIG;
    getaddrinfo(ip, port, &hints, &listp);
    for (p = listp; p; p = p->ai_next) {
        if ((clientfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            continue;
        }
        if (connect(clientfd, p->ai_addr, p->ai_addrlen) != -1) {
            break;
        }
        close(clientfd);
    }
    freeaddrinfo(listp);
    if (!p) {
        return -1;
    }else{
        return clientfd;
    }
}

/* Cite from textbook Computer System: A Programmers Perspective, page 1043*/
 /* Create an empty, bounded, shared FIFO buffer with n slots */
void sbuf_init(sbuf_t *sp, int n){
    sp->buf = calloc(n, sizeof(int));
    sp->n = n; /* Buffer holds max of n items */
    sp->front = sp->rear = 0; /* Empty buffer iff front == rear */
    sem_init(&sp->mutex, 0, 1); /* Binary semaphore for locking */
    sem_init(&sp->slots, 0, n); /* Initially, buf has n empty slots */
    sem_init(&sp->items, 0, 0); /* Initially, buf has zero data items */
    }
/* Clean up buffer sp */
void sbuf_deinit(sbuf_t *sp){
    free(sp->buf);
}
 /* Insert item onto the rear of shared buffer sp */
void sbuf_insert(sbuf_t *sp, int item){
    // P(&sp->slots); /* Wait for available slot */
    // P(&sp->mutex); /* Lock the buffer */
    sp->buf[(++sp->rear)%(sp->n)] = item; /* Insert the item */
    // V(&sp->mutex); /* Unlock the buffer */
    // V(&sp->items); /* Announce available item */
    }


 /* Remove and return the first item from buffer sp */
int sbuf_remove(sbuf_t *sp){
    int item;
    // p(&sp->items); /* Wait for available item */
    // p(&sp->mutex); /* Lock the buffer */
    item = sp->buf[(++sp->front)%(sp->n)]; /* Remove the item */
    // v(&sp->mutex); /* Unlock the buffer */
    // v(&sp->slots); /* Announce available slot */
    return item;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <commands file> <server ip>\n", argv[0]);
        exit(0);
    }
    int sockfd = open_clientfd(argv[2], "9999");
    FILE* fp = fopen(argv[1], "r");
    if (fp == NULL) {
        printf("coommand File is not recognized.\n");
        exit(0);
    }
    printf("Welcome to ICS53 Online Cloud Storage.\n");
    client_t client;
    client.fd = sockfd;
    char line[BUF_SIZE];
    char message[BUF_SIZE];
    char* command;
    char* filename;
    char* time_paused;

    while (1) {
        printf("> ");
        if (fgets(line, BUF_SIZE, fp) == NULL) {
            break;
        }
        printf("%s", line);
        command = strtok(line, " \n");
        if (command == NULL) {
            continue;
        }
        if (strcmp(command, "pause") == 0) {
            time_paused = strtok(NULL, " \n");
            if (time_paused == NULL) {
                printf("Command [%s] is not recognized.\n", command);
                continue;
            }
            int num = atoi(time_paused);
            sleep(num);
            continue;
        }
        if (strcmp(command, "quit") == 0) {
            break;
        }
        filename = strtok(NULL, " \n");
        if (filename == NULL) {
            snprintf(message, BUF_SIZE, "%s\n", command);
        } else {
            snprintf(message, BUF_SIZE, "%s %s\n", command, filename);
        }
        if (!strcmp(command, "download")) {
            writen2(client.fd, message, strlen(message));
            download(&client, filename);
        } else if (!strcmp(command, "upload")) {
            upload(&client, filename, message);
        } else if (!strcmp(command, "delete")) {
            writen2(client.fd, message, strlen(message));
            delete2(&client, filename);
        } else if (!strcmp(command, "append")) {
            writen2(client.fd, message, strlen(message));
            append(&client, filename, fp);
        } else if (!strcmp(command, "syncheck")) {
            writen2(client.fd, message, strlen(message));
            syscheck(&client, filename);
        } else {
            printf("Command [%s] is not recognized.\n", command);
        }
    }
    return 0;
}


int main22(){
    // init();
    char userInput[BUF_SIZE];
	int childNum = 0;
	while (1) {
		printf(">");
		fgets(userInput, MaxLine, stdin);
		char* token = strtok(userInput, " ");
		if (!strncmp(token, "quit", 4)){
			break;
		}else if (!strncmp(token, "malloc", 6)){
			token = strtok(NULL, " ");
			int size = atoi(token);
			// malloc1(size);
		}else if (!strncmp(token, "free", 4)){
			token = strtok(NULL, " ");
			int index = atoi(token);
			// free1(index);
		}else if (!strncmp(token, "blocklist", 9)){
			// blocklist();
		}else if (!strncmp(token, "writemem", 8)){
            token = strtok(NULL, " ");
			int index = atoi(token);
            token = strtok(NULL, " ");
            char* str = token;
			// writemem(index, str);
		}else if (!strncmp(token, "printmem", 8)){
            token = strtok(NULL, " ");
			int index = atoi(token);
            token = strtok(NULL, " ");
            int numChar = atoi(token);
            // printmem(index, numChar);
        }else{
        }
    }
    return 0;
}

/* Cite from textbook Computer System: A Programmers Perspective, page 981*/
int open_clientfd_example(char *hostname, char *port) {
int clientfd;
struct addrinfo hints, *listp, *p;
memset(&hints, 0, sizeof(struct addrinfo));
hints.ai_socktype = SOCK_STREAM; /* Open a connection */
hints.ai_flags = AI_NUMERICSERV; /* ... using a numeric port arg. */
hints.ai_flags |= AI_ADDRCONFIG; /* Recommended for connections */
getaddrinfo(hostname, port, &hints, &listp);
for (p = listp; p; p = p->ai_next) {
if ((clientfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
continue; /* Socket failed, try the next */
if (connect(clientfd, p->ai_addr, p->ai_addrlen) != -1)
break; /* Success */
close(clientfd); /* Connect failed, try another */
}
freeaddrinfo(listp);
if (!p) /* All connects failed */
return -1;
else /* The last connect succeeded */
return clientfd;
}



/* Cite from textbook Computer System: A Programmers Perspective, page 993*/
void doit(int fd);
// void read_requesthdrs(rio_t *rp);
int parse_uri(char *uri, char *filename, char *cgiargs);
void serve_static(int fd, char *filename, int filesize);
void get_filetype(char *filename, char *filetype);
void serve_dynamic(int fd, char *filename, char *cgiargs);
void clienterror(int fd, char *cause, char *errnum,
char *shortmsg, char *longmsg);
