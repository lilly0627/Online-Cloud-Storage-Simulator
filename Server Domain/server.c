#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include "Md5.c"
#define LISTENQ  1024 
#define BUF_SIZE 1024
typedef struct client {
    int fd;
    char buf[BUF_SIZE];
    int nbuf;
    int stop;
    struct file_table *head;
} client_t;

struct file_table {
    char *filename;
    struct file_table *next;
};

struct file_table *head;
pthread_mutex_t my_lock = PTHREAD_MUTEX_INITIALIZER;

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


/* Metadata returned by the stat and fstat functions */
struct stat2 {
dev_t st_dev; /* Device */
ino_t st_ino; /* inode */
mode_t st_mode; /* Protection and file type */
nlink_t st_nlink; /* Number of hard links */
uid_t st_uid; /* User ID of owner */
gid_t st_gid; /* Group ID of owner */
dev_t st_rdev; /* Device type (if inode device) */
off_t st_size; /* Total size, in bytes */
unsigned long st_blksize; /* Block size for filesystem I/O */
unsigned long st_blocks; /* Number of blocks allocated */

};


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
int writen(int fd, char *usrbuf, int n) {
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
        if ((nread = read2(client->fd, client->buf + client->nbuf, BUF_SIZE - client->nbuf)) <= 0) {
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

int download(client_t* client, char* path, char* filename) {
    char msg[BUF_SIZE];
    int result;
    pthread_mutex_lock(&my_lock);
    int check = 0;;
    struct file_table *curr = head;
    while (curr != NULL) {
        if (strcmp(curr->filename, filename) == 0) {
            check = 1;
        }
        curr = curr->next;
    }
    if (check == 1) {
        pthread_mutex_unlock(&my_lock);
        result = 0;
    }else{
        pthread_mutex_unlock(&my_lock);
        result = 1;
    }

    if (result == 0) {
        snprintf(msg, BUF_SIZE, "File [%s] is currently locked by another user.\n", filename);

        writen(client->fd, msg, strlen(msg));

        return 1;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        snprintf(msg, BUF_SIZE, "File [%s] could not be found in remote directory.\n", filename);

            writen(client->fd, msg, strlen(msg));

        return 1;
    }
    writen(client->fd, "OK\n", strlen("OK\n"));
    struct stat st;
    fstat(fd, &st);
    unsigned int size = st.st_size;
    size = htonl(size);
    writen(client->fd, (char*)&size, sizeof(size));
    int nread;
    while ((nread = read(fd, msg, BUF_SIZE)) > 0) {
        writen(client->fd, msg, nread);
    }
    return 1;
}

int upload(client_t* client, char* path, char* filename) {
    char msg[BUF_SIZE];
    int result;
    pthread_mutex_lock(&my_lock);
    int check = 0;
    struct file_table *curr = head;
    while (curr != NULL) {
        if (strcmp(curr->filename, filename) == 0) {
            check = 1;
        }
        curr = curr->next;
    }
    if (check == 1) {
        pthread_mutex_unlock(&my_lock);
        result = 0;
    }else{
        pthread_mutex_unlock(&my_lock);
        result = 1;
    }
    if (result == 0) {
        snprintf(msg, BUF_SIZE, "File [%s] is currently locked by another user.\n", filename);
        writen(client->fd, msg, strlen(msg));
        return 1;
    }
    
    
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf("open [%s] failed\n", path);
        return 1;
    }

    writen(client->fd, "OK\n", strlen("OK\n"));
    unsigned int size = 0;
    read_int(client, &size);
   
    while (size > 0) {
        if (client->nbuf > 0) {
            int nwrite = size > client->nbuf ? client->nbuf : size;
            writen(fd, client->buf, nwrite);
            if (nwrite < client->nbuf) {
                memmove(client->buf, client->buf + nwrite, client->nbuf - nwrite);
            }
            size -= nwrite;
            client->nbuf -= nwrite;
        }
        if (size > 0) {
            int nread = size > BUF_SIZE - client->nbuf ? BUF_SIZE - client->nbuf : size;
            int n = 0;
            n = read(client->fd, client->buf + client->nbuf, nread);
            client->nbuf += n;
        }
    }
    return 1;
}

int delete(client_t* client, char* path, char* filename) {
    char msg[BUF_SIZE];
    int result;
    pthread_mutex_lock(&my_lock);
    int check = 0;
    struct file_table *curr = head;
    while (curr != NULL) {
        if (strcmp(curr->filename, filename) == 0) {
            check = 1;
        }
        curr = curr->next;
    }
    if (check == 1) {
        pthread_mutex_unlock(&my_lock);
        result = 0;
    }else{
        pthread_mutex_unlock(&my_lock);
        result = 1;
    }
    if (result == 0) {
        snprintf(msg, BUF_SIZE, "File [%s] is currently locked by another user.\n", filename);
        writen(client->fd, msg, strlen(msg));
        return 1;
    }

    struct stat st;
    if (stat(path, &st) < 0) {
        snprintf(msg, BUF_SIZE, "File [%s] could not be found in remote directory.\n", filename);
        writen(client->fd, msg, strlen(msg));
        return 0;
    }
    unlink(path);
    writen(client->fd, "OK\n", strlen("OK\n"));
    return 0;
}


int append(client_t* client, char* path, char* filename) {
    char msg[BUF_SIZE];
    int fd = open(path, O_WRONLY | O_APPEND, 0644);
    if (fd < 0) {
        snprintf(msg, BUF_SIZE, "File [%s] could not be found in remote directory.\n", filename);
        writen(client->fd, msg, strlen(msg));
        return 1;
    }
    int result;
    pthread_mutex_lock(&my_lock);
    int check = 0;
    struct file_table *curr = head;
    while (curr != NULL) {
        if (strcmp(curr->filename, filename) == 0) {
            check = 1;
        }
        curr = curr->next;
    }
    if (check == 1) {
        pthread_mutex_unlock(&my_lock);
        result = 0;
    }else{
        struct file_table *new_file = malloc(sizeof(struct file_table));
        new_file->filename = strdup(filename);
        new_file->next = head;
        head = new_file;
        pthread_mutex_unlock(&my_lock);
        result = 1;
    }

    if (result == 0) {
        snprintf(msg, BUF_SIZE, "File [%s] is currently locked by another user.\n", filename);
        writen(client->fd, msg, strlen(msg));
        return 1;
    }
    writen(client->fd, "OK\n", strlen("OK\n"));

    while (1) {
        read_line(client, msg);
        if (strcmp(msg, "close\n") == 0) {
            writen(client->fd, "OK\n", strlen("OK\n"));
            break;
        }
        writen(fd, "\n", 1);
        writen(fd, msg, strlen(msg)-1);
        writen(client->fd, "OK\n", strlen("OK\n"));
    }
    pthread_mutex_lock(&my_lock);

    curr = head;
    struct file_table *prev = NULL;
    while (curr != NULL) {
        if (strcmp(curr->filename, filename) == 0) {
            if (prev == NULL) {
                head = curr->next;
            } else {
                prev->next = curr->next;
            }
            free(curr->filename);
            free(curr);
            break;
        }
        prev = curr;
        curr = curr->next;
    }
    pthread_mutex_unlock(&my_lock);

    return 1;
}

int syscheck(client_t* client, char* path, char* filename) {
    writen(client->fd, "OK\n", strlen("OK\n"));
    struct stat st;
    unsigned int len = 0;
    if (stat(path, &st) < 0) {
        len = htonl(len);
        writen(client->fd, (char*)&len, sizeof(len));
        return 1;
    }

    unsigned int size = st.st_size;
    unsigned char digest[16];
    unsigned int status = 0;
    MD5File(path, digest);

    len += sizeof(size) +16 + 4;

    int result;
    pthread_mutex_lock(&my_lock);
    int check = 0;
    struct file_table *curr = head;
    while (curr != NULL) {
        if (strcmp(curr->filename, filename) == 0) {
            check = 1;
        }
        curr = curr->next;
    }
    if (check == 1) {
        pthread_mutex_unlock(&my_lock);
        result = 0;
    }else{
        pthread_mutex_unlock(&my_lock);
        result = 1;
    }
    if (result == 0) {
        status = 1;
    } else {
        status = 0;
    }
    len = htonl(len);
    writen(client->fd, (char*)&len, sizeof(len));
    size = htonl(size);
    writen(client->fd, (char*)&size, sizeof(size));
    writen(client->fd, (char*)digest, 16);
    status = htonl(status);
    writen(client->fd, (char*)&status, sizeof(status));

    return 1;
}

void* my_thread(void* arg) {
    pthread_detach(pthread_self());
    client_t* client = (client_t*)arg;
    client->stop = 0;
    int fd = client->fd;

    char line[BUF_SIZE];
    char path[BUF_SIZE];
    char* command = NULL;
    char* filename = NULL;
    while (!client->stop) {
        if (read_line(client, line) <= 0)
            break;

        command = strtok(line, " \n");
        if (command != NULL && strcmp(command, "quit") == 0) {
            writen(client->fd, "OK\n", strlen("OK\n"));
            client->stop = 1;
            break;
        }

        filename = strtok(NULL, " \n");
        if (command == NULL || filename == NULL) {
            printf("Invalid command.\n");
            writen(client->fd, "Command [%s] is not recognized.\n", strlen("Command [%s] is not recognized.\n"));
            continue;
        }

        snprintf(path, BUF_SIZE, "%s/%s", "Remote Directory", filename);
        if (strcmp(command, "upload") == 0) {
            upload(client, path, filename) ;

        } else if (strcmp(command, "download") == 0) {
            download(client, path, filename);

        } else if (strcmp(command, "delete") == 0) {
            delete(client, path, filename);

        } else if (strcmp(command, "append") == 0) {
            append(client, path, filename);

        } else if (strcmp(command, "syncheck") == 0) {
            syscheck(client, path, filename);

        } else {
            snprintf(line, BUF_SIZE, "Command [%s] is not recognized.\n", command);
            writen(client->fd, line, strlen(line));  
        }
    }
    return NULL;
}

int open_listenfd(const char* ip, const char* port) {
    struct addrinfo hints, *res;
    int sockfd;
    int yes = 1;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(ip, port, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    struct addrinfo *p;

    for (p = res; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("setsockopt");
            return -1;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }
        break;
    }

    if (p == NULL) {
        fprintf(stderr, "server: failed to bind\n");
        return -1;
    }

    freeaddrinfo(res);
    if (listen(sockfd, 10) == -1) { // 10 to 1024
        perror("listen");
        return -1;
    }

    return sockfd;
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: %s <ip>\n", argv[0]);
        return 1;
    }
    int serverfd = open_listenfd(argv[1], "9999");
    while (1) {
        struct sockaddr_storage client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int clientfd = accept(serverfd, (struct sockaddr *)&client_addr, &client_addr_len);
        client_t* client = (client_t*)malloc(sizeof(client_t));
        client->fd = clientfd;
        client->nbuf = 0;
        pthread_t tid;
        pthread_create(&tid, NULL, my_thread, client);
    }

    return 0;
}

/* Cite from textbook Computer System: A Programmers Perspective, page 1045*/
/* Global variables */
int readcnt; /* Initially = 0 */
int mutex, w; /* Both initially = 1 */
void reader(void)
{
    while (1) {
    // p(&mutex);
    readcnt++;
    if (readcnt == 1) /* First in */
//         p(&w);
//         v(&mutex);
// /* Critical section */
// /* Reading happens */
//         p(&mutex);
        readcnt--;
    if (readcnt == 0) /* Last out */
        continue;
    //     v(&w);
    // v(&mutex);
    }
}


/* Cite from textbook Computer System: A Programmers Perspective, page 1045*/
int open_listenfd_example(char *port)
{
    struct addrinfo hints, *listp, *p;
    int listenfd, optval=1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM; /* Accept connections */
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG; /* ... on any IP address */
    hints.ai_flags |= AI_NUMERICSERV; /* ... using port number */
    getaddrinfo(NULL, port, &hints, &listp);

    for (p = listp; p; p = p->ai_next) {

        if ((listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
            continue; /* Socket failed, try the next */

        setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

        if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0)
            break; /* Success */
        close(listenfd); /* Bind failed, try the next */
    }

    freeaddrinfo(listp);
    if (!p) /* No address worked */
        return -1;

    if (listen(listenfd, LISTENQ) < 0) {
        close(listenfd);
        return -1;
    }
    return listenfd;
}