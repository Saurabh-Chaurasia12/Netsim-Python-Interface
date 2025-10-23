// netsim_frag_windows.c
// Windows-only robust chunking/fragments for MESSAGE/SEGMENT send+receive over TCP
// Compile (MinGW): gcc netsim_frag_windows.c -o netsim_frag_windows.exe -lws2_32
// Compile (MSVC): cl /EHsc netsim_frag_windows.c ws2_32.lib

#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>   // Sleep
#pragma comment(lib, "Ws2_32.lib")

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

/* Configuration */
#define PORT 5555
#define BACKLOG 1
#define MAX_CHUNK_PAYLOAD 512   // maximum bytes of payload we will pack into one chunk (not including 4-byte length prefix)
#define ACK_BUF 64
#define VAR_END 0xFFFF

/* control strings */
#define ACK_STR "__ACK__"
#define OK_STR  "__OK__"
#define END_STR "__END__"

/* Segment type constants */
#define SEG_INT          1
#define SEG_DOUBLE       2
#define SEG_CHAR         3
#define SEG_BOOL         4
#define SEG_STRING       5
#define SEG_INT_ARRAY    6
#define SEG_DOUBLE_ARRAY 7

typedef SOCKET sock_t;
#define SOCK_INVALID INVALID_SOCKET
#define SOCK_ERR SOCKET_ERROR
#define sock_close(s) closesocket(s)

/* Portable 64-bit byte-swap helpers.
   Use MSVC intrinsic if available else builtin.
*/
static inline uint64_t portable_htonll(uint64_t x) {
#if defined(_MSC_VER)
    return _byteswap_uint64(x);
#elif defined(__GNUC__)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(x);
#else
    return x;
#endif
#else
    // Fallback generic
    uint64_t hi = (uint64_t)htonl((uint32_t)(x >> 32));
    uint64_t lo = (uint64_t)htonl((uint32_t)(x & 0xFFFFFFFFULL));
    return (lo << 32) | hi;
#endif
}
static inline uint64_t portable_ntohll(uint64_t x) {
#if defined(_MSC_VER)
    return _byteswap_uint64(x);
#elif defined(__GNUC__)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(x);
#else
    return x;
#endif
#else
    uint64_t hi = (uint64_t)ntohl((uint32_t)(x >> 32));
    uint64_t lo = (uint64_t)ntohl((uint32_t)(x & 0xFFFFFFFFULL));
    return (lo << 32) | hi;
#endif
}

/* Sleep helper (seconds) */
static inline void sleep_secs(unsigned int s) {
    Sleep(s * 1000u);
}

/* send_all / recv_all helpers (blocking) */
static int send_all(sock_t sock, const void *buf, int len) {
    int total = 0;
    const char *p = (const char*)buf;
    while (total < len) {
        int sent = send(sock, p + total, len - total, 0);
        if (sent == SOCKET_ERROR) return -1;
        total += sent;
    }
    return total;
}
static int recv_all(sock_t sock, void *buf, int len) {
    int total = 0;
    char *p = (char*)buf;
    while (total < len) {
        int r = recv(sock, p + total, len - total, 0);
        if (r == SOCKET_ERROR || r == 0) return -1; // error or closed
        total += r;
    }
    return total;
}

/* Basic structs */
typedef struct SEGMENT {
    uint16_t type;
    uint32_t count;           // number of elements (1 for single)
    /* send-side typed pointers (may be set by add_* functions) */
    int    *ivals;           // for int / int array (host-order)
    double *dvals;           // for double / double array (host-order)
    char   *sval;            // for string (null-terminated)
    char   *bvals;           // for bool array (1 byte each)
    /* receive-side raw buffer (always allocated when receiving segment payload) */
    char   *raw;             // raw payload bytes as received (size = size_in_bytes)
    uint32_t size_in_bytes;   // total payload bytes for this segment
    uint32_t payload_sent;    // how many payload bytes already sent (used for fragmentation)
    struct SEGMENT *next;
} SEGMENT;

typedef struct MESSAGE {
    SEGMENT *head;
    SEGMENT *tail;
    uint32_t segment_count;
    uint32_t total_size_in_bytes;
} MESSAGE;

typedef struct {
    sock_t listen_fd;
    sock_t conn_fd;
} AI_HANDLE;

/* element size helper */
static inline uint32_t elem_size_by_type(uint16_t t) {
    if (t == SEG_INT || t == SEG_INT_ARRAY) return 4;
    if (t == SEG_DOUBLE || t == SEG_DOUBLE_ARRAY) return 8;
    if (t == SEG_CHAR || t == SEG_STRING) return 1;
    if (t == SEG_BOOL) return 1;
    return 1;
}

/* API: Init listener and accept a client (blocking).
   Returns AI_HANDLE* (caller must eventually closesocket and WSACleanup at program end).
*/
void* Init_AI_ML_Interface() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return NULL;
    }

    AI_HANDLE *h = (AI_HANDLE*) calloc(1, sizeof(AI_HANDLE));
    if (!h) {
        WSACleanup();
        return NULL;
    }

    sock_t sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == SOCK_INVALID) {
        fprintf(stderr, "socket() failed: %d\n", WSAGetLastError());
        free(h);
        WSACleanup();
        return NULL;
    }

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        fprintf(stderr, "setsockopt failed: %d\n", WSAGetLastError());
        sock_close(sockfd);
        free(h);
        WSACleanup();
        return NULL;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "bind failed: %d\n", WSAGetLastError());
        sock_close(sockfd);
        free(h);
        WSACleanup();
        return NULL;
    }

    if (listen(sockfd, BACKLOG) == SOCKET_ERROR) {
        fprintf(stderr, "listen failed: %d\n", WSAGetLastError());
        sock_close(sockfd);
        free(h);
        WSACleanup();
        return NULL;
    }

    printf("Listening on port %d...\n", PORT);
    h->listen_fd = sockfd;

    struct sockaddr_in cli;
    int clilen = sizeof(cli);
    sock_t conn = accept(sockfd, (struct sockaddr*)&cli, &clilen);
    if (conn == SOCK_INVALID) {
        fprintf(stderr, "accept failed: %d\n", WSAGetLastError());
        sock_close(sockfd);
        free(h);
        WSACleanup();
        return NULL;
    }

    h->conn_fd = conn;
    printf("Client connected.\n");
    return (void*)h;
}

/* Message helpers */
MESSAGE* Init_Message() {
    MESSAGE *m = (MESSAGE*) calloc(1, sizeof(MESSAGE));
    return m;
}

// Add single int
static void add_int_to_message(void* message_v, int value) {
    if (!message_v) return;
    MESSAGE *m = (MESSAGE*)message_v;

    SEGMENT *s = (SEGMENT*) calloc(1, sizeof(SEGMENT));
    if (!s) return;

    s->type = SEG_INT;
    s->count = 1;
    s->payload_sent = 0;
    s->next = NULL;

    s->ivals = (int*) malloc(sizeof(int));
    if (!s->ivals) { free(s); return; }
    s->ivals[0] = value;

    s->raw = (char*) malloc(4);
    if (!s->raw) { free(s->ivals); free(s); return; }
    uint32_t tmp = htonl(value);
    memcpy(s->raw, &tmp, 4);

    s->size_in_bytes = 4;

    if (!m->head) m->head = m->tail = s;
    else { m->tail->next = s; m->tail = s; }
    m->segment_count++; 
    m->total_size_in_bytes += (2 + 4 + s->size_in_bytes);
}

// Add int array
static void add_intarray_to_message(void* message_v, int *arr, uint32_t length) {
    if (!message_v || (!arr && length>0)) return;
    MESSAGE *m = (MESSAGE*)message_v;

    SEGMENT *s = (SEGMENT*) calloc(1, sizeof(SEGMENT));
    if (!s) return;

    s->type = SEG_INT_ARRAY;
    s->count = length;
    s->payload_sent = 0;
    s->next = NULL;

    if (length > 0) {
        s->ivals = (int*) malloc(sizeof(int) * length);
        if (!s->ivals) { free(s); return; }
        memcpy(s->ivals, arr, sizeof(int) * length);
    }

    s->raw = (char*) malloc(4 * length);
    if (!s->raw && length>0) { free(s->ivals); free(s); return; }
    for (uint32_t i=0;i<length;i++) {
        uint32_t tmp = htonl(arr[i]);
        memcpy(s->raw + i*4, &tmp, 4);
    }

    s->size_in_bytes = 4 * length;

    if (!m->head) m->head = m->tail = s;
    else { m->tail->next = s; m->tail = s; }
    m->segment_count++; 
    m->total_size_in_bytes += (2 + 4 + s->size_in_bytes);
}

// Add double
static void add_double_to_message(void* message_v, double value) {
    if (!message_v) return;
    MESSAGE *m = (MESSAGE*)message_v;

    SEGMENT *s = (SEGMENT*) calloc(1, sizeof(SEGMENT));
    if (!s) return;

    s->type = SEG_DOUBLE;
    s->count = 1;
    s->payload_sent = 0;
    s->next = NULL;

    s->dvals = (double*) malloc(sizeof(double));
    if (!s->dvals) { free(s); return; }
    s->dvals[0] = value;

    s->raw = (char*) malloc(8);
    if (!s->raw) { free(s->dvals); free(s); return; }

    uint64_t tmp;
    memcpy(&tmp, &value, 8);
    tmp = portable_htonll(tmp); // convert double to network byte order
    memcpy(s->raw, &tmp, 8);

    s->size_in_bytes = 8;

    if (!m->head) m->head = m->tail = s;
    else { m->tail->next = s; m->tail = s; }
    m->segment_count++;
    m->total_size_in_bytes += (2 + 4 + s->size_in_bytes);
}

static void add_doublearray_to_message(void* message_v, double *arr, uint32_t length) {
    if (!message_v || (!arr && length>0)) return;
    MESSAGE *m = (MESSAGE*)message_v;

    SEGMENT *s = (SEGMENT*) calloc(1, sizeof(SEGMENT));
    if (!s) return;

    s->type = SEG_DOUBLE_ARRAY;
    s->count = length;
    s->payload_sent = 0;
    s->next = NULL;

    if (length > 0) {
        s->dvals = (double*) malloc(sizeof(double) * length);
        if (!s->dvals) { free(s); return; }
        memcpy(s->dvals, arr, sizeof(double) * length);
    }

    s->raw = (char*) malloc(8 * length);
    if (!s->raw && length>0) { free(s->dvals); free(s); return; }
    for (uint32_t i=0;i<length;i++) {
        union { double d; uint64_t u; } conv;
        conv.d = arr[i];
        uint64_t nu = portable_htonll(conv.u);
        memcpy(s->raw + i*8, &nu, 8);
    }

    s->size_in_bytes = 8 * length;

    if (!m->head) m->head = m->tail = s;
    else { m->tail->next = s; m->tail = s; }
    m->segment_count++;
    m->total_size_in_bytes += (2 + 4 + s->size_in_bytes);
}

/* Add single char (not treated as a multi-byte string) */
void add_char_to_message(void* message_v, char value) {
    if (!message_v) return;
    MESSAGE *m = (MESSAGE*) message_v;

    SEGMENT *s = (SEGMENT*) calloc(1, sizeof(SEGMENT));
    if (!s) return;

    s->type = SEG_CHAR;
    s->count = 1;
    s->payload_sent = 0;
    s->next = NULL;

    /* raw payload: single byte */
    s->raw = (char*) malloc(1);
    if (!s->raw) { free(s); return; }
    s->raw[0] = (char) value;

    /* convenience null-terminated sval for printing (optional) */
    s->sval = (char*) malloc(2);
    if (!s->sval) { free(s->raw); free(s); return; }
    s->sval[0] = (char) value;
    s->sval[1] = '\0';

    s->size_in_bytes = 1;

    if (!m->head) m->head = m->tail = s;
    else { m->tail->next = s; m->tail = s; }
    m->segment_count++;
    m->total_size_in_bytes += (2 + 4 + s->size_in_bytes);
}


// Add string
static void add_string_to_message(void* message_v, const char* str) {
    if (!message_v || !str) return;
    MESSAGE *m = (MESSAGE*)message_v;

    uint32_t len = (uint32_t)strlen(str);

    SEGMENT *s = (SEGMENT*) calloc(1, sizeof(SEGMENT));
    if (!s) return;

    s->type = SEG_STRING;
    s->count = len;
    s->payload_sent = 0;
    s->next = NULL;

    s->sval = (char*) malloc(len + 1);
    if (!s->sval) { free(s); return; }
    memcpy(s->sval, str, len);
    s->sval[len] = '\0';

    s->raw = (char*) malloc(len + 1);
    if (!s->raw) { free(s->sval); free(s); return; }
    memcpy(s->raw, str, len);
    s->raw[len] = '\0';

    s->size_in_bytes = len + 1;

    if (!m->head) m->head = m->tail = s;
    else { m->tail->next = s; m->tail = s; }
    m->segment_count++;
    m->total_size_in_bytes += (2 + 4 + s->size_in_bytes);
}

/* === add_variable_to_message (variadic) ===
   Usage pattern:
     add_variable_to_message(m,
        SEG_INT, 42,
        SEG_INT_ARRAY, int_arr_ptr, (unsigned int)len,
        SEG_STRING, "hello", (unsigned int)5,
        SEG_DOUBLE_ARRAY, dbl_arr_ptr, (unsigned int)len,
        VAR_END);
   Caller must provide the proper arguments for each type and terminate with VAR_END.
*/
void add_variable_to_message(void *message_v, ...){
    if (!message_v){
        return;
    }
    MESSAGE *m = (MESSAGE *)message_v;
    va_list ap;
    va_start(ap, message_v);
    while (1){
        unsigned int t_promoted = va_arg(ap, unsigned int);
        uint16_t t = (uint16_t)t_promoted;
        if (t == VAR_END){
            break;
        }
        switch (t){
            case SEG_INT:{
                int v = va_arg(ap, int);
                add_int_to_message(m, v);
                break;
            }
            case SEG_DOUBLE:{
                double d = va_arg(ap, double);
                add_double_to_message(m, d);
                break;
            }
            case SEG_STRING:{
                const char *str = va_arg(ap, const char *);
                add_string_to_message(m, str);
                break;
            }
            case SEG_INT_ARRAY:{
                int *arr = va_arg(ap, int *);
                unsigned int len = va_arg(ap, unsigned int);
                add_intarray_to_message(m, arr, (uint32_t)len);
                break;
            }
            case SEG_DOUBLE_ARRAY:{
                double *arrd = va_arg(ap, double *);
                unsigned int len = va_arg(ap, unsigned int);
                add_doublearray_to_message(m, arrd, (uint32_t)len);
                break;
            }
            case SEG_CHAR: {
                /* single char passed as int (promotion) */
            int ci = va_arg(ap, int);
            char c = (char)ci;
                add_char_to_message(m, c);
            break;
            }
            case SEG_BOOL:{
                /* treat bool as single int (0/1) for now */
                int bi = va_arg(ap, int);
                add_int_to_message(m, bi ? 1 : 0);
                break;
            }
            default:
                fprintf(stderr, "add_variable_to_message: unsupported type %u\n", (unsigned int)t); /* cannot reliably skip varargs for unknown type; aborting */
                va_end(ap);
                return;
            }
    }
    va_end(ap);
}

/* form_segment_bytes: fragment aware */
static uint32_t form_segment_bytes(uint32_t max_size, SEGMENT **segment_ptr, char *outbuf) {
    if (!segment_ptr || !outbuf) return 0;
    char *t = outbuf;
    uint32_t used = 0;
    SEGMENT *seg = *segment_ptr;

    while (seg) {
        uint32_t total_payload = seg->size_in_bytes;
        uint32_t remaining_payload = total_payload - seg->payload_sent;
        (void)remaining_payload;
        uint32_t elem_size = elem_size_by_type(seg->type);

        if (seg->payload_sent == 0) {
            if (used + 7 > max_size) break; // need 1+2+4 bytes for header flag+type+count
            *t++ = 1; used += 1;
            uint16_t nettype = htons(seg->type);
            uint32_t netcount = htonl(seg->count);
            memcpy(t, &nettype, 2); t += 2; used += 2;
            memcpy(t, &netcount, 4); t += 4; used += 4;
        } else {
            if (used + 1 > max_size) break;
            *t++ = 0; used += 1;
        }

        uint32_t space_left = max_size - used;
        uint32_t can_copy = 0;

        if (seg->type == SEG_INT || seg->type == SEG_INT_ARRAY) {
            uint32_t start_elem = seg->payload_sent / 4;
            uint32_t max_elems = space_left / 4;
            uint32_t remaining_elems = (total_payload - seg->payload_sent) / 4;
            uint32_t elems_to_copy = (max_elems < remaining_elems) ? max_elems : remaining_elems;
            can_copy = elems_to_copy * 4;
            for (uint32_t i = 0; i < elems_to_copy; ++i) {
                uint32_t v = (uint32_t) seg->ivals[start_elem + i];
                uint32_t nv = htonl(v);
                memcpy(t, &nv, 4); t += 4;
            }
        } else if (seg->type == SEG_DOUBLE || seg->type == SEG_DOUBLE_ARRAY) {
            uint32_t start_elem = seg->payload_sent / 8;
            uint32_t max_elems = space_left / 8;
            uint32_t remaining_elems = (total_payload - seg->payload_sent) / 8;
            uint32_t elems_to_copy = (max_elems < remaining_elems) ? max_elems : remaining_elems;
            can_copy = elems_to_copy * 8;
            for (uint32_t i = 0; i < elems_to_copy; ++i) {
                union { double d; uint64_t u; } du;
                du.d = seg->dvals[start_elem + i];
                uint64_t netu = portable_htonll(du.u);
                memcpy(t, &netu, 8); t += 8;
            }
        } else {
            uint32_t bytes_to_copy = (space_left < (total_payload - seg->payload_sent)) ? space_left : (total_payload - seg->payload_sent);
            char *src = NULL;
            if (seg->type == SEG_STRING) {
                src = seg->sval;   // string with null terminator
            } else if (seg->type == SEG_CHAR) {
                src = seg->raw;    // use raw byte(s) directly
            } else if (seg->type == SEG_BOOL) {
                src = seg->bvals;
            } else {
                src = seg->raw;    // INT, DOUBLE, INT_ARRAY, DOUBLE_ARRAY
            }
            memcpy(t, src + seg->payload_sent, bytes_to_copy);
            t += bytes_to_copy;
            can_copy = bytes_to_copy;
        }

        used += can_copy;
        seg->payload_sent += can_copy;

        if (seg->payload_sent >= total_payload) {
            seg->payload_sent = 0;
            seg = seg->next;
            *segment_ptr = seg;
            continue;
        } else {
            break;
        }
    }
    return used;
}

/* free_message */
void free_message(void* message_v) {
    MESSAGE *m = (MESSAGE*)message_v;
    if (!m) return;
    SEGMENT *s = m->head;
    while (s) {
        SEGMENT *n = s->next;
        if (s->raw) { free(s->raw); s->raw = NULL; }
        if (s->sval) { free(s->sval); s->sval = NULL; } // note: for strings we may have set sval=raw and raw=NULL
        if (s->ivals) { free(s->ivals); s->ivals = NULL; }
        if (s->dvals) { free(s->dvals); s->dvals = NULL; }
        if (s->bvals) { free(s->bvals); s->bvals = NULL; }
        free(s);
        s = n;
    }
    free(m);
}

/* validate a single segment before sending (sender-side) */
static int validate_segment_for_send(const SEGMENT *s) {
    if (!s) return -1;
    if (s->count == 0 && s->size_in_bytes == 0) {
        // allow zero-length segment only for explicit use-cases
        return 0;
    }

    uint32_t expected_bytes = elem_size_by_type(s->type) * s->count;
    if (s->type == SEG_STRING) {
        // string's 'count' is length WITHOUT terminator; stored size should be count+1
        expected_bytes = s->count + 1;
    } else if (s->type == SEG_CHAR) {
        // char array: count bytes, no terminator in our design
        expected_bytes = s->count;
    }

    if (s->size_in_bytes != expected_bytes) {
        fprintf(stderr, "validate_segment_for_send: mismatch size_in_bytes (%u) vs expected (%u) for type %u\n",
                s->size_in_bytes, expected_bytes, (unsigned)s->type);
        return -1;
    }

    // type-specific checks
    if ((s->type == SEG_INT || s->type == SEG_INT_ARRAY) && s->count > 0) {
        if (!s->ivals) {
            fprintf(stderr, "validate_segment_for_send: ivals is NULL for int segment\n");
            return -1;
        }
    }
    if ((s->type == SEG_DOUBLE || s->type == SEG_DOUBLE_ARRAY) && s->count > 0) {
        if (!s->dvals) {
            fprintf(stderr, "validate_segment_for_send: dvals is NULL for double segment\n");
            return -1;
        }
    }
    if (s->type == SEG_STRING) {
        if (!s->sval) {
            fprintf(stderr, "validate_segment_for_send: sval is NULL for string\n");
            return -1;
        }
        // ensure nul terminator present at expected position
        if ((unsigned)strlen(s->sval) != s->count) {
            fprintf(stderr, "validate_segment_for_send: string length %zu does not equal count %u\n",
                    strlen(s->sval), s->count);
            return -1;
        }
    }
    if (s->type == SEG_BOOL && s->count > 0) {
        if (!s->bvals && !s->ivals) {
            fprintf(stderr, "validate_segment_for_send: bool segment has no backing storage\n");
            return -1;
        }
    }

    return 0;
}

/* validate whole message before send */
static int validate_message_for_send(const MESSAGE *m) {
    if (!m) return -1;
    SEGMENT *s = m->head;
    while (s) {
        if (validate_segment_for_send(s) != 0) {
            fprintf(stderr, "validate_message_for_send: segment validation failed (type=%u)\n", s->type);
            return -1;
        }
        s = s->next;
    }
    return 0;
}

/* send_message */
static int send_message(void* ai_handle_v, void* message_v) {
    AI_HANDLE *ai = (AI_HANDLE*)ai_handle_v;
    MESSAGE *m = (MESSAGE*)message_v;
    if (validate_message_for_send(m) != 0) {
        fprintf(stderr,"send_message: validation failed, aborting send\n");
        return -1;
    }
    if (!ai || !m) return -1;
    SEGMENT *index = m->head;
    char payload[MAX_CHUNK_PAYLOAD];
    char ack[ACK_BUF];
    size_t ack_len = strlen(ACK_STR);

    while (index) {
        uint32_t n = form_segment_bytes(MAX_CHUNK_PAYLOAD, &index, payload);
        if (n == 0) {
            fprintf(stderr,"form_segment_bytes returned 0\n");
            return -1;
        }
        uint32_t netlen = htonl(n);
        if (send_all(ai->conn_fd, &netlen, 4) != 4) { fprintf(stderr,"send len failed\n"); return -1; }
        if (send_all(ai->conn_fd, payload, n) != (int)n) { fprintf(stderr,"send payload failed\n"); return -1; }

        fprintf(stderr,"chunk sent, waiting for ack...\n");
        if (recv_all(ai->conn_fd, ack, (int)ack_len) <= 0) { fprintf(stderr,"recv ack failed\n"); return -1; }
        fprintf(stderr,"ack received\n");
        ack[ack_len] = '\0';
        if (strncmp(ack, ACK_STR, ack_len) != 0) {
            fprintf(stderr,"expected %s, got '%s'\n", ACK_STR, ack);
            return -1;
        }
    }

    const char *endmsg = END_STR;
    uint32_t endlen = (uint32_t) strlen(endmsg);
    uint32_t netendlen = htonl(endlen);
    if (send_all(ai->conn_fd, &netendlen, 4) != 4) { fprintf(stderr,"send end len failed\n"); return -1; }
    if (send_all(ai->conn_fd, endmsg, (int)endlen) != (int)endlen) { fprintf(stderr,"send end payload failed\n"); return -1; }
    fprintf(stderr,"sending end marker...\n");
    size_t ok_len = strlen(OK_STR);
    if (recv_all(ai->conn_fd, ack, (int)ok_len) <= 0) { fprintf(stderr,"recv ok failed\n"); return -1; }
    fprintf(stderr,"end ack received\n");

    ack[ok_len] = '\0';
    if (strncmp(ack, OK_STR, ok_len) != 0) {
        fprintf(stderr,"expected %s, got '%s'\n", OK_STR, ack);
        return -1;
    }
    return 0;
}

/* validate a reassembled segment after receiving (receiver-side)
   Checks raw buffer length vs expected, element alignment, and decodes consistency. */
static int validate_segment_on_receive(const SEGMENT *s) {
    if (!s) return -1;
    uint32_t expected_bytes = elem_size_by_type(s->type) * s->count;
    if (s->type == SEG_STRING) expected_bytes = s->count + 1;
    else if (s->type == SEG_CHAR) expected_bytes = s->count;

    if (s->size_in_bytes != expected_bytes) {
        fprintf(stderr, "validate_segment_on_receive: size_in_bytes (%u) != expected (%u) for type %u\n",
                s->size_in_bytes, expected_bytes, (unsigned)s->type);
        return -1;
    }

    if ((s->type == SEG_INT || s->type == SEG_INT_ARRAY) && (s->size_in_bytes % 4 != 0)) {
        fprintf(stderr, "validate_segment_on_receive: int segment byte size %u not divisible by 4\n", s->size_in_bytes);
        return -1;
    }
    if ((s->type == SEG_DOUBLE || s->type == SEG_DOUBLE_ARRAY) && (s->size_in_bytes % 8 != 0)) {
        fprintf(stderr, "validate_segment_on_receive: double segment byte size %u not divisible by 8\n", s->size_in_bytes);
        return -1;
    }

    if (s->type == SEG_STRING) {
        /* Accept either:
           - raw buffer present and last byte is '\0'
           - or sval present (string pointer) and its length equals count
           (this handles the common `sval = raw; raw = NULL` pattern).
        */
        if (s->raw != NULL) {
            if ((unsigned char) s->raw[s->size_in_bytes - 1] != '\0') {
                fprintf(stderr, "validate_segment_on_receive: string raw last byte is not '\\0'\n");
                return -1;
            }
        } else if (s->sval != NULL) {
            /* sval should be null-terminated and its strlen should equal count */
            size_t ls = strlen(s->sval);
            if (ls != (size_t) s->count) {
                fprintf(stderr, "validate_segment_on_receive: sval length %zu != count %u\n", ls, s->count);
                return -1;
            }
            /* also ensure underlying memory was not truncated (size_in_bytes >= count+1) */
        } else {
            fprintf(stderr, "validate_segment_on_receive: string has neither raw nor sval\n");
            return -1;
        }
    }

    if (s->type == SEG_BOOL && s->count > 0) {
        if (!s->bvals && !s->ivals) {
            fprintf(stderr, "validate_segment_for_send: bool segment has no backing storage\n");
            return -1;
        }
    }

    return 0;
}

/* validate whole message after receive */
static int validate_message_on_receive(const MESSAGE *m) {
    if (!m) return -1;
    SEGMENT *s = m->head;
    while (s) {
        if (validate_segment_on_receive(s) != 0) {
            fprintf(stderr, "validate_message_on_receive: segment validate failed (type=%u)\n", s->type);
            return -1;
        }
        s = s->next;
    }
    return 0;
}

/* receive_message */
static int receive_message(void* ai_handle_v, void** outMessage) {
    AI_HANDLE *ai = (AI_HANDLE*)ai_handle_v;
    if (!ai || !outMessage) return -1;
    *outMessage = NULL;
    MESSAGE *m = Init_Message(NULL);
    if (!m) return -1;

    SEGMENT *cur_segment = NULL;
    uint32_t cur_received = 0;
    char ack_msg[] = ACK_STR;
    char ok_msg[] = OK_STR;
    size_t ack_len = strlen(ACK_STR);

    while (1) {
        uint32_t netlen;
        if (recv_all(ai->conn_fd, &netlen, 4) <= 0) { fprintf(stderr,"recv chunk len failed\n"); goto fail; }
        uint32_t len = ntohl(netlen);
        if (len == 0) {
            if (send_all(ai->conn_fd, ack_msg, (int)ack_len) != (int)ack_len) { fprintf(stderr,"send ack failed\n"); goto fail; }
            continue;
        }
        char *chunk = (char*) malloc(len);
        if (!chunk) { fprintf(stderr,"malloc chunk failed\n"); goto fail; }
        if (recv_all(ai->conn_fd, chunk, (int)len) <= 0) { fprintf(stderr,"recv chunk payload failed\n"); free(chunk); goto fail; }

        if (len == strlen(END_STR) && memcmp(chunk, END_STR, strlen(END_STR)) == 0) {
            fprintf(stderr,"received END marker, sending END ACK...\n");
            if (send_all(ai->conn_fd, ok_msg, (int)strlen(OK_STR)) != (int)strlen(OK_STR)) { fprintf(stderr,"send ok failed\n"); free(chunk); goto fail; }
            free(chunk);
            if (validate_message_on_receive(m) != 0) {
                fprintf(stderr, "receive_message: validation failed on assembled message\n");
                // free message and return error
                free_message(m);
                *outMessage = NULL;
                goto fail;   // or return -1 after cleaning as you already do
            }
            *outMessage = m;
            return 0;
        }

        uint32_t pos = 0;
        while (pos < len) {
            if (pos >= len) break;
            uint8_t flag = (uint8_t) chunk[pos++];
            if (flag == 1) {
                if (pos + 6 > len) { fprintf(stderr,"Malformed chunk header\n"); free(chunk); goto fail; }
                uint16_t nettype;
                uint32_t netcount;
                memcpy(&nettype, chunk + pos, 2); pos += 2;
                memcpy(&netcount, chunk + pos, 4); pos += 4;
                uint16_t type = ntohs(nettype);
                uint32_t count = ntohl(netcount);

                uint32_t payload_bytes = 0;
                if (type == SEG_INT || type == SEG_INT_ARRAY) payload_bytes = 4 * count;
                else if (type == SEG_DOUBLE || type == SEG_DOUBLE_ARRAY) payload_bytes = 8 * count;
                else if (type == SEG_STRING) payload_bytes = count + 1;  /* string still needs null terminator */
                else if (type == SEG_CHAR)   payload_bytes = count;      /* char is raw single byte */
                else payload_bytes = elem_size_by_type(type) * count;

                cur_segment = (SEGMENT*) calloc(1, sizeof(SEGMENT));
                if (!cur_segment) { fprintf(stderr,"calloc cur_segment failed\n"); free(chunk); goto fail; }
                cur_segment->type = type;
                cur_segment->count = count;
                cur_segment->size_in_bytes = payload_bytes;
                cur_segment->payload_sent = 0;
                cur_segment->next = NULL;
                cur_segment->raw = (char*) malloc(payload_bytes ? payload_bytes : 1);
                if (!cur_segment->raw && payload_bytes > 0) { fprintf(stderr,"malloc payload buffer failed\n"); free(cur_segment); free(chunk); goto fail; }
                cur_received = 0;

                uint32_t avail = len - pos;
                uint32_t want = (payload_bytes - cur_received);
                uint32_t to_copy = (avail < want) ? avail : want;
                if (to_copy > 0) {
                    memcpy(cur_segment->raw + cur_received, chunk + pos, to_copy);
                    pos += to_copy;
                    cur_received += to_copy;
                    cur_segment->payload_sent = cur_received;
                }

                if (cur_received >= payload_bytes) {
                    if (cur_segment->type == SEG_INT || cur_segment->type == SEG_INT_ARRAY) {
                        uint32_t num = cur_segment->count;
                        cur_segment->ivals = (int*) malloc(sizeof(int) * num);
                        if (!cur_segment->ivals && num>0) { fprintf(stderr,"malloc ivals failed\n"); free(cur_segment->raw); free(cur_segment); free(chunk); goto fail; }
                        for (uint32_t i=0;i<num;i++) {
                            uint32_t tmp;
                            memcpy(&tmp, cur_segment->raw + i*4, 4);
                            cur_segment->ivals[i] = (int) ntohl(tmp);
                        }
                    } else if (cur_segment->type == SEG_DOUBLE || cur_segment->type == SEG_DOUBLE_ARRAY) {
                        uint32_t num = cur_segment->count;
                        cur_segment->dvals = (double*) malloc(sizeof(double) * num);
                        if (!cur_segment->dvals && num>0) { fprintf(stderr,"malloc dvals failed\n"); free(cur_segment->raw); free(cur_segment); free(chunk); goto fail; }
                        for (uint32_t i=0;i<num;i++) {
                            uint64_t tmpu;
                            memcpy(&tmpu, cur_segment->raw + i*8, 8);
                            tmpu = portable_ntohll(tmpu);
                            union { double d; uint64_t u; } conv;
                            conv.u = tmpu;
                            cur_segment->dvals[i] = conv.d;
                        }
                    } 
                    else if (cur_segment->type == SEG_BOOL) {
                        /* store bools as bytes in bvals and also as ints in ivals for convenience */
                        uint32_t num = cur_segment->count;
                        cur_segment->bvals = (char*) malloc(num ? num : 1);
                        if (!cur_segment->bvals && num>0) { fprintf(stderr,"malloc bvals failed\n"); free(cur_segment->raw); free(cur_segment); free(chunk); goto fail; }
                        cur_segment->ivals = (int*) malloc(sizeof(int) * num);
                        if (!cur_segment->ivals && num>0) { fprintf(stderr,"malloc ivals failed\n"); free(cur_segment->bvals); free(cur_segment->raw); free(cur_segment); free(chunk); goto fail; }
                        for (uint32_t i=0;i<num;i++) {
                            unsigned char v = (unsigned char) cur_segment->raw[i];
                            cur_segment->bvals[i] = (char) v;
                            cur_segment->ivals[i] = v ? 1 : 0;
                        }
                    }
                    else if (cur_segment->type == SEG_CHAR) {
                        cur_segment->sval = (char*) malloc(cur_segment->count + 1);
                        memcpy(cur_segment->sval, cur_segment->raw, cur_segment->count);
                        cur_segment->sval[cur_segment->count] = '\0';
                    }
                    else if (cur_segment->type == SEG_STRING) {
                        if (cur_segment->size_in_bytes > 0) cur_segment->raw[cur_segment->size_in_bytes - 1] = '\0';
                        // you can also set cur_segment->sval = cur_segment->raw;  // reuse raw as string
                        cur_segment->sval = cur_segment->raw; // reuse raw buffer for string convenience
                        cur_segment->raw = NULL; // prevent double-free (we moved ownership) *********** IMPORTANT ***********
                    }

                    if (!m->head) m->head = m->tail = cur_segment;
                    else { m->tail->next = cur_segment; m->tail = cur_segment; }
                    m->segment_count++;
                    m->total_size_in_bytes += (2 + 4 + cur_segment->size_in_bytes);

                    cur_segment = NULL;
                    cur_received = 0;
                }
            } else if (flag == 0) {
                if (!cur_segment) { 
                    fprintf(stderr,"Continuation without current segment\n"); 
                    free(chunk); 
                    goto fail; 
                }

                uint32_t avail = len - pos;
                uint32_t want = cur_segment->size_in_bytes - cur_segment->payload_sent;
                uint32_t to_copy = (avail < want) ? avail : want;

                if (to_copy > 0) {
                    memcpy(cur_segment->raw + cur_segment->payload_sent, chunk + pos, to_copy);
                    pos += to_copy;
                    cur_segment->payload_sent += to_copy;
                }

                if (cur_segment->payload_sent >= cur_segment->size_in_bytes) {
                    // Decode after full segment is received
                    if (cur_segment->type == SEG_INT || cur_segment->type == SEG_INT_ARRAY) {
                        uint32_t num = cur_segment->count;
                        cur_segment->ivals = (int*) malloc(sizeof(int) * num);
                        for (uint32_t i=0; i<num; i++) {
                            uint32_t tmp;
                            memcpy(&tmp, cur_segment->raw + i*4, 4);
                            cur_segment->ivals[i] = (int) ntohl(tmp);
                        }
                    } else if (cur_segment->type == SEG_DOUBLE || cur_segment->type == SEG_DOUBLE_ARRAY) {
                        uint32_t num = cur_segment->count;
                        cur_segment->dvals = (double*) malloc(sizeof(double) * num);
                        for (uint32_t i=0; i<num; i++) {
                            uint64_t tmpu;
                            memcpy(&tmpu, cur_segment->raw + i*8, 8);
                            tmpu = portable_ntohll(tmpu);
                            union { double d; uint64_t u; } conv;
                            conv.u = tmpu;
                            cur_segment->dvals[i] = conv.d;
                        }
                    }else if (cur_segment->type == SEG_BOOL) {
                        /* store bools as bytes in bvals and also as ints in ivals for convenience */
                        uint32_t num = cur_segment->count;
                        cur_segment->bvals = (char*) malloc(num ? num : 1);
                        if (!cur_segment->bvals && num>0) { fprintf(stderr,"malloc bvals failed\n"); free(cur_segment->raw); free(cur_segment); free(chunk); goto fail; }
                        cur_segment->ivals = (int*) malloc(sizeof(int) * num);
                        if (!cur_segment->ivals && num>0) { fprintf(stderr,"malloc ivals failed\n"); free(cur_segment->bvals); free(cur_segment->raw); free(cur_segment); free(chunk); goto fail; }
                        for (uint32_t i=0;i<num;i++) {
                            unsigned char v = (unsigned char) cur_segment->raw[i];
                            cur_segment->bvals[i] = (char) v;
                            cur_segment->ivals[i] = v ? 1 : 0;
                        }
                    }
                    else if (cur_segment->type == SEG_CHAR) {
                        cur_segment->sval = (char*) malloc(cur_segment->count + 1);
                        memcpy(cur_segment->sval, cur_segment->raw, cur_segment->count);
                        cur_segment->sval[cur_segment->count] = '\0';
                    }
                     else if (cur_segment->type == SEG_STRING) {
                        // Make sval point to raw
                        if (cur_segment->size_in_bytes > 0) cur_segment->raw[cur_segment->size_in_bytes-1] = '\0';
                        cur_segment->sval = cur_segment->raw;
                        cur_segment->raw = NULL; // prevent double-free (we moved ownership) *********** IMPORTANT ***********
                    }

                    // Add to message linked list
                    if (!m->head) m->head = m->tail = cur_segment;
                    else { m->tail->next = cur_segment; m->tail = cur_segment; }

                    m->segment_count++;
                    m->total_size_in_bytes += (2 + 4 + cur_segment->size_in_bytes);

                    cur_segment = NULL;
                }
            } else {
                fprintf(stderr,"Unknown fragment flag: %u\n", flag);
                free(chunk);
                goto fail;
            }
        } // end while pos < len

        /* send ack for chunk */
        fprintf(stderr,"chunk received, sending ack...\n");
        if (send_all(ai->conn_fd, ack_msg, (int)ack_len) != (int)ack_len) {
            fprintf(stderr,"send ack failed\n"); free(chunk); goto fail;
        }
        free(chunk);
    }

fail:
    // cleanup on error
    if (m) {
        SEGMENT *s = m->head;
        while (s) {
            SEGMENT *n = s->next;
            if (s->raw) { free(s->raw); s->raw = NULL; }
            if (s->sval) { free(s->sval); s->sval = NULL; } // note: for strings we may have set sval=raw and raw=NULL
            if (s->ivals) { free(s->ivals); s->ivals = NULL; }
            if (s->dvals) { free(s->dvals); s->dvals = NULL; }
            if (s->bvals) { free(s->bvals); s->bvals = NULL; }
            free(s);
            s = n;
        }
    free(m);
    }
    return -1;
}

int Send_receive_message(void* handle, void* message_v, void** outMessage) {
    // Your spec: "will call send_message if message is not null; will call receive_message if outmessage is not null"
    // I provide a function that does both as appropriate; returns 0 on success, -1 on error.
    if (!handle) return -1;
    int rc = 0;
    if (message_v) {
        fprintf(stderr,"\nSending Message to Python\n");
        rc = send_message(handle, message_v);
        if (rc != 0) return -1;
    }
    if (outMessage) {
        fprintf(stderr,"\nReceiving Message from Python\n");
        rc = receive_message(handle, outMessage);
        if (rc != 0) return -1;
    }
    return 0;
}

uint32_t get_variablecount(void* message_v) {
    if (!message_v) return 0;
    MESSAGE *m = (MESSAGE*) message_v;
    return m->segment_count;
}

// /* Return SEGMENT* at zero-based index. If type_ptr != NULL set *type_ptr, if count_ptr != NULL set *count_ptr (element count) */
void* get_variable_from_message(void* message_v, uint32_t index, uint16_t *type_ptr, uint32_t *count_ptr) {
    if (!message_v) return NULL;
    MESSAGE *m = (MESSAGE*) message_v;
    if (index >= m->segment_count) return NULL;
    SEGMENT *s = m->head;
    for (uint32_t i=0;i<index;i++) {
        if (!s) return NULL;
        s = s->next;
    }
    if (!s) return NULL;
    if (type_ptr) *type_ptr = s->type;
    if (count_ptr) *count_ptr = s->count;
    return (void*) s;
}

static void debug_print_segment(const SEGMENT* s, int want_raw) {
    if (!s) { fprintf(stderr,"NULL SEGMENT]\n"); return; }

    fprintf(stderr,"Segment Debug Info : \n");

    fprintf(stderr,"Type: %d\n", s->type);
    fprintf(stderr,"Count: %d\n", s->count);
    fprintf(stderr,"Size in bytes: %d\n", s->size_in_bytes);

    if (want_raw!=0) {
        if (s->raw) {
            fprintf(stderr,"Raw (hex): ");
            unsigned int limit = s->size_in_bytes;
            for (unsigned int i = 0; i < limit; i++) fprintf(stderr,"%02X", (unsigned char)s->raw[i]);
            fprintf(stderr,"\n");
        } 
        else if(s->type == SEG_STRING && s->sval){
            fprintf(stderr,"Raw (hex): ");
            for (unsigned int i = 0; i < s->size_in_bytes; i++){
                fprintf(stderr,"%02X", (unsigned char)s->sval[i]); 
            }
            fprintf(stderr,"\n");
        } else {
            fprintf(stderr,"Raw buffer: NULL\n");
        }
    }

    if (s->ivals) {
        fprintf(stderr,"Int values: ");
        for (unsigned int i = 0; i < s->count; i++) fprintf(stderr,"%d ", s->ivals[i]);
        fprintf(stderr,"\n");
    }
    if (s->dvals) {
        fprintf(stderr,"Double values: ");
        for (unsigned int i = 0; i < s->count; i++) fprintf(stderr,"%.3f ", s->dvals[i]);
        fprintf(stderr,"\n");
    }
    if (s->bvals) {
        fprintf(stderr,"Bool values: ");
        for (unsigned int i = 0; i < s->count; i++) fprintf(stderr,"%d ", s->bvals[i]);
        fprintf(stderr,"\n");
    }
    if (s->sval) {
        char disp[100];
        strncpy(disp, s->sval, sizeof(disp) - 1);
        disp[sizeof(disp) - 1] = '\0';
        for (char* p = disp; *p; ++p)
            if (*p == '\n') *p = ' ';
        if(s->type == SEG_CHAR)
            fprintf(stderr,"Char value: '%s'\n", disp);
        else
            fprintf(stderr,"String value: '%s'\n", disp);
    }

}

void debug_print_message(const MESSAGE* m, int want_raw) {
    if (!m) { fprintf(stderr,"NULL MESSAGE]\n"); return; }

    fprintf(stderr,"\nMessage Debug Info\n");
    fprintf(stderr,"Total segments: %u\n", m->segment_count);

    SEGMENT* s = m->head;
    unsigned int idx = 0;
    while (s) {
        fprintf(stderr,"\nSegment %u\n", idx + 1);
        debug_print_segment(s,want_raw);
        s = s->next;
        idx++;
    }
    fprintf(stderr,"\n");
    fprintf(stderr,"End of Message\n\n");
}


int main() {
    void *ai_handle = Init_AI_ML_Interface();
    if (!ai_handle) {
        fprintf(stderr, "Failed to init AI interface\n");
        return 1;
    }
    AI_HANDLE *ai = (AI_HANDLE*) ai_handle;

    /* Create a message */
    MESSAGE *msg = Init_Message();
    if (!msg) {
        fprintf(stderr, "Failed to init message\n");
        /* cleanup */
        if (ai->conn_fd != SOCK_INVALID) sock_close(ai->conn_fd);
        if (ai->listen_fd != SOCK_INVALID) sock_close(ai->listen_fd);
        free(ai);
        WSACleanup();
        return 1;
    }

    /* Sample variables to send */
    int arr[] = {10, 20, 30};
    double dval = 3.14159;
    double arr2[] = {12.32,1234.435,54.1,4.0};
    int check = 1;
    const char *str = "hello-from-c";
    char cg = 'X';
    int single_int = 42;

    /* Build message using variadic API (passes correct msg pointer) */
    add_variable_to_message(msg,
        SEG_INT, single_int,
        SEG_INT_ARRAY, arr, 3,
        SEG_DOUBLE_ARRAY, arr2, 4,
        SEG_DOUBLE, dval,
        SEG_CHAR, cg,
        SEG_STRING, str,
        SEG_BOOL, check,
        VAR_END
    );
    int arr1[7000];
    for(int i=0;i<7000;i++) arr1[i] = i*10;
    add_variable_to_message(msg,
        SEG_INT_ARRAY, arr1, 7000,VAR_END
    ); 

    /* Debug: print each segment's metadata and raw payload (hex) before sending */
    // printf("[NetSim] Built message: segments=%u total_size=%u\n", msg->segment_count, msg->total_size_in_bytes);
    // SEGMENT *ps = msg->head;
    // unsigned seg_index = 0;
    // while (ps) {
    //     printf("  seg[%u] type=%u count=%u size=%u\n", seg_index, (unsigned)ps->type, (unsigned)ps->count, (unsigned)ps->size_in_bytes);
    //     if (ps->raw && ps->size_in_bytes > 0) {
    //         printf("    raw(hex):");
    //         for (uint32_t i=0;i<ps->size_in_bytes;i++) {
    //             printf(" %02X", (unsigned char) ps->raw[i]);
    //         }
    //         printf("\n");
    //     } else {
    //         printf("    (no raw buffer present)\n");
    //     }
    //     /* for convenience print typed values if present */
    //     if (ps->type == SEG_INT || ps->type == SEG_INT_ARRAY) {
    //         if (ps->ivals) {
    //             for (uint32_t i=0;i<ps->count;i++) printf("      int[%u]=%d\n", i, ps->ivals[i]);
    //         }
    //     } else if (ps->type == SEG_DOUBLE || ps->type == SEG_DOUBLE_ARRAY) {
    //         if (ps->dvals) {
    //             for (uint32_t i=0;i<ps->count;i++) printf("      double[%u]=%f\n", i, ps->dvals[i]);
    //         }
    //     } else if (ps->type == SEG_STRING) {
    //         if (ps->sval) printf("      string='%s'\n", ps->sval);
    //     } else if (ps->type == SEG_BOOL) {
    //         if (ps->bvals) {
    //             for (uint32_t i=0;i<ps->count;i++) printf("      bool[%u]=%u\n", i, (unsigned)ps->bvals[i]);
    //         } else if (ps->ivals) {
    //             /* sometimes we stored bool as ivals for convenience */
    //             for (uint32_t i=0;i<ps->count;i++) printf("      bool[%u]=%d\n", i, ps->ivals[i]);
    //         }
    //     }
    //     seg_index++;
    //     ps = ps->next;
    // }

    /* Send the message and optionally receive reply (use same socket) */
    void *reply = NULL;
    int rc = Send_receive_message(ai_handle, msg, &reply); /* send msg, wait for reply */

    if (rc == 0) {
        if (reply) {
            MESSAGE *r = (MESSAGE*) reply;
            debug_print_message(r,0);
            // printf("[NetSim] Reply: segments=%u total_size=%u\n", r->segment_count, r->total_size_in_bytes);
            // SEGMENT *seg = r->head;
            // while (seg) {
            //     if (seg->raw && seg->size_in_bytes > 0) {
            //         printf("    raw(hex):");
            //         for (uint32_t i=0;i<seg->size_in_bytes;i++) {
            //             printf(" %02X", (unsigned char) seg->raw[i]);
            //         }
            //         printf("\n");
            //     } else {
            //         printf("    (no raw buffer present)\n");
            //     }
            //     switch(seg->type) {
            //         case SEG_INT_ARRAY:
            //             for (uint32_t i=0;i<seg->count;i++)
            //                 printf("  reply int[%u]=%d\n", i, seg->ivals ? seg->ivals[i] : 0);
            //             break;
            //         case SEG_INT:
            //             printf("  reply int=%d\n", seg->ivals ? seg->ivals[0] : 0);
            //             break;
            //         case SEG_DOUBLE_ARRAY:
            //         case SEG_DOUBLE:
            //             for (uint32_t i=0;i<seg->count;i++)
            //                 printf("  reply double[%u]=%f\n", i, seg->dvals ? seg->dvals[i] : 0.0);
            //             break;
            //         case SEG_CHAR:
            //             if (seg->sval) printf("  reply char='%s'\n", seg->sval);
            //             else if (seg->raw && seg->size_in_bytes>0) printf("  reply char='%c'\n", seg->raw[0]);
            //             break;
            //         case SEG_STRING:
            //             printf("  reply string='%s'\n", seg->sval ? seg->sval : "");
            //             break;
            //         case SEG_BOOL:
            //             if (seg->bvals) {
            //                 for (uint32_t i=0;i<seg->count;i++) printf("  reply bool[%u]=%u\n", i, (unsigned)seg->bvals[i]);
            //             } else if (seg->ivals) {
            //                 for (uint32_t i=0;i<seg->count;i++) printf("  reply bool[%u]=%d\n", i, seg->ivals[i]);
            //             } else {
            //                 printf("  reply bool (no storage)\n");
            //             }
            //             break;
            //         default:
            //             printf("  reply unknown-type=%u count=%u size=%u\n", seg->type, seg->count, seg->size_in_bytes);
            //     }
            //     seg = seg->next;
            // }
            free_message(reply);
        } else {
            printf("send succeeded but reply pointer is NULL\n");
        }
    } else {
        printf("Send_receive_message failed (rc=%d). Possibly no reply or socket error.\n", rc);
    }

    /* Clean up */
    free_message(msg);
    /* Bidirectional loop: C can send or receive as needed */
    // printf("[NetSim] Ready for further message exchanges. Entering bidirectional loop...\n");
        /* Example: decide whether to send or receive (replace with your own logic) */
    //     printf("[NetSim] Enter 's' to send, 'r' to receive, 'q' to quit: ");
    //     char cmd[8] = {0};
    //     if (!fgets(cmd, sizeof(cmd), stdin)) break;
    //     if (cmd[0] == 'q') break;
    //     if (cmd[0] == 's') {
    //         /* Build and send a new message */
    //         for(int i=0;i<10;i++){
    //             add_double_to_message(out_msg, (double)i * 1.1);
    //         }
    //         int val = 12342080;
    //         add_int_to_message(out_msg, val);
    //         const char *reply_str = "C says hello again";
    //         add_string_to_message(out_msg, reply_str);
    //         int rc = send_message(ai_handle, out_msg);
    //         if (rc == 0) {
    //             printf("[NetSim] Sent message to Python client.\n");
    //         } else {
    //             printf("[NetSim] send_message failed or connection closed.\n");
    //             free_message(out_msg);
    //             break;
    //         }
    //     } else if (cmd[0] == 'r') {
    //         /* Receive a message from Python */
    //         void *new_msg = NULL;
    //         int rc = receive_message(ai_handle, &new_msg);
    //         if (rc == 0 && new_msg) {
    //             printf("[NetSim] Received new message: segments=%u total_size=%u\n", ((MESSAGE*)new_msg)->segment_count, ((MESSAGE*)new_msg)->total_size_in_bytes);
    //             /* Optionally process new_msg here */
    //             free_message(new_msg);
    //         } else {
    //             printf("[NetSim] Connection closed or error occurred. Exiting loop.\n");
    //             break;
    //         }
    //     }
    // }

    /* Clean up sockets and resources */
    if (ai->conn_fd != SOCK_INVALID) sock_close(ai->conn_fd);
    if (ai->listen_fd != SOCK_INVALID) sock_close(ai->listen_fd);
    free(ai);
    WSACleanup();
    return 0;
}

