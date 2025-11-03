/* netsim_frag.h
 *
 * Public header for the netsim fragmentation/streaming protocol (Windows).
 * - Provides MESSAGE/SEGMENT structures and APIs for building, sending and
 *   receiving fragment-aware messages over a TCP socket.
 *
 * Usage:
 *   #include "netsim_frag.h"
 *
 *   void *ai = Init_AI_ML_Interface(); // creates listen socket and accepts a client
 *   MESSAGE *m = Init_Message();
 *   add_int_to_message(m, 42);
 *   // ... add other variables ...
 *   Send_receive_message(ai, m, &reply); // sends m and optionally receives reply
 *   free_message(reply);
 *   free_message(m);
 *   // close sockets + WSACleanup() handled in implementation or caller as needed
 */

#ifndef NETSIM_FRAG_H
#define NETSIM_FRAG_H

#ifdef __cplusplus
extern "C" {
#endif

/* Platform note: header targets Windows build. The implementation requires
 * <winsock2.h> and WS2_32 libs. */
#include <stdint.h>
#include <stddef.h>

/* Configuration defaults (override in implementation if needed) */
#ifndef NETSIM_PORT
#define NETSIM_PORT 5555
#else
#define NETSIM_PORT NETSIM_PORT
#endif

/* Control strings lengths in implementation: "__ACK__", "__OK__", "__END__" */
#define ACK_BUF 64
#define VAR_END 0xFFFF

/* Segment type constants */
#define SEG_INT          1
#define SEG_DOUBLE       2
#define SEG_CHAR         3
#define SEG_BOOL         4
#define SEG_STRING       5
#define SEG_INT_ARRAY    6
#define SEG_DOUBLE_ARRAY 7

/* Macros for logging */
#define LOG_INFO(fmt, ...) do { \
    if (g_log) fprintf(g_log, "INFO: " fmt, ##__VA_ARGS__); \
    if (g_log_to_console) fprintf(stdout, "INFO: " fmt, ##__VA_ARGS__); \
    if (g_log) fflush(g_log); \
} while(0)

#define LOG_WARN(fmt, ...) do { \
    if (g_log) fprintf(g_log, "WARN: " fmt, ##__VA_ARGS__); \
    if (g_log_to_console) fprintf(stderr, "WARN: " fmt, ##__VA_ARGS__); \
    if (g_log) fflush(g_log); \
} while(0)

#define LOG_ERR(fmt, ...) do { \
    if (g_log) fprintf(g_log, "ERROR: " fmt, ##__VA_ARGS__); \
    if (g_log_to_console) fprintf(stderr, "ERROR: " fmt, ##__VA_ARGS__); \
    if (g_log) fflush(g_log); \
} while(0)

/* Forward-declare sock_t for use in API docs (actual typedef exists in implementation) */
typedef void* sock_placeholder_t;

/* SEGMENT and MESSAGE structures (public - caller may inspect fields) */
typedef struct SEGMENT {
    uint16_t type;            /* SEG_* */
    uint32_t count;           /* number-of-elements (1 for single) */

    /* send-side typed pointers (host-order) - optional, set by add_* helpers */
    int    *ivals;            /* int / int array */
    double *dvals;            /* double / double array */
    char   *sval;             /* string (null-terminated) */
    char   *bvals;            /* bool array (one byte per element) */

    /* receive-side raw buffer (allocated by receive_message while assembling) */
    char   *raw;              /* raw payload bytes (size = size_in_bytes) */

    uint32_t size_in_bytes;   /* total payload bytes for this segment */
    uint32_t payload_sent;    /* sender-only: bytes already sent when fragmenting */
    struct SEGMENT *next;
} SEGMENT;

typedef struct MESSAGE {
    SEGMENT *head;
    SEGMENT *tail;
    SEGMENT *cursor; /* pointer to current segment */
    uint32_t segment_count;
    uint32_t total_size_in_bytes;
} MESSAGE;

/* Opaque socket handle returned by Init_AI_ML_Interface.
 * On Windows this contains listen_fd and conn_fd sockets. */
typedef struct AI_HANDLE {
    /* Implementation fills these (type is SOCKET in implementation). */
    intptr_t listen_fd;
    intptr_t conn_fd;
} AI_HANDLE;

/* === Initialization / teardown === */

/* Initialize logging subsystem (call before any logging). path tells where to write logs,
 * if to_console is non-zero, also log to stdout/stderr. Returns 0 on success, -1 on failure. */
int init_logging(const char *path, int to_console);

/* Get the current value segment from a message (if any). */
SEGMENT* msg_get_value(MESSAGE* m);

/* Reset the message cursor and segment list. */
void msg_reset(MESSAGE* m);


/* Initialize Winsock, create listening socket, accept a client and return AI_HANDLE*.
 * This is a convenience helper that does accept() internally (blocking).
 * Caller must eventually cleanup sockets and call WSACleanup() (implementation may or may not do it).
 * Returns NULL on failure. */
void* Init_AI_ML_Interface();

/* Free a MESSAGE and its segments (frees segment->raw or typed buffers if allocated).
 * Safe to call with NULL. */
void free_message(void* message_v);

/* Initialize an empty MESSAGE object (caller must free via free_message). */
MESSAGE* Init_Message();

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
void add_variable_to_message(void *message_v, ...);

/* === Sending / receiving helpers === */

/* Fragment-aware pack helper (implementation-level): writes up to max_size bytes
 * of chunk payload into outbuf from *segment_ptr onwards. Updates *segment_ptr to
 * point to the first segment not fully sent. Returns number of payload bytes written.
 * (Exposed for completeness but typically you will not call this directly) */

/* send_message: fragment-aware sender. Iterates segments in message_v and sends one or more
 * length-prefixed chunks per segment. Blocks waiting for per-chunk ACKs and a final OK.
 * Returns 0 on success, -1 on error. */

/* receive_message: blocking reassembler. Reads length-prefixed chunks, sends ACK after each,
 * assembles full SEGMENTs into a dynamically allocated MESSAGE object and returns it via outMessage.
 * When it receives the END marker it replies OK and returns the assembled message.
 * Returns 0 on success (and *outMessage set), -1 on error or connection closed.
 *
 * Note: caller must free returned MESSAGE using free_message().
 */

/* Combined helper: send_message if message_v != NULL, then receive_message if outMessage != NULL.
 * Returns 0 on success, -1 on error. */
int send_receive_message(void* handle, void* message_v, MESSAGE** outMessage);

/* === Convenience accessors (optional helpers) === */

/* Return number of segments in message (0 if message_v is NULL) */
uint32_t get_variablecount(void* message_v);

/* Return SEGMENT* at zero-based index (or NULL). Optionally fill type_ptr and count_ptr. */
void* get_variable_from_message(void* message_v, uint32_t index, uint16_t *type_ptr, uint32_t *count_ptr);

/* === Debugging helpers === */
/* Print segment info to stderr (if want_raw is non-zero, print raw payload bytes as hex) */
void debug_print_message(const MESSAGE* m, int want_raw);

/* === Lightweight conversion helpers for external use (take a pointer to a serialized
 * segment buffer starting at the 6-byte header, i.e. pointer layout: [2 bytes type][4 bytes count][payload...]).
 * These helpers assume the pointer points at the beginning of the serialized segment buffer; they read
 * payload bytes at offset +6.
 *
 * If you use the MESSAGE/SEGMENT structures from receive_message, you may not need these helpers.
 */

/* === End extern "C" === */
#ifdef __cplusplus
}
#endif

#endif /* NETSIM_FRAG_H */
