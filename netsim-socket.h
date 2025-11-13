/* 
 *
 * Public header for the netsim fragmentation/streaming protocol (Windows).
 * - Provides MESSAGE/SEGMENT structures and APIs for building, sending and
 *   receiving fragment-aware messages over a TCP socket.
 *
 *  Example usage (simplified):
 *    void *ai = Init_AI_ML_Interface(); // creates listen socket and accepts one client
 *    MESSAGE *m = Init_Message();
 *    add_variable_to_message(m, SEG_INT, 42, VAR_END);
 *    MESSAGE *reply = NULL;
 *    send_receive_message(ai, m, &reply);  // send and optionally receive
 *    free_message(reply);
 *    free_message(m);
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Standard headers used by callers */
#include <stdint.h>
#include <stddef.h>

/* ------------------------------
 *  Configurable defaults
 * ------------------------------ */

/* Default TCP port used by the reference implementation; callers may
 * override in build or by defining NETSIM_PORT before including. */
#ifndef NETSIM_PORT
#define NETSIM_PORT 5555
#endif

/* Control strings lengths in implementation: "__ACK__", "__OK__", "__END__" */
#define ACK_BUF 64
#define VAR_END 0xFFFF  /* sentinel used by add_variable_to_message variadic API */

/* Segment type constants */
#define SEG_INT          1
#define SEG_DOUBLE       2
#define SEG_CHAR         3
#define SEG_BOOL         4
#define SEG_STRING       5
#define SEG_INT_ARRAY    6
#define SEG_DOUBLE_ARRAY 7

/* Basic logging macros suitable for inclusion in the implementation. These
 * are provided here so callers that include this header can also log
 * consistently if they wish. Implementation-level logging must call
 * init_logging() to initialize g_log. */
#define LOG_INFO(fmt, ...) do { \
    if (g_log) fprintf(g_log, "INFO: " fmt, ##__VA_ARGS__); \
    if (g_log_to_console) fprintf(stderr, "INFO: " fmt, ##__VA_ARGS__); \
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

/* ------------------------------
 *  Public data structures
 * ------------------------------ */

/**
 * SEGMENT
 *
 * Public segment structure that describes a typed payload. The API exposes
 * this so callers can examine reply messages and access typed buffers.
 *
 * Fields:
 *   - type: SEG_* constant.
 *   - count: number of elements.
 *
 * Representation notes / ownership:
 *   - On the sending side the implementation will populate either the typed
 *     pointers (ivals, dvals, sval, bvals) or the raw buffer (`raw`).
 *   - On the receiving side:
 *       - `raw` points at the raw payload bytes allocated by receive_message.
 *       - For SEG_STRING, the implementation commonly 'moves' raw into sval
 *         (i.e. sets sval == raw and sets raw = NULL) to make string access
 *         convenient. The message free routine knows how to free either.
 *       - Caller must not free segment internals — use free_message().
 */
typedef struct SEGMENT {
    uint16_t type;            /* SEG_* */
    uint32_t count;           /* number-of-elements (1 for single) */

    /* send-side typed pointers (host-order) - optional, set by add_* helpers */
    int    *ivals;            /* int / int array */
    double *dvals;            /* double / double array */
    char   *sval;             /* string (null-terminated) */
    char   *bvals;            /* bool array (one byte per element) */

    /* receive-side raw buffer (allocated by receive_message while assembling) */
    char   *raw;


    uint32_t size_in_bytes;   /* total payload bytes for this segment */
    uint32_t payload_sent;    /* sender-only: bytes already sent when fragmenting */
    struct SEGMENT *next;     /* linked-list in MESSAGE */
} SEGMENT;


/**
 * MESSAGE
 *
 * Linked list container for a list of SEGMENTs.
 *
 * Ownership:
 *   - MESSAGE and contained SEGMENTs returned by receive_message() are
 *     dynamically allocated; free_message() MUST be called by the caller to
 *     avoid leaks.
 */
typedef struct MESSAGE {
    SEGMENT *head;
    SEGMENT *tail;
    SEGMENT *cursor; /* pointer to current segment */
    uint32_t segment_count;
    uint32_t total_size_in_bytes;
} MESSAGE;

/* Opaque-ish handle returned by Init_AI_ML_Interface(). Implementation uses
 * a struct containing sockets; callers treat it as void*. */
typedef struct AI_HANDLE {
    /* Implementation fills these (type is SOCKET in implementation). */
    intptr_t listen_fd;
    intptr_t conn_fd;
} AI_HANDLE;

/* ------------------------------
 *  Initialization / teardown API
 * ------------------------------ */

/**
 * init_logging(path, to_console)
 *
 * Initialize the library logging subsystem. Must be called before using LOG_*.
 * - path: file path for the log file (created/appended as per implementation).
 * - to_console: non-zero positive to also duplicate logs to console.
 * Returns: 0 on success, -1 on failure.
 *
 * Implementation note: the implementation may register an atexit handler to
 * close the log file automatically.
 */
int init_logging(const char *path, int to_console);

/**
 * Init_AI_ML_Interface()
 *
 * Convenience initializer: sets up Winsock (WSAStartup), binds a listening TCP
 * socket on NETSIM_PORT, listens, and performs a single accept() to obtain a
 * client connection. This call blocks in accept() until a client connects.
 *
 * Returns:
 *   - pointer to AI_HANDLE on success (caller treats it as opaque void*).
 *   - NULL on failure.
 *
 * Important:
 *   - Implementation is blocking and single-client by design (example/demo).
 *   - Caller (or implementation) is responsible for closing sockets and
 *     calling WSACleanup() when the application exits.
 */
void* Init_AI_ML_Interface();

/* ------------------------------
 *  Message construction helpers
 * ------------------------------ */

/**
 * Init_Message()
 *
 * Allocate and return a new empty MESSAGE. Caller must later call
 * free_message() to release it.
 */
MESSAGE* Init_Message();

/**
 * free_message(message_v)
 *
 * Free a MESSAGE and all its contained SEGMENTs and buffers. Safe to call
 * with NULL.
 */
void free_message(void* message_v);

/**
 * add_variable_to_message(message_v, ...)
 *
 * Variadic helper to append typed variables to a MESSAGE in a single call.
 * Usage pattern:
 *
 *   add_variable_to_message(m,
 *       SEG_INT, 42,
 *       SEG_INT_ARRAY, int_arr_ptr, (unsigned int)len,
 *       SEG_STRING, "hello", (unsigned int)5,
 *       SEG_DOUBLE_ARRAY, dbl_arr_ptr, (unsigned int)len,
 *       VAR_END);
 *
 * The caller must pass correct argument types for each segment type and must
 * terminate the list with VAR_END (see header constant).
 */
void add_variable_to_message(void *message_v, ...);

/* Get the current segment from a message (if any), and internal cursor shifts to next segment when called.. */
SEGMENT* msg_get_value(MESSAGE* m);

/* Reset the message cursor and segment list. */
void msg_reset(MESSAGE* m);


/* ------------------------------
 *  Send / Receive API (blocking)
 * ------------------------------ */

/**
 * send_receive_message(handle, message_v, outMessage)
 *
 * Combined helper:
 *   - If message_v != NULL: send_message(handle, message_v) is invoked.
 *   - If outMessage != NULL: receive_message(handle, outMessage) is invoked.
 *
 * Parameters:
 *   - handle: pointer returned by Init_AI_ML_Interface() (must be valid).
 *   - message_v: MESSAGE* to send, or NULL to skip sending.
 *   - outMessage: address of MESSAGE* to receive a reply (pass NULL if no reply).
 *
 * Returns:
 *   0 on success (send and/or receive completed),
 *  -1 on error (socket error, validation failure, or unexpected peer behaviour).
 *
 * Memory:
 *   - On success when receiving, *outMessage is assigned to a newly allocated
 *     MESSAGE that the caller must free with free_message().
 */
int send_receive_message(void* handle, void* message_v, void** outMessage);


/* === Convenience accessors (optional helpers) === */

/* Return number of segments in message (0 if message_v is NULL) */
uint32_t get_variablecount(void* message_v);

/* Return SEGMENT* at zero-based index (or NULL). Optionally fill type_ptr and count_ptr. */
void* get_variable_from_message(void* message_v, uint32_t index, uint16_t *type_ptr, uint32_t *count_ptr);

/* === Debugging helpers === */
/* Print segment info to stderr (if want_raw is non-zero positive, print raw payload bytes as hex) */
void debug_print_message(const MESSAGE* m, int want_raw);

/* === End extern "C" === */
#ifdef __cplusplus
}
#endif