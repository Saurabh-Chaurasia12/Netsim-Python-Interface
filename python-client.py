# netsim_client.py
# Python 3.x
# Matches the netsim_frag_windows.c protocol:
# - 4-byte length prefix (network order) for each chunk
# - chunk payload structure: [1 byte flag][...]
#   flag==1 => header present: [2 bytes type][4 bytes count] then payload fragment
#   flag==0 => continuation payload for last segment
# - per-chunk ACK: "__ACK__" (6 bytes)
# - end marker chunk payload: "__END__" -> server replies "__OK__"
#
# Usage:
#  - Run the Windows C server first
#  - Then run this client: python netsim_client.py
#
import os
import socket
import struct
from typing import List, Tuple, Optional
import time
import logging
import os
from logging.handlers import RotatingFileHandler

HOST = '127.0.0.1'
PORT = 5555

ACK_BYTES = b"__ACK__"
OK_BYTES  = b"__OK__"
END_BYTES = b"__END__"

MAX_CHUNK_PAYLOAD = 512  # must match C side

# Segment type constants (mirror C)
SEG_INT          = 1
SEG_DOUBLE       = 2
SEG_CHAR         = 3
SEG_BOOL         = 4
SEG_STRING       = 5
SEG_INT_ARRAY    = 6
SEG_DOUBLE_ARRAY = 7

# Helper: exact recv
def recv_all(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)

# ---- Data classes for segments/messages ----
class Segment:
    def __init__(self, seg_type:int, count:int, raw_payload:bytes=None):
        self.type = seg_type
        self.count = count
        self.size_in_bytes = self._compute_size()
        # representation: store typed values once decoded
        self.ivalues: Optional[List[int]] = None
        self.dvalues: Optional[List[float]] = None
        self.svalue: Optional[str] = None
        # temporary raw builder used during reassembly
        if raw_payload is None:
            self._raw = bytearray(self.size_in_bytes if self.size_in_bytes>0 else 1)
        else:
            self._raw = bytearray(raw_payload)

    def _compute_size(self) -> int:
        if self.type in (SEG_INT, SEG_INT_ARRAY):
            return 4 * self.count
        if self.type in (SEG_DOUBLE, SEG_DOUBLE_ARRAY):
            return 8 * self.count
        if self.type == SEG_STRING:
            # C side stores length + 1 for null terminator
            return self.count + 1
        if self.type in (SEG_BOOL, SEG_CHAR):
            return 1 * self.count
        return self.count

    def decode_from_raw(self):
        # decode raw buffer into typed fields (call when raw buffer is fully filled)
        b = bytes(self._raw)
        if self.type in (SEG_INT, SEG_INT_ARRAY):
            vals = []
            for i in range(self.count):
                (u,) = struct.unpack_from('!I', b, i*4)  # network-order 4 bytes
                # interpret bit-pattern as signed 32-bit
                if u & 0x80000000:
                    vals.append(struct.unpack('!i', struct.pack('!I', u))[0])
                else:
                    vals.append(struct.unpack('!i', struct.pack('!I', u))[0])
            self.ivalues = vals
        elif self.type in (SEG_DOUBLE, SEG_DOUBLE_ARRAY):
            vals = []
            for i in range(self.count):
                (d,) = struct.unpack_from('!d', b, i*8)
                vals.append(d)
            self.dvalues = vals
        elif self.type == SEG_STRING:
            # strip at first null
            s = b.split(b'\x00',1)[0].decode(errors='replace')
            self.svalue = s
        elif self.type == SEG_CHAR:
            # single char or char array
            self.svalue = b.split(b'\x00',1)[0].decode(errors='replace')
        elif self.type == SEG_BOOL:
            vals = [ (1 if b[i] != 0 else 0) for i in range(self.count) ]
            self.ivalues = vals
        else:
            # raw fallback
            self.svalue = b

    def __repr__(self):
        if self.type in (SEG_INT, SEG_INT_ARRAY):
            return f"Segment(INT, count={self.count}, vals={self.ivalues})"
        if self.type in (SEG_DOUBLE, SEG_DOUBLE_ARRAY):
            return f"Segment(DOUBLE, count={self.count}, vals={self.dvalues})"
        if self.type == SEG_STRING:
            return f"Segment(STRING, '{self.svalue}')"
        if self.type == SEG_CHAR:
            return f"Segment(CHAR, '{self.svalue}')"
        if self.type == SEG_BOOL:
        # boolean array or single bool
            if self.ivalues is not None:
                return f"Segment(BOOL, count={self.count}, vals={self.ivalues})"
            # fallback: show raw bytes
            return f"Segment(BOOL, count={self.count}, raw={self._raw!r})"
        return f"Segment(type={self.type}, count={self.count}, vals={self.ivalues})"

class Message:
    def __init__(self):
        self.segments: List[Segment] = []
        self._cursor_idx = 0  # for future use

    def add_segment(self, seg: Segment):
        self.segments.append(seg)

    def __repr__(self):
        return f"Message(segments={self.segments})"
    
    def reset_cursor(self):
        """Reset the internal cursor to start reading from the first segment."""
        self._cursor_idx = 0
    
    def get_next_segment(self):
        """Return next Segment object and advance cursor, or None if finished."""
        if self._cursor_idx >= len(self.segments):
            return None
        s = self.segments[self._cursor_idx]
        self._cursor_idx += 1
        return s

    def get_value(self):
        """
        Return tuple (python_value) for the next segment and advance cursor.
        seg_type is an integer (SEG_*). python_value types:
          - SEG_INT -> int
          - SEG_DOUBLE -> float
          - SEG_STRING/SEG_CHAR -> str
          - SEG_BOOL -> bool or list[bool]
          - SEG_INT_ARRAY -> list[int]
          - SEG_DOUBLE_ARRAY -> list[float]
          - unknown -> raw bytes
        Returns None when no segments left.
        """
        seg = self.get_next_segment()
        if seg is None:
            return None

        # If decode_from_raw wasn't called yet, call it
        if (seg.type in (SEG_INT, SEG_INT_ARRAY) and seg.ivalues is None) \
           or (seg.type in (SEG_DOUBLE, SEG_DOUBLE_ARRAY) and seg.dvalues is None) \
           or (seg.type in (SEG_STRING, SEG_CHAR) and seg.svalue is None) \
           or (seg.type == SEG_BOOL and seg.ivalues is None):
            # decode now (safe; decode_from_raw uses seg._raw)
            seg.decode_from_raw()

        if seg.type == SEG_INT:
            return (seg.ivalues[0] if seg.ivalues is not None else int.from_bytes(bytes(seg._raw[:4]), 'big', signed=True))
        if seg.type == SEG_DOUBLE:
            return (seg.dvalues[0] if seg.dvalues is not None else struct.unpack('!d', bytes(seg._raw[:8]))[0])
        if seg.type == SEG_STRING:
            return seg.svalue
        if seg.type == SEG_CHAR:
            return seg.svalue
        if seg.type == SEG_BOOL:
            if seg.count == 1:
                # single bool -> return bool
                if seg.ivalues is not None:
                    return bool(seg.ivalues[0])
                return bool(seg._raw[0])
            else:
                if seg.ivalues is not None:
                    return [bool(x) for x in seg.ivalues]
                return [bool(b) for b in seg._raw]
        if seg.type == SEG_INT_ARRAY:
            if seg.ivalues is not None:
                return list(seg.ivalues)
            # fallback decode from raw
            arr = []
            for i in range(seg.count):
                arr.append(struct.unpack_from('!i', seg._raw, i*4)[0])
            return arr
        if seg.type == SEG_DOUBLE_ARRAY:
            if seg.dvalues is not None:
                return list(seg.dvalues)
            arr = []
            for i in range(seg.count):
                arr.append(struct.unpack_from('!d', seg._raw, i*8)[0])
            return arr

        # default: return raw bytes
        return bytes(seg._raw)

# ---- Sender helpers: pack segments into fragmented chunks ----
def pack_segment_fragmentwise(seg: Segment, start_offset: int, max_payload_bytes: int) -> Tuple[bytes,int]:
    """
    Pack from seg._raw starting at start_offset up to the limit defined by max_payload_bytes.
    Returns (chunk_payload_bytes, bytes_written_count).
    The caller is responsible for writing the 1-byte flag + header when start_offset==0.
    For ints/doubles this function will only include whole elements.
    """
    # Not used directly by external code; send_message below builds chunks by iterating segments.
    raise NotImplementedError  # implementation is done in send_message (inline) for clarity

def setup_logging(log_path="netsim_python.log",level=logging.INFO,max_bytes=10 * 1024 * 1024,backup_count=3,to_console=True,to_file=False):
    """
    Initialize and configure logging for the Python-side NetSim interface.

    Parameters:
        log_path (str): Path to the log file (default: "netsim_python.log").
        level (int): Logging level (e.g., logging.DEBUG, logging.INFO).
        max_bytes (int): Maximum log file size before rotation (default: 10 MB).
        backup_count (int): Number of rotated log files to keep.
        to_console (bool): If True, also print logs to console.
        to_file (bool): If True, write logs to a file as well.

    Usage:
        setup_logging(level=logging.DEBUG, to_file=True)
        logging.info("Python interface initialized")

    Notes:
        - Should be called once before any other NetSim–Python communication.
        - Enables detailed debugging of message exchange and socket behavior.
    """

    logger = logging.getLogger()
    logger.setLevel(level)

    # Remove old handlers to avoid duplicates
    if logger.handlers:
        for h in logger.handlers[:]:
            logger.removeHandler(h)

    # Optional file logging
    if to_file:
        # Start fresh each run
        if os.path.exists(log_path):
            os.remove(log_path)

        fh = RotatingFileHandler(
            log_path, mode='w', maxBytes=max_bytes,
            backupCount=backup_count, encoding='utf-8'
        )
        fh.setLevel(level)
        fmt = logging.Formatter("[%(levelname)s] %(message)s")
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    # Optional console logging
    if to_console:
        ch = logging.StreamHandler()
        ch.setLevel(level)
        fmt = logging.Formatter("[%(levelname)s] %(message)s")
        ch.setFormatter(fmt)
        logger.addHandler(ch)

    return logger

logger = setup_logging()

def debug_print_segment(seg, want_raw):
    """
    Pretty-print all details of one segment for debugging.
    """
    if seg.type == SEG_INT:
        type_name = "SEG_INT"
    elif seg.type == SEG_DOUBLE:
        type_name = "SEG_DOUBLE"
    elif seg.type == SEG_INT_ARRAY:
        type_name = "SEG_INT_ARRAY"
    elif seg.type == SEG_DOUBLE_ARRAY:
        type_name = "SEG_DOUBLE_ARRAY"
    elif seg.type == SEG_STRING:
        type_name = "SEG_STRING"
    elif seg.type == SEG_CHAR:
        type_name = "SEG_CHAR"
    elif seg.type == SEG_BOOL:
        type_name = "SEG_BOOL"
    else:
        type_name = f"UNKNOWN({seg.type})"

    # print("\033[96m" + "═" * 60 + "\033[0m")
    print(f"Segment Debug Info : \ntype={type_name} \ncount={seg.count} \nsize={seg.size_in_bytes}")
    # print("─" * 60)

    if want_raw>0:
        # Raw bytes
        if getattr(seg, "_raw", None) is not None:
            print(f"Raw bytes (hex): {seg._raw.hex()}")
            print(f"Total raw length: {len(seg._raw)}")
        else:
            print("Raw buffer: None")

    # Value fields
    if getattr(seg, "ivalues", None) is not None:
        print(f"Int values: {seg.ivalues}")
    if getattr(seg, "dvalues", None) is not None:
        print(f"Double values: {seg.dvalues}")
    if getattr(seg, "bvalues", None) is not None:
        print(f"Bool values: {seg.bvalues}")
    if getattr(seg, "svalue", None) is not None:
        sdisp = seg.svalue.replace("\n", "\\n")[:100]
        if(seg.type == SEG_CHAR):
            print(f"Char value: '{sdisp}'")
        else : print(f"String value: '{sdisp}'")

    # print("\033[96m" + "═" * 60 + "\033[0m\n")


def debug_print_message(msg, want_raw, title: str = "Message Debug Info"):
    """
    Print the detailed contents of a MESSAGE object for debugging.

    Parameters:
        msg (Message): The message object received or to be sent.
        want_raw (int): Should be non-zero positive to print raw byte payloads in hexadecimal.
        title (str): Optional title to display before message dump.

    Usage:
        debug_print_message(message, want_raw=0)
        debug_print_message(reply_msg, want_raw=1, title="Received Reply")

    Notes:
        - Useful for verifying correct encoding/decoding of segments.
        - Each segment (int, double, bool, string, etc.) is displayed with its type and count.
    """
    # print("\n" + "="*80)
    print(f"{title}")
    print("\n")
    # print("="*80)

    for i, seg in enumerate(msg.segments):
        print(f"Segment {i+1}/{len(msg.segments)}")
        debug_print_segment(seg,want_raw)  # use our detailed segment printer
        print("\n")

    # print("="*80 + "\n")

def validate_segment(seg: Segment) -> bool:
    """Return True if segment is internally consistent and ready to send."""
    if seg is None:
        return False
    # compute expected bytes
    if seg.type in (SEG_INT, SEG_INT_ARRAY):
        expected = 4 * seg.count
    elif seg.type in (SEG_DOUBLE, SEG_DOUBLE_ARRAY):
        expected = 8 * seg.count
    elif seg.type == SEG_STRING:
        expected = seg.count + 1   # count is strlen without null
    elif seg.type == SEG_CHAR:
        expected = seg.count       # char array has no terminator
    elif seg.type == SEG_BOOL:
        expected = 1 * seg.count
    else:
        expected = seg.count

    # if raw exists, check its length
    if hasattr(seg, "_raw") and seg._raw is not None:
        if len(seg._raw) != expected:
            logger.error(f"validate_segment_for_send: raw length {len(seg._raw)} != expected {expected} for type {seg.type}")
            return False
    else:
        # if no raw, check typed lists
        if seg.type in (SEG_INT, SEG_INT_ARRAY):
            if seg.ivalues is None or len(seg.ivalues) != seg.count:
                logger.error("validate_segment_for_send: ivals missing or length mismatch")
                return False
        elif seg.type in (SEG_DOUBLE, SEG_DOUBLE_ARRAY):
            if seg.dvalues is None or len(seg.dvalues) != seg.count:
                logger.error("validate_segment_for_send: dvals missing or length mismatch")
                return False
        elif seg.type == SEG_STRING:
            if seg.svalue is None or len(seg.svalue) != seg.count:
                logger.error("validate_segment_for_send: svalue missing or length mismatch")
                return False
        elif seg.type == SEG_BOOL:
            if seg.ivalues is None or len(seg.ivalues) != seg.count:
                logger.error("validate_segment_for_send: bool ivals missing or length mismatch")
                return False
    # element alignment checks
    if seg.type in (SEG_INT, SEG_INT_ARRAY) and expected % 4 != 0:
        logger.error("validate_segment_for_send: int segment byte size not divisible by 4")
        return False
    if seg.type in (SEG_DOUBLE, SEG_DOUBLE_ARRAY) and expected % 8 != 0:
        logger.error("validate_segment_for_send: double segment byte size not divisible by 8")
        return False

    return True

def validate_message_for_send(msg: Message) -> bool:
    for seg in msg.segments:
        if not validate_segment(seg):
            logger.error("validate_message_for_send: segment validation failed")
            return False
    return True

def send_message(sock: socket.socket, message: Message) -> bool:
    if not validate_message_for_send(message):
        logger.error("send_message: validation failed, aborting send")
        return False
    
    for seg in message.segments:
        # prepare raw buffer if not exists
        if not hasattr(seg,'_raw') or seg._raw is None:
            seg._raw = bytearray()
            if seg.type in (SEG_INT, SEG_INT_ARRAY):
                for v in seg.ivalues or []:
                    seg._raw.extend(struct.pack('!i', v))
            elif seg.type in (SEG_DOUBLE, SEG_DOUBLE_ARRAY):
                for d in seg.dvalues or []:
                    seg._raw.extend(struct.pack('!d', d))
            elif seg.type == SEG_CHAR:
                seg._raw = bytearray(seg.svalue.encode() if seg.svalue else b'\x00')
            elif seg.type == SEG_STRING:
                seg._raw = bytearray((seg.svalue or '').encode() + b'\x00')
            elif seg.type == SEG_BOOL:
                for b in seg.ivalues or []:
                    seg._raw.append(1 if b else 0)
            seg.size_in_bytes = len(seg._raw)

        sent = 0
        while sent < seg.size_in_bytes:
            buf = bytearray()
            if sent == 0:
                buf.append(1)
                buf.extend(struct.pack('!H', seg.type))
                buf.extend(struct.pack('!I', seg.count))
            else:
                buf.append(0)

            header_len = len(buf)
            space = MAX_CHUNK_PAYLOAD - header_len
            remaining = seg.size_in_bytes - sent
            if seg.type in (SEG_INT, SEG_INT_ARRAY):
                copy_bytes = min(space - (space %4), remaining)
            elif seg.type in (SEG_DOUBLE, SEG_DOUBLE_ARRAY):
                copy_bytes = min(space - (space %8), remaining)
            else:
                copy_bytes = min(space, remaining)

            buf.extend(seg._raw[sent:sent+copy_bytes])
            try:
                sock.sendall(struct.pack('!I', len(buf)))
                sock.sendall(buf)
            except Exception as e:
                logger.error("send failed:", e)
                return False

            logger.info("Chunk sent, Waiting for ACK...")
            ack = recv_all(sock, len(ACK_BYTES))
            if ack != ACK_BYTES:
                logger.error("unexpected ACK", ack)
                return False
            logger.info("ACK received.")
            sent += copy_bytes

    # send END
    try:
        logger.info("Sending END marker...")
        sock.sendall(struct.pack('!I', len(END_BYTES)))
        sock.sendall(END_BYTES)
    except Exception as e:
        logger.error("send END failed:", e)
        return False
    logger.info("END ACK Received.")
    ok = recv_all(sock, len(OK_BYTES))
    return ok==OK_BYTES


# ---- Receiver: streaming parser & reassembly ----
def receive_message(sock: socket.socket) -> Optional[Message]:
    """
    Blocking: read length-prefixed chunks, reassemble segments.
    Replies '__ACK__' after each chunk; when '__END__' chunk seen replies '__OK__' and returns assembled Message.
    Returns Message on success, None on error/connection closed.
    """
    msg = Message()
    current_segment: Optional[Segment] = None
    current_filled = 0  # bytes filled for the current segment's raw buffer

    while True:
        # 1) read 4-byte length
        ln_bytes = recv_all(sock, 4)
        if ln_bytes is None:
            logger.warning("connection closed while reading length")
            return None
        (chunk_len,) = struct.unpack('!I', ln_bytes)
        if chunk_len == 0:
            # ack and continue
            sock.sendall(ACK_BYTES)
            continue
        # 2) read exactly chunk_len bytes payload
        logger.info("Receiving chunk....")
        chunk = recv_all(sock, chunk_len)
        if chunk is None:
            logger.warning("connection closed while reading chunk payload")
            return None

        # check END marker
        if chunk_len == len(END_BYTES) and chunk == END_BYTES:
            # send OK and return assembled message
            logger.info("received END marker, sending END ACK...")
            sock.sendall(OK_BYTES)
            for seg in msg.segments:
                if not validate_segment(seg):
                    logger.error("validate_segment (receive): segment validation failed")
                    return None
            return msg

        # parse fragment(s) inside chunk
        pos = 0
        while pos < chunk_len:
            # read 1-byte flag
            flag = chunk[pos]
            pos += 1
            if flag == 1:
                # header must be present: 2 + 4 bytes
                if pos + 6 > chunk_len:
                    logger.error("malformed chunk: header incomplete")
                    return None
                seg_type = struct.unpack_from('!H', chunk, pos)[0]; pos += 2
                seg_count = struct.unpack_from('!I', chunk, pos)[0]; pos += 4
                # compute payload size
                if seg_type in (SEG_INT, SEG_INT_ARRAY):
                    payload_bytes = 4 * seg_count
                elif seg_type in (SEG_DOUBLE, SEG_DOUBLE_ARRAY):
                    payload_bytes = 8 * seg_count
                elif seg_type == SEG_STRING:
                    payload_bytes = seg_count + 1
                elif seg_type in (SEG_BOOL, SEG_CHAR):
                    payload_bytes = 1 * seg_count
                else:
                    payload_bytes = seg_count
                # create segment and allocate raw buffer
                current_segment = Segment(seg_type, seg_count)
                current_segment._raw = bytearray(payload_bytes if payload_bytes>0 else 1)
                current_filled = 0
                # copy available payload bytes in this chunk into current_segment._raw
                avail = chunk_len - pos
                want = payload_bytes - current_filled
                to_copy = min(avail, want)
                if to_copy > 0:
                    current_segment._raw[current_filled:current_filled+to_copy] = chunk[pos:pos+to_copy]
                    pos += to_copy
                    current_filled += to_copy
                # if completed now, decode and append
                if current_filled >= payload_bytes:
                    current_segment.decode_from_raw()
                    msg.add_segment(current_segment)
                    current_segment = None
                    current_filled = 0
            elif flag == 0:
                # continuation payload for current segment
                if current_segment is None:
                    logger.warning("received continuation fragment but no active segment")
                    return None
                avail = chunk_len - pos
                want = current_segment.size_in_bytes - current_filled
                to_copy = min(avail, want)
                if to_copy > 0:
                    current_segment._raw[current_filled:current_filled+to_copy] = chunk[pos:pos+to_copy]
                    pos += to_copy
                    current_filled += to_copy
                if current_filled >= current_segment.size_in_bytes:
                    current_segment.decode_from_raw()
                    msg.add_segment(current_segment)
                    current_segment = None
                    current_filled = 0
            else:
                logger.error("unknown fragment flag", flag)
                return None
        # after processing chunk, send ACK
        logger.info("Sending ACK...")
        sock.sendall(ACK_BYTES)
    # unreachable

def send_and_receive(sock: socket.socket, message, expect_reply: bool = True):
    """
    Send `message` or wait for reply.
    Parameters:
        sock (socket.socket): Active TCP socket connected to NetSim.
        message (Message): Message object containing data to send. if None, only waits for reply.
        expect_reply (bool): If True, waits for and returns a MESSAGE reply.

    Returns:
        If expect_reply is True and a reply is received, returns the Message object.
        If no reply is expected, returns True on successful send.

    Usage:
        reply = send_and_receive(sock, message, expect_reply=True)
        success = send_and_receive(sock, None, expect_reply=False)

    """

    if(message is not None):
        logger.info("Sending message...")
        send_ok = send_message(sock, message)
        if not send_ok:
            return True
    if expect_reply:
        logger.info("Waiting for reply...")
        reply = receive_message(sock)
        if reply is not None:
            logger.info("Received reply")
            return reply
    return True

def add_variable(message: Message, var_type:int, value, length:int=0):
    """
    Append a variable or array to a message before sending to NetSim.

    Parameters:
        message (Message): The message to which the variable is added.
        var_type (int): One of SEG_INT, SEG_DOUBLE, SEG_BOOL, SEG_STRING, etc.
        value: The variable or list/array of values to send.
        length (int): Number of elements if sending an array (ignored for single values).

    Usage:
        msg = Message()
        add_variable(msg, SEG_INT, 123)
        add_variable(msg, SEG_STRING, "Hello")
        add_variable(msg, SEG_DOUBLE_ARRAY, [1.1, 2.2, 3.3], length=3)

    Notes:
        - Must call add_variable() for each segment before send_and_receive().
        - Each variable type is automatically encoded to the correct binary format.
    """
    # infer length for arrays if caller didn't pass it
    if var_type in (SEG_INT_ARRAY, SEG_DOUBLE_ARRAY) and length == 0:
        try:
            length = len(value)
        except Exception:
            raise ValueError("Array type requires an iterable value or explicit length")

    if var_type == SEG_INT:
        seg = Segment(SEG_INT, 1)
        seg.ivalues = [int(value)]
        # signed 32-bit network order
        seg._raw = bytearray(struct.pack('!i', seg.ivalues[0]))
        seg.size_in_bytes = len(seg._raw)

    elif var_type == SEG_DOUBLE:
        seg = Segment(SEG_DOUBLE, 1)
        seg.dvalues = [float(value)]
        seg._raw = bytearray(struct.pack('!d', seg.dvalues[0]))
        seg.size_in_bytes = len(seg._raw)

    elif var_type == SEG_STRING:
        s = str(value)
        seg = Segment(SEG_STRING, len(s))   # count==len (C expects count, C will add +1)
        seg.svalue = s
        seg._raw = bytearray(s.encode() + b'\x00')   # include null terminator
        seg.size_in_bytes = len(seg._raw)

    elif var_type == SEG_CHAR:
        s = str(value)  # ensure it's string/char
        if len(s) != 1:
            raise ValueError("SEG_CHAR expects a single character")
        seg = Segment(SEG_CHAR, 1)  # count = 1
        seg.svalue = s
        seg._raw = bytearray(s.encode()) 
        seg.size_in_bytes = len(seg._raw)

    elif var_type == SEG_BOOL:
        seg = Segment(SEG_BOOL, 1)
        b = 1 if value else 0
        seg.ivalues = [b]
        seg._raw = bytearray(bytes([1 if b else 0]))
        seg.size_in_bytes = len(seg._raw)

    elif var_type == SEG_INT_ARRAY:
        seg = Segment(SEG_INT_ARRAY, length)
        seg.ivalues = [int(x) for x in value]
        seg._raw = bytearray()
        for v in seg.ivalues:
            # pack signed 32-bit network order (C uses htonl on uint32; two's complement ok)
            seg._raw.extend(struct.pack('!i', v))
        seg.size_in_bytes = len(seg._raw)

    elif var_type == SEG_DOUBLE_ARRAY:
        seg = Segment(SEG_DOUBLE_ARRAY, length)
        # ensure floats (python float -> C double)
        seg.dvalues = [float(x) for x in value]
        seg._raw = bytearray()
        for d in seg.dvalues:
            seg._raw.extend(struct.pack('!d', d))
        seg.size_in_bytes = len(seg._raw)

    else:
        raise ValueError("unknown type")

    # final safety checks
    if not hasattr(seg, '_raw') or seg._raw is None:
        seg._raw = bytearray(seg.size_in_bytes if seg.size_in_bytes>0 else 0)
    if seg.size_in_bytes == 0:
        seg.size_in_bytes = len(seg._raw)

    message.add_segment(seg)

def connect(host: str, port: int,
            retries: int = 6,
            backoff: float = 1.0,
            timeout: Optional[float] = 1000000.0,
            keepalive: bool = True) -> socket.socket:
    """
    Establish a TCP connection from Python to the NetSim socket server.

    Parameters:
        host (str): IP address or hostname where NetSim is running.
        port (int): TCP port number (must match the port in NetSim’s Init_AI_ML_Interface()).
        retries (int): Number of connection attempts before giving up (default: 6).
        backoff (float): Seconds to wait between retries.
        timeout (float | None): Socket timeout in seconds (default: large value to block indefinitely).
        keepalive (bool): Enables TCP keepalive to detect dead connections.

    Returns:
        socket.socket: Connected socket ready for send_and_receive().

    Usage:
        sock = connect("127.0.0.1", 5555)
        print("Connected to NetSim")
        ...
        sock.close()

    Notes:
        - Must be called before attempting any data exchange.
        - Works across computers on the same network (ensure firewall allows the port).
        - To connect across networks, ensure both systems can reach each other’s IP and port.
    """
    last_exc = None
    attempt = 0
    while attempt < retries:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            # keepalive option
            if keepalive:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                # tuning keepalive intervals is platform-specific; this sets only the flag.
            # set socket to blocking for send/recv normally but keep timeout for recv_all if desired
            s.settimeout(timeout)
            return s
        except Exception as e:
            logger.error(f"connect attempt {attempt+1} failed: {e}")
            logger.info("Retrying...")
            last_exc = e
            attempt += 1
            if attempt >= retries:
                break
            # exponential backoff jitter
            time.sleep(backoff * (2 ** (attempt - 1)) * (0.9 + 0.2 * (attempt % 2)))
    raise ConnectionError(f"connect failed after {retries} attempts: {last_exc!r}")


s = connect(HOST,PORT)
msg = Message()
add_variable(msg, SEG_INT_ARRAY, [100,200,300], 3)
add_variable(msg, SEG_STRING, "hello-from-python")
add_variable(msg, SEG_DOUBLE, 2.7182818)
add_variable(msg, SEG_INT, 42)
add_variable(msg, SEG_BOOL, 1)
add_variable(msg, SEG_CHAR, 'A')
add_variable(msg, SEG_DOUBLE_ARRAY, [2.14,4.456,1.865])
c=[]
for u in range(800):
    c.append(u*10)
add_variable(msg, SEG_INT_ARRAY, c, 800)
# print(msg.get_value())
# print(msg.get_value())
# print(msg)
# msg.reset_cursor()
# print(msg)

print("eglqbnqj")
print(send_and_receive(s, None,True))
print(send_and_receive(s, msg,False))
print(send_and_receive(s, None,True))
print(send_and_receive(s, msg,False))

# s.close()




# while(1):
#     reply = receive_message(s)  
# reply = receive_message(s)
# debug_print_message(reply,0)

# ok = send_message(s, msg)
    


# while True:
#     cmd = input("Enter command (send/receive/quit): ").strip().lower()
#     if cmd == "send":
#         demo_send_receive(s)
#     elif cmd == "receive":
#         reply = receive_message(s)
#         print("Received reply:", reply)
#     elif cmd == "quit":
#         print("Exiting.")
#         break
#     else:
#         print("Unknown command. Please enter 'send', 'receive', or 'quit'.")