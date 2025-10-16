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
import socket
import struct
from typing import List, Tuple, Optional

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

    def add_segment(self, seg: Segment):
        self.segments.append(seg)

    def __repr__(self):
        return f"Message(segments={self.segments})"

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

def debug_print_segment(seg: Segment):
    print(f"  seg type={seg.type} count={seg.count} size={seg.size_in_bytes}")
    print("   raw(hex):", seg._raw.hex())
    if seg.ivalues is not None: print("   ivalues:", seg.ivalues)
    if seg.dvalues is not None: print("   dvalues:", seg.dvalues)
    if seg.svalue is not None: print("   svalue:", seg.svalue)

def send_message(sock: socket.socket, message: Message) -> bool:
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
                print("send failed:", e)
                return False

            ack = recv_all(sock, len(ACK_BYTES))
            if ack != ACK_BYTES:
                print("unexpected ACK", ack)
                return False
            sent += copy_bytes

    # send END
    try:
        sock.sendall(struct.pack('!I', len(END_BYTES)))
        sock.sendall(END_BYTES)
    except Exception as e:
        print("send END failed:", e)
        return False
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
            print("connection closed while reading length")
            return None
        (chunk_len,) = struct.unpack('!I', ln_bytes)
        if chunk_len == 0:
            # ack and continue
            sock.sendall(ACK_BYTES)
            continue
        # 2) read exactly chunk_len bytes payload
        chunk = recv_all(sock, chunk_len)
        if chunk is None:
            print("connection closed while reading chunk payload")
            return None

        # check END marker
        if chunk_len == len(END_BYTES) and chunk == END_BYTES:
            # send OK and return assembled message
            sock.sendall(OK_BYTES)
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
                    print("malformed chunk: header incomplete")
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
                    print("received continuation fragment but no active segment")
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
                print("unknown fragment flag", flag)
                return None
        # after processing chunk, send ACK
        sock.sendall(ACK_BYTES)
    # unreachable



def add_variable(message: Message, var_type:int, value, length:int=0):
    """
    Robust helper that mirrors C add_variable_to_message.
    - For arrays: if length==0 we infer len(value).
    - Builds seg._raw in network byte order and sets seg.size_in_bytes.
    - Sets typed lists (ivalues/dvalues/svalue) for convenience.
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

# ---- small demo usage ----
# def demo_receive_once():
#     s = socket.create_connection((HOST, PORT))
#     print("Connected to server", HOST, PORT)
#     msg = receive_message(s)
#     if msg is None:
#         print("receive_message failed or connection closed")
#     else:
#         print("Received message:", msg)
#     return s

# def demo_send_sample(s):
#     # connect, construct a sample message and send it
#     # s = socket.create_connection((HOST, PORT))
#     print("Connected to server (for send)", HOST, PORT)
#     # sample message: int array [10,20,30], string "hello", double 3.14
#     m = Message()
#     seg_intarr = Segment(SEG_INT_ARRAY, 3)
#     seg_intarr.ivalues = [10,20,30]
#     # build raw for seg_intarr
#     seg_intarr._raw = bytearray()
#     for v in seg_intarr.ivalues:
#         seg_intarr._raw.extend(struct.pack('!I', v & 0xffffffff))
#     seg_intarr.size_in_bytes = len(seg_intarr._raw)
#     m.add_segment(seg_intarr)

#     seg_str = Segment(SEG_STRING, len("hello"))
#     seg_str.svalue = "hello"
#     seg_str._raw = bytearray(seg_str.svalue.encode() + b'\x00')
#     seg_str.size_in_bytes = len(seg_str._raw)
#     m.add_segment(seg_str)

#     seg_d = Segment(SEG_DOUBLE, 1)
#     seg_d.dvalues = [3.14159]
#     seg_d._raw = bytearray(struct.pack('!d', seg_d.dvalues[0]))
#     seg_d.size_in_bytes = len(seg_d._raw)
#     m.add_segment(seg_d)

#     ok = send_message(s, m)
#     print("send_message ok?", ok)

def demo_send_receive(s):
    
    msg = Message()
    add_variable(msg, SEG_INT_ARRAY, [100,200,300], 3)
    add_variable(msg, SEG_STRING, "hello-from-python")
    add_variable(msg, SEG_DOUBLE, 2.7182818)
    add_variable(msg, SEG_INT, 42)
    add_variable(msg, SEG_BOOL, 1)
    add_variable(msg, SEG_CHAR, 'A')
    add_variable(msg, SEG_DOUBLE_ARRAY, [2.14,4.456,1.865])
    # print("Sending message:", msg)
    # for seg in msg.segments:
    #     debug_print_segment(seg)

    # send message first
    

    # then receive reply
    reply = receive_message(s)
    print("Received reply:", reply)
    ok = send_message(s, msg)
    print("send_message ok?", ok)
    # s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    # s.close()


s = socket.create_connection((HOST, PORT))
# demo_send_receive(s)
msg = Message()
c=[]
# for _ in range(100):
reply = receive_message(s)
print("Received reply:", reply)
for u in range(100):
    c.append(u*10)
add_variable(msg, SEG_INT_ARRAY, c, 100)
ok = send_message(s, msg)
print("send_message ok?", ok)
    


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