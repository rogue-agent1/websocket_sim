#!/usr/bin/env python3
"""WebSocket protocol simulator — RFC 6455 frame encode/decode + connection lifecycle.

Implements: handshake, frame encoding (text/binary/ping/pong/close),
masking, fragmentation, and a simulated client-server message exchange.

Usage: python websocket_sim.py [--test]
"""

import sys, struct, hashlib, base64, os

# Opcodes
OPCODE_CONTINUATION = 0x0
OPCODE_TEXT = 0x1
OPCODE_BINARY = 0x2
OPCODE_CLOSE = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA

WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def compute_accept_key(key):
    """Compute Sec-WebSocket-Accept from client key."""
    combined = key + WS_MAGIC
    sha1 = hashlib.sha1(combined.encode()).digest()
    return base64.b64encode(sha1).decode()

def generate_key():
    """Generate random Sec-WebSocket-Key."""
    return base64.b64encode(os.urandom(16)).decode()

def encode_frame(payload, opcode=OPCODE_TEXT, fin=True, mask=False):
    """Encode a WebSocket frame."""
    if isinstance(payload, str):
        payload = payload.encode('utf-8')
    
    frame = bytearray()
    # First byte: FIN + opcode
    byte1 = (0x80 if fin else 0x00) | (opcode & 0x0F)
    frame.append(byte1)
    
    # Second byte: MASK + payload length
    length = len(payload)
    mask_bit = 0x80 if mask else 0x00
    
    if length < 126:
        frame.append(mask_bit | length)
    elif length < 65536:
        frame.append(mask_bit | 126)
        frame.extend(struct.pack('>H', length))
    else:
        frame.append(mask_bit | 127)
        frame.extend(struct.pack('>Q', length))
    
    # Masking key + masked payload
    if mask:
        mask_key = os.urandom(4)
        frame.extend(mask_key)
        masked = bytearray(len(payload))
        for i in range(len(payload)):
            masked[i] = payload[i] ^ mask_key[i % 4]
        frame.extend(masked)
    else:
        frame.extend(payload)
    
    return bytes(frame)

def decode_frame(data):
    """Decode a WebSocket frame. Returns (opcode, payload, fin, bytes_consumed)."""
    if len(data) < 2:
        return None
    
    pos = 0
    byte1 = data[pos]; pos += 1
    byte2 = data[pos]; pos += 1
    
    fin = bool(byte1 & 0x80)
    opcode = byte1 & 0x0F
    masked = bool(byte2 & 0x80)
    length = byte2 & 0x7F
    
    if length == 126:
        if len(data) < pos + 2: return None
        length = struct.unpack('>H', data[pos:pos+2])[0]
        pos += 2
    elif length == 127:
        if len(data) < pos + 8: return None
        length = struct.unpack('>Q', data[pos:pos+8])[0]
        pos += 8
    
    mask_key = None
    if masked:
        if len(data) < pos + 4: return None
        mask_key = data[pos:pos+4]
        pos += 4
    
    if len(data) < pos + length:
        return None
    
    payload = bytearray(data[pos:pos+length])
    if mask_key:
        for i in range(length):
            payload[i] ^= mask_key[i % 4]
    
    return opcode, bytes(payload), fin, pos + length

def fragment_message(payload, opcode=OPCODE_TEXT, fragment_size=128, mask=False):
    """Fragment a message into multiple frames."""
    if isinstance(payload, str):
        payload = payload.encode('utf-8')
    
    frames = []
    offset = 0
    first = True
    while offset < len(payload):
        chunk = payload[offset:offset + fragment_size]
        is_last = (offset + fragment_size >= len(payload))
        op = opcode if first else OPCODE_CONTINUATION
        frames.append(encode_frame(chunk, opcode=op, fin=is_last, mask=mask))
        first = False
        offset += fragment_size
    
    if not frames:
        frames.append(encode_frame(b'', opcode=opcode, fin=True, mask=mask))
    
    return frames

def build_handshake_request(host, path="/", key=None):
    """Build HTTP upgrade request."""
    if key is None:
        key = generate_key()
    return (f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"), key

def build_handshake_response(key):
    """Build HTTP 101 switching protocols response."""
    accept = compute_accept_key(key)
    return (f"HTTP/1.1 101 Switching Protocols\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            f"\r\n")

def close_frame(code=1000, reason=""):
    """Build a close frame with status code and reason."""
    payload = struct.pack('>H', code) + reason.encode('utf-8')
    return encode_frame(payload, opcode=OPCODE_CLOSE)

def parse_close_frame(payload):
    """Parse close frame payload."""
    if len(payload) >= 2:
        code = struct.unpack('>H', payload[:2])[0]
        reason = payload[2:].decode('utf-8', errors='replace')
        return code, reason
    return None, ""

# --- Simulated connection ---

class WSConnection:
    """Simulated WebSocket connection."""
    def __init__(self, is_client=True):
        self.is_client = is_client
        self.state = "connecting"
        self.received = []
        self.fragments = bytearray()
        self.fragment_opcode = None
    
    def send(self, message, binary=False):
        opcode = OPCODE_BINARY if binary else OPCODE_TEXT
        return encode_frame(message, opcode=opcode, mask=self.is_client)
    
    def receive(self, frame_data):
        result = decode_frame(frame_data)
        if result is None:
            return None
        opcode, payload, fin, consumed = result
        
        if opcode == OPCODE_PING:
            return ("pong", encode_frame(payload, opcode=OPCODE_PONG))
        if opcode == OPCODE_CLOSE:
            code, reason = parse_close_frame(payload)
            self.state = "closed"
            return ("close", code, reason)
        if opcode == OPCODE_CONTINUATION:
            self.fragments.extend(payload)
            if fin:
                msg = bytes(self.fragments)
                self.fragments = bytearray()
                op = self.fragment_opcode
                self.fragment_opcode = None
                return ("message", msg, op)
            return ("fragment",)
        if opcode in (OPCODE_TEXT, OPCODE_BINARY):
            if fin:
                return ("message", payload, opcode)
            self.fragment_opcode = opcode
            self.fragments = bytearray(payload)
            return ("fragment",)
        return None

# --- Tests ---

def test_accept_key():
    # RFC 6455 example
    key = "dGhlIHNhbXBsZSBub25jZQ=="
    accept = compute_accept_key(key)
    assert accept == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

def test_frame_roundtrip():
    msg = "Hello, WebSocket!"
    frame = encode_frame(msg)
    opcode, payload, fin, consumed = decode_frame(frame)
    assert opcode == OPCODE_TEXT
    assert payload == msg.encode()
    assert fin == True

def test_masked_frame():
    msg = b"masked message"
    frame = encode_frame(msg, opcode=OPCODE_BINARY, mask=True)
    opcode, payload, fin, consumed = decode_frame(frame)
    assert payload == msg

def test_large_frame():
    msg = b"x" * 70000
    frame = encode_frame(msg, opcode=OPCODE_BINARY)
    opcode, payload, fin, consumed = decode_frame(frame)
    assert payload == msg
    assert consumed == len(frame)

def test_fragmentation():
    msg = "A" * 500
    frames = fragment_message(msg, fragment_size=128)
    assert len(frames) == 4  # 500/128 = 3.9 → 4
    
    # Reassemble
    conn = WSConnection(is_client=False)
    full_payload = None
    for f in frames:
        result = conn.receive(f)
        if result and result[0] == "message":
            full_payload = result[1]
    assert full_payload == msg.encode()

def test_close_frame():
    frame = close_frame(1000, "Normal closure")
    opcode, payload, fin, _ = decode_frame(frame)
    assert opcode == OPCODE_CLOSE
    code, reason = parse_close_frame(payload)
    assert code == 1000
    assert reason == "Normal closure"

def test_ping_pong():
    conn = WSConnection()
    ping = encode_frame(b"ping!", opcode=OPCODE_PING)
    result = conn.receive(ping)
    assert result[0] == "pong"
    pong_frame = result[1]
    opcode, payload, _, _ = decode_frame(pong_frame)
    assert opcode == OPCODE_PONG
    assert payload == b"ping!"

def test_handshake():
    req, key = build_handshake_request("example.com")
    assert "Upgrade: websocket" in req
    resp = build_handshake_response(key)
    assert "101 Switching Protocols" in resp
    assert compute_accept_key(key) in resp

if __name__ == "__main__":
    if "--test" in sys.argv or len(sys.argv) == 1:
        test_accept_key()
        test_frame_roundtrip()
        test_masked_frame()
        test_large_frame()
        test_fragmentation()
        test_close_frame()
        test_ping_pong()
        test_handshake()
        print("All tests passed!")
