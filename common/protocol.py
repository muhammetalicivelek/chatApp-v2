import json
import struct

MSG_REGISTER = "REGISTER"
MSG_LOGIN = "LOGIN"
MSG_SEND = "SEND"
MSG_INCOMING = "INCOMING"
MSG_LIST = "USER_LIST"
MSG_ERROR = "ERROR"
MSG_LOGOUT = "LOGOUT"

def create_msg(msg_type, **kwargs):
    payload = {"type": msg_type}
    payload.update(kwargs)
    return json.dumps(payload).encode('utf-8')

def parse_msg(byte_data):
    try:
        return json.loads(byte_data.decode('utf-8'))
    except:
        return {}

def send_packet(sock, byte_data):
    """Veri boyutunu başa ekleyerek gönderir (Network için kritik)"""
    length = len(byte_data)
    sock.sendall(struct.pack('>I', length) + byte_data)

def recv_packet(sock):
    """Veriyi boyutunu okuyarak eksiksiz alır"""
    header = _recv_all(sock, 4)
    if not header: return None
    msg_len = struct.unpack('>I', header)[0]
    return _recv_all(sock, msg_len)

def _recv_all(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet: return None
        data += packet
    return data