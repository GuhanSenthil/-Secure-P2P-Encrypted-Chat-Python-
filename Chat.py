import socket, threading, base64, os, struct
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PORT = 7777
BUFFER = 65536

name = input("Your name: ").strip()

# ================= GET LOCAL IP =================
def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

MY_IP = get_my_ip()
print("Your IP:", MY_IP)

# ================= RSA KEYS =================
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# ================= SESSION =================
session = {}   # ip -> AES object
peer_names = {}  # ip -> name
peers = set()
lock = threading.Lock()

# ================= SAFE SEND / RECEIVE =================
def send_packet(sock, data: bytes):
    sock.sendall(struct.pack("!I", len(data)) + data)

def recv_packet(sock):
    raw_len = sock.recv(4)
    if not raw_len:
        return None
    msg_len = struct.unpack("!I", raw_len)[0]
    data = b""
    while len(data) < msg_len:
        chunk = sock.recv(msg_len - len(data))
        if not chunk:
            return None
        data += chunk
    return data

# ================= ENCRYPTION =================
def encrypt_chat(aes, msg: str) -> bytes:
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, msg.encode(), None)
    return base64.b64encode(nonce + ct)

def decrypt_chat(aes, packet: bytes) -> str:
    data = base64.b64decode(packet)
    nonce, ct = data[:12], data[12:]
    return aes.decrypt(nonce, ct, None).decode()

# ================= HANDLE CLIENT =================
def handle_client(conn, addr):
    ip = addr[0]
    peers.add(ip)

    try:
        data = recv_packet(conn)
        if not data:
            return

        tag, payload = data.split(b"|", 1)

        # HELLO
        if tag == b"HELLO":
            username, peer_pub_bytes = payload.split(b"||", 1)
            peer_names[ip] = username.decode()

            peer_pub = serialization.load_pem_public_key(peer_pub_bytes)

            aes_key = AESGCM.generate_key(bit_length=128)
            with lock:
                session[ip] = AESGCM(aes_key)

            enc_key = peer_pub.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            send_packet(conn, b"KEY|" + enc_key)

        # KEY
        elif tag == b"KEY":
            aes_key = private_key.decrypt(
                payload,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            with lock:
                session[ip] = AESGCM(aes_key)

        # MSG
        elif tag == b"MSG":
            aes = session.get(ip)
            if aes:
                msg = decrypt_chat(aes, payload)
                print("\n" + msg)
                send_packet(conn, b"ACK")

    except Exception as e:
        print(f"[Error from {ip}]:", e)

    finally:
        conn.close()

# ================= LISTENER =================
def listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT))
    s.listen(10)

    print(f"📡 Listening on port {PORT}...\n")

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

# ================= HANDSHAKE =================
def connect_and_handshake(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, PORT))

        payload = name.encode() + b"||" + public_bytes
        send_packet(s, b"HELLO|" + payload)

        data = recv_packet(s)
        if data and data.startswith(b"KEY|"):
            enc = data.split(b"|",1)[1]

            aes_key = private_key.decrypt(
                enc,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            with lock:
                session[ip] = AESGCM(aes_key)

        s.close()
        print(f"🔗 Connected to {ip}")

    except Exception as e:
        print(f"❌ Failed to connect to {ip}")

# ================= SEND LOOP =================
def send_loop():
    while True:
        text = input()
        if not text:
            continue

        ts = datetime.now().strftime("%H:%M:%S")
        msg = f"[{ts}] {name}: {text}"
        print(msg)

        for ip in list(peers):
            aes = session.get(ip)
            if not aes:
                connect_and_handshake(ip)
                continue

            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((ip, PORT))

                packet = encrypt_chat(aes, msg)
                send_packet(s, b"MSG|" + packet)

                recv_packet(s)
                s.close()

            except Exception:
                print(f"⚠ Reconnecting {ip}...")
                connect_and_handshake(ip)

# ================= START =================
threading.Thread(target=listener, daemon=True).start()

print("\nEnter peer IPs (same WiFi)")
print("Press ENTER when done\n")

while True:
    ip = input("Peer IP: ").strip()
    if not ip:
        break
    peers.add(ip)
    connect_and_handshake(ip)

print("\n🔐 Secure chat started\n")
send_loop()