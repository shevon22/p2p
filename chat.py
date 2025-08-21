"""
P2P Encrypted Chat (AES‑GCM + RSA‑OAEP) — CLI + Tkinter GUI
-----------------------------------------------------------
Simple two‑peer encrypted chat over TCP, written in pure Python.
Now includes a clean Tkinter GUI in addition to the original CLI mode.

Features
• End‑to‑end encryption (session key protected with RSA‑OAEP + SHA‑256)
• Authenticated encryption of messages using AES‑GCM (fresh nonce per message)
• Public‑key fingerprint display so peers can verify keys out‑of‑band
• Clean length‑prefixed framing over TCP (no partial read issues)
• Works on LAN or localhost; one peer hosts, the other joins
• GUI: scrollable chat, status bar with fingerprints, graceful shutdown

Security note (important!)
• This is a learning/demo tool. It does not authenticate peers automatically.
  You must verify the displayed public‑key fingerprint with your partner
  (via phone/WhatsApp, etc.). If fingerprints don’t match, DO NOT chat.

Usage
------
1) Install dependency:
   pip install cryptography

2) Host side (listens for a connection):
   CLI  : python p2p_encrypted_chat.py host 0.0.0.0 9999 "YourName" [PeerName]
   GUI  : python p2p_encrypted_chat.py host 0.0.0.0 9999 "YourName" [PeerName] --gui

3) Join side (connects to host):
   CLI  : python p2p_encrypted_chat.py join <HOST_IP> 9999 "YourName" [PeerName]
   GUI  : python p2p_encrypted_chat.py join <HOST_IP> 9999 "YourName" [PeerName] --gui

4) In GUI, type at the bottom and press Enter or click Send. Use File → Quit to exit.

Test locally with two terminals:
   A (host): python p2p_encrypted_chat.py host 127.0.0.1 7777 Alice Bob --gui
   B (join): python p2p_encrypted_chat.py join 127.0.0.1 7777 Bob Alice --gui

Author: ChatGPT (Shevon's project helper)
"""

import os
import socket
import struct
import sys
import threading
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------- Utility: TCP framing ----------------------------

def send_lp(sock: socket.socket, data: bytes) -> None:
    header = struct.pack("!I", len(data))
    sock.sendall(header + data)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf.extend(chunk)
    return bytes(buf)


def recv_lp(sock: socket.socket) -> bytes:
    (length,) = struct.unpack("!I", recv_exact(sock, 4))
    return recv_exact(sock, length)

# --------------------------- Crypto: RSA + AES‑GCM ---------------------------

def gen_rsa_keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def pubkey_bytes(priv: rsa.RSAPrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_pubkey(pem: bytes):
    return serialization.load_pem_public_key(pem)


def rsa_oaep_encrypt(pubkey, data: bytes) -> bytes:
    return pubkey.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_oaep_decrypt(priv: rsa.RSAPrivateKey, ct: bytes) -> bytes:
    return priv.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def sha256_fingerprint(data: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    h = digest.finalize().hex()
    return ":".join(h[i:i+2] for i in range(0, len(h), 2))

# --------------------------- Encrypted channel -------------------------------

class SecureChannel:
    def __init__(self, sock: socket.socket, aes_key: bytes):
        if len(aes_key) != 32:
            raise ValueError("AES key must be 32 bytes (AES‑256)")
        self.sock = sock
        self.aes_key = aes_key
        self.lock = threading.Lock()
        self.closed = False

    def close(self):
        if self.closed:
            return
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        self.closed = True

    def send_text(self, text: str) -> None:
        if self.closed:
            return
        data = text.encode("utf-8")
        aes = AESGCM(self.aes_key)
        nonce = os.urandom(12)  # 96‑bit nonce as recommended for GCM
        ct = aes.encrypt(nonce, data, None)
        packet = nonce + ct  # [12‑byte nonce][ciphertext+tag]
        with self.lock:
            send_lp(self.sock, packet)

    def recv_text(self) -> str:
        packet = recv_lp(self.sock)
        if len(packet) < 12:
            raise ValueError("Invalid packet")
        nonce, ct = packet[:12], packet[12:]
        aes = AESGCM(self.aes_key)
        pt = aes.decrypt(nonce, ct, None)
        return pt.decode("utf-8", errors="replace")

# ------------------------------ Handshake ------------------------------------

def handshake_host(conn: socket.socket) -> Tuple[SecureChannel, str, str]:
    my_priv = gen_rsa_keypair()
    my_pub_pem = pubkey_bytes(my_priv)
    send_lp(conn, my_pub_pem)
    peer_pub_pem = recv_lp(conn)
    peer_pub = load_pubkey(peer_pub_pem)
    session_key = os.urandom(32)  # AES‑256
    encrypted_key = rsa_oaep_encrypt(peer_pub, session_key)
    send_lp(conn, encrypted_key)
    my_fp = sha256_fingerprint(my_pub_pem)
    peer_fp = sha256_fingerprint(peer_pub_pem)
    return SecureChannel(conn, session_key), my_fp, peer_fp


def handshake_join(sock: socket.socket) -> Tuple[SecureChannel, str, str]:
    my_priv = gen_rsa_keypair()
    my_pub_pem = pubkey_bytes(my_priv)
    host_pub_pem = recv_lp(sock)
    send_lp(sock, my_pub_pem)
    encrypted_key = recv_lp(sock)
    session_key = rsa_oaep_decrypt(my_priv, encrypted_key)
    my_fp = sha256_fingerprint(my_pub_pem)
    peer_fp = sha256_fingerprint(host_pub_pem)
    return SecureChannel(sock, session_key), my_fp, peer_fp

# ----------------------------- CLI routines ----------------------------------

def recv_loop_cli(name_peer: str, chan: SecureChannel):
    try:
        while True:
            msg = chan.recv_text()
            print(f"[{name_peer}] {msg}", end="", flush=True)
    except (ConnectionError, OSError):
        print("[!] Connection closed by peer.")
        os._exit(0)
    except Exception as e:
        print(f"[!] Receive error: {e}")
        os._exit(1)


def run_host_cli(bind_ip: str, port: int, my_name: str, peer_name: str = "Peer"):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_ip, port))
    srv.listen(1)
    print(f"[+] Hosting on {bind_ip}:{port} – waiting for a connection…")
    conn, addr = srv.accept()
    print(f"[+] Peer connected from {addr[0]}:{addr[1]}")
    chan, my_fp, peer_fp = handshake_host(conn)
    print("[Key fingerprints] Share & verify over a trusted channel:")
    print(f"  Your key   ({my_name}):  {my_fp}")
    print(f"  Peer key ({peer_name}):  {peer_fp}")
    print("  If these don't match what your peer reads for you, disconnect!")
    threading.Thread(target=recv_loop_cli, args=(peer_name, chan), daemon=True).start()
    try:
        while True:
            text = input("> ").strip()
            if not text:
                continue
            if text.lower() == "/quit":
                break
            chan.send_text(text)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        chan.close()
        try:
            srv.close()
        except Exception:
            pass
        print("[+] Bye.")


def run_join_cli(host_ip: str, port: int, my_name: str, peer_name: str = "Peer"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[+] Connecting to {host_ip}:{port}…")
    sock.connect((host_ip, port))
    chan, my_fp, peer_fp = handshake_join(sock)
    print("[Key fingerprints] Share & verify over a trusted channel:")
    print(f"  Your key   ({my_name}):  {my_fp}")
    print(f"  Peer key ({peer_name}):  {peer_fp}")
    print("  If these don't match what your peer reads for you, disconnect!")
    threading.Thread(target=recv_loop_cli, args=(peer_name, chan), daemon=True).start()
    try:
        while True:
            text = input("> ").strip()
            if not text:
                continue
            if text.lower() == "/quit":
                break
            chan.send_text(text)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        chan.close()
        print("[+] Bye.")

# ----------------------------- Tkinter GUI -----------------------------------

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
    from tkinter.scrolledtext import ScrolledText
    TK_AVAILABLE = True
except Exception:
    TK_AVAILABLE = False

class ChatGUI:
    def __init__(self, root: "tk.Tk", my_name: str, peer_name: str, my_fp: str, peer_fp: str, chan: SecureChannel):
        self.root = root
        self.chan = chan
        self.my_name = my_name
        self.peer_name = peer_name

        root.title(f"Secure P2P Chat – {my_name} ↔ {peer_name}")
        root.protocol("WM_DELETE_WINDOW", self.on_quit)

        # Menu
        menubar = tk.Menu(root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Copy My Fingerprint", command=lambda: self.copy_to_clipboard(my_fp))
        filemenu.add_command(label="Copy Peer Fingerprint", command=lambda: self.copy_to_clipboard(peer_fp))
        filemenu.add_separator()
        filemenu.add_command(label="Quit", command=self.on_quit)
        menubar.add_cascade(label="File", menu=filemenu)
        root.config(menu=menubar)

        # Layout
        self.chat_area = ScrolledText(root, wrap=tk.WORD, state=tk.DISABLED, height=20)
        self.chat_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 6))

        bottom = ttk.Frame(root)
        bottom.pack(fill=tk.X, padx=10, pady=(0, 10))
        self.entry = ttk.Entry(bottom)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.entry.bind("<Return>", self.send_message)
        send_btn = ttk.Button(bottom, text="Send", command=self.send_message)
        send_btn.pack(side=tk.LEFT, padx=(8, 0))

        self.status = ttk.Label(root, text=f"Your FP: {my_fp}    |    Peer FP: {peer_fp}", anchor="w")
        self.status.pack(fill=tk.X, padx=10, pady=(0, 10))

        # Start background receiver thread
        threading.Thread(target=self.recv_loop_gui, daemon=True).start()

    def append(self, text: str):
        self.chat_area.configure(state=tk.NORMAL)
        self.chat_area.insert(tk.END, text + "")
        self.chat_area.configure(state=tk.DISABLED)
        self.chat_area.see(tk.END)

    def send_message(self, event=None):
        msg = self.entry.get().strip()
        if not msg:
            return
        self.entry.delete(0, tk.END)
        try:
            self.chan.send_text(msg)
            self.append(f"[{self.my_name}] {msg}")
        except Exception as e:
            messagebox.showerror("Send error", str(e))

    def recv_loop_gui(self):
        try:
            while True:
                msg = self.chan.recv_text()
                # Ensure UI updates happen in main thread
                self.root.after(0, lambda m=msg: self.append(f"[{self.peer_name}] {m}"))
        except Exception:
            self.root.after(0, lambda: self.append("[!] Connection closed."))

    def copy_to_clipboard(self, text: str):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()

    def on_quit(self):
        try:
            self.chan.close()
        except Exception:
            pass
        self.root.destroy()


def run_host_gui(bind_ip: str, port: int, my_name: str, peer_name: str = "Peer"):
    if not TK_AVAILABLE:
        print("[!] Tkinter not available. Run without --gui or install a Python build with Tk.")
        sys.exit(1)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_ip, port))
    srv.listen(1)
    print(f"[+] Hosting on {bind_ip}:{port} – waiting for a connection…")
    conn, addr = srv.accept()
    print(f"[+] Peer connected from {addr[0]}:{addr[1]}")
    chan, my_fp, peer_fp = handshake_host(conn)

    root = tk.Tk()
    app = ChatGUI(root, my_name, peer_name, my_fp, peer_fp, chan)
    app.append("[i] Secure channel established. Verify fingerprints via a trusted channel.")
    root.mainloop()
    try:
        srv.close()
    except Exception:
        pass


def run_join_gui(host_ip: str, port: int, my_name: str, peer_name: str = "Peer"):
    if not TK_AVAILABLE:
        print("[!] Tkinter not available. Run without --gui or install a Python build with Tk.")
        sys.exit(1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[+] Connecting to {host_ip}:{port}…")
    sock.connect((host_ip, port))
    chan, my_fp, peer_fp = handshake_join(sock)

    root = tk.Tk()
    app = ChatGUI(root, my_name, peer_name, my_fp, peer_fp, chan)
    app.append("[i] Secure channel established. Verify fingerprints via a trusted channel.")
    root.mainloop()

# --------------------------------- Main --------------------------------------

def print_usage():
    print(
        """
Usage:
  Host (CLI): python p2p_encrypted_chat.py host <bind_ip> <port> <YourName> [PeerName]
  Join (CLI): python p2p_encrypted_chat.py join <host_ip> <port> <YourName> [PeerName]

  Host (GUI): python p2p_encrypted_chat.py host <bind_ip> <port> <YourName> [PeerName] --gui
  Join (GUI): python p2p_encrypted_chat.py join <host_ip> <port> <YourName> [PeerName] --gui

Commands (CLI):
  /quit   – exit chat
        """.strip()
    )


def main():
    if len(sys.argv) < 5:
        print_usage()
        sys.exit(1)

    mode = sys.argv[1].lower()
    ip = sys.argv[2]
    try:
        port = int(sys.argv[3])
    except ValueError:
        print("[!] Port must be an integer")
        sys.exit(1)

    my_name = sys.argv[4]
    peer_name = sys.argv[5] if len(sys.argv) >= 6 and not sys.argv[5].startswith("-") else "Peer"
    use_gui = "--gui" in sys.argv

    if mode == "host":
        if use_gui:
            run_host_gui(ip, port, my_name, peer_name)
        else:
            run_host_cli(ip, port, my_name, peer_name)
    elif mode == "join":
        if use_gui:
            run_join_gui(ip, port, my_name, peer_name)
        else:
            run_join_cli(ip, port, my_name, peer_name)
    else:
        print("[!] First arg must be 'host' or 'join'")
        print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
