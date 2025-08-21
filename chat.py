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

class AnimatedFrame(ttk.Frame):
    def __init__(self, master=None, **kw):
        super().__init__(master, **kw)
        self.animating = False
        self.alpha = 0.0
        self.fade_duration = 150  # ms
        
    def fade_in(self):
        if self.alpha >= 1.0:
            return
        self.alpha = min(1.0, self.alpha + 0.1)
        self.attributes('-alpha', self.alpha)
        if self.alpha < 1.0:
            self.after(int(self.fade_duration/10), self.fade_in)

class ChatGUI:
    def __init__(self, root: "tk.Tk", my_name: str, peer_name: str, my_fp: str, peer_fp: str, chan: SecureChannel):
        self.root = root
        self.chan = chan
        self.my_name = my_name
        self.peer_name = peer_name
        self.typing = False
        self.connected = True
        
        # Configure main window
        root.title(f"Secure P2P Chat – {my_name} ↔ {peer_name}")
        root.protocol("WM_DELETE_WINDOW", self.on_quit)
        
        # Set dark theme colors
        self.bg_color = "#1e1e2e"
        self.bg_secondary = "#2a2a3a"
        self.text_color = "#e0e0e0"
        self.accent_color = "#7289da"
        self.peer_msg_color = "#3b3b4d"
        self.my_msg_color = "#4a5fc1"
        self.timestamp_color = "#888888"
        
        # Configure styles
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', background=self.bg_color, foreground=self.text_color)
        style.configure('TFrame', background=self.bg_color)
        style.configure('TLabel', background=self.bg_color, foreground=self.text_color)
        style.configure('TButton', background=self.bg_secondary, foreground=self.text_color)
        style.configure('TEntry', fieldbackground=self.bg_secondary, foreground=self.text_color, insertcolor=self.text_color)
        style.map('TButton', background=[('active', '#3a3a4a')])
        
        # Menu
        menubar = tk.Menu(root, bg=self.bg_secondary, fg=self.text_color, bd=0)
        filemenu = tk.Menu(menubar, tearoff=0, bg=self.bg_secondary, fg=self.text_color)
        filemenu.add_command(label="Copy My Fingerprint", command=lambda: self.copy_to_clipboard(my_fp))
        filemenu.add_command(label="Copy Peer Fingerprint", command=lambda: self.copy_to_clipboard(peer_fp))
        filemenu.add_separator()
        filemenu.add_command(label="Quit", command=self.on_quit)
        menubar.add_cascade(label="File", menu=filemenu)
        root.config(menu=menubar, bg=self.bg_color)
        
        # Main container
        main_frame = ttk.Frame(root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Chat area with scrollbar
        chat_frame = ttk.Frame(main_frame)
        chat_frame.pack(fill=tk.BOTH, expand=True)
        
        self.chat_canvas = tk.Canvas(chat_frame, bg=self.bg_color, highlightthickness=0)
        scrollbar = ttk.Scrollbar(chat_frame, orient="vertical", command=self.chat_canvas.yview)
        self.scrollable_frame = ttk.Frame(self.chat_canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all"))
        )
        
        self.chat_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.chat_canvas.configure(yscrollcommand=scrollbar.set)
        
        self.chat_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Input area
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Typing indicator
        self.typing_label = ttk.Label(input_frame, text="", foreground=self.text_color, background=self.bg_color)
        self.typing_label.pack(anchor="w", pady=(0, 5))
        
        # Message entry and send button
        entry_frame = ttk.Frame(input_frame)
        entry_frame.pack(fill=tk.X)
        
        self.entry = ttk.Entry(entry_frame, style='TEntry')
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.entry.bind("<Return>", self.send_message)
        
        self.send_btn = ttk.Button(entry_frame, text="Send", command=self.send_message)
        self.send_btn.pack(side=tk.RIGHT)
        
        # Status bar
        status_frame = ttk.Frame(main_frame, style='TFrame')
        status_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.status_light = tk.Canvas(status_frame, width=12, height=12, bg="#4CAF50", highlightthickness=0, bd=0)
        self.status_light.pack(side=tk.LEFT, padx=(0, 5))
        
        self.status_text = ttk.Label(status_frame, text="Connected", foreground=self.text_color)
        self.status_text.pack(side=tk.LEFT)
        
        # Fingerprint info
        fp_frame = ttk.Frame(status_frame)
        fp_frame.pack(side=tk.RIGHT)
        
        ttk.Label(fp_frame, text=f"Your FP: {my_fp[:8]}...").pack(side=tk.LEFT)
        ttk.Label(fp_frame, text=" | ").pack(side=tk.LEFT, padx=5)
        ttk.Label(fp_frame, text=f"Peer FP: {peer_fp[:8]}...").pack(side=tk.LEFT)
        
        # Tooltips for full fingerprints
        ToolTip(fp_frame, f"Your full fingerprint: {my_fp}\nPeer's fingerprint: {peer_fp}")
        
        # Configure grid weights
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=1)
        
        # Start with fade-in animation
        self.root.attributes('-alpha', 0.0)
        self.fade_in()
        
        # Start background receiver thread
        self.receive_thread = threading.Thread(target=self.recv_loop_gui, daemon=True)
        self.receive_thread.start()
        
        # Focus the entry widget
        self.entry.focus_set()
    
    def fade_in(self):
        alpha = self.root.attributes('-alpha')
        if alpha < 1.0:
            alpha += 0.05
            self.root.attributes('-alpha', alpha)
            self.root.after(10, self.fade_in)
    
    def add_message(self, sender, message, is_me=False):
        # Create message frame
        msg_frame = ttk.Frame(self.scrollable_frame, style='TFrame')
        
        # Configure alignment based on sender
        if is_me:
            msg_frame.pack(anchor='e', padx=20, pady=2, fill=tk.X)
            bubble_color = self.my_msg_color
            anchor = 'e'
        else:
            msg_frame.pack(anchor='w', padx=20, pady=2, fill=tk.X)
            bubble_color = self.peer_msg_color
            anchor = 'w'
        
        # Create bubble frame with rounded corners
        bubble = tk.Canvas(msg_frame, bg=bubble_color, highlightthickness=0, bd=0, 
                          height=30, width=200)  # Initial size, will expand
        
        # Add bubble to frame
        bubble.pack(anchor=anchor, pady=2)
        
        # Add sender name
        name_label = ttk.Label(bubble, text=sender, background=bubble_color, 
                              foreground=self.text_color, font=('Helvetica', 8, 'bold'))
        name_label.pack(anchor='nw', padx=8, pady=(5, 0))
        
        # Add message text
        msg_label = ttk.Label(bubble, text=message, background=bubble_color, 
                             foreground=self.text_color, wraplength=300, justify='left')
        msg_label.pack(anchor='nw', padx=8, pady=(0, 5), fill=tk.X)
        
        # Add timestamp
        timestamp = datetime.datetime.now().strftime("%H:%M")
        time_label = ttk.Label(bubble, text=timestamp, background=bubble_color, 
                              foreground=self.timestamp_color, font=('Helvetica', 7))
        time_label.pack(anchor='se', padx=8, pady=(0, 3))
        
        # Calculate bubble size based on content
        bubble.update_idletasks()
        bubble.configure(
            height=msg_label.winfo_reqheight() + name_label.winfo_reqheight() + 20,
            width=min(400, msg_label.winfo_reqwidth() + 50)
        )
        
        # Animate message appearance
        self.animate_message(bubble)
        
        # Scroll to bottom
        self.chat_canvas.yview_moveto(1.0)
    
    def animate_message(self, widget):
        # Fade-in and slide-up animation
        alpha = 0.0
        y_offset = 10
        
        def update():
            nonlocal alpha, y_offset
            if alpha < 1.0 or y_offset > 0:
                alpha = min(1.0, alpha + 0.1)
                y_offset = max(0, y_offset - 1)
                widget.place(y=y_offset, relx=1.0 if 'anchor' in widget.pack_info() and widget.pack_info()['anchor'] == 'e' else 0.0, anchor='ne' if 'anchor' in widget.pack_info() and widget.pack_info()['anchor'] == 'e' else 'nw')
                widget.configure(alpha=alpha)
                widget.after(10, update)
        
        update()
    
    def show_typing_indicator(self, is_typing=True):
        if is_typing and not self.typing:
            self.typing = True
            self.animate_typing_dots()
        elif not is_typing and self.typing:
            self.typing = False
            self.typing_label.config(text="")
    
    def animate_typing_dots(self):
        if not self.typing:
            return
            
        dots = self.typing_label.cget("text").count(".")
        dots = (dots + 1) % 4
        self.typing_label.config(text=f"{self.peer_name} is typing{"." * dots}")
        
        if self.typing:
            self.root.after(500, self.animate_typing_dots)
    
    def update_connection_status(self, connected):
        self.connected = connected
        if connected:
            self.status_light.config(bg="#4CAF50")
            self.status_text.config(text="Connected")
        else:
            self.status_light.config(bg="#f44336")
            self.status_text.config(text="Disconnected")
        
        # Animate status change
        self.animate_status_change()
    
    def animate_status_change(self):
        # Simple pulse animation for status light
        current_color = self.status_light.cget("bg")
        target_color = "#4CAF50" if self.connected else "#f44336"
        
        if current_color != target_color:
            r1, g1, b1 = [int(current_color[i+1:i+3], 16) for i in (0, 2, 4)]
            r2, g2, b2 = [int(target_color[i+1:i+3], 16) for i in (0, 2, 4)]
            
            r = min(255, r1 + (r2 - r1) // 4)
            g = min(255, g1 + (g2 - g1) // 4)
            b = min(255, b1 + (b2 - b1) // 4)
            
            new_color = f"#{r:02x}{g:02x}{b:02x}"
            self.status_light.config(bg=new_color)
            
            if new_color != target_color:
                self.root.after(20, self.animate_status_change)
    
    def send_message(self, event=None):
        msg = self.entry.get().strip()
        if not msg:
            return
            
        # Clear input and disable send button during sending
        self.entry.delete(0, tk.END)
        self.send_btn.config(state=tk.DISABLED)
        
        try:
            # Show message immediately in UI
            self.add_message("You", msg, is_me=True)
            
            # Send message in a separate thread to avoid UI freeze
            def send_thread():
                try:
                    self.chan.send_text(msg)
                    self.root.after(0, lambda: self.send_btn.config(state=tk.NORMAL))
                except Exception as e:
                    self.root.after(0, lambda: messagebox.showerror("Send Error", f"Failed to send message: {str(e)}"))
                    self.root.after(0, lambda: self.send_btn.config(state=tk.NORMAL))
            
            threading.Thread(target=send_thread, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {str(e)}")
            self.send_btn.config(state=tk.NORMAL)
    
    def recv_loop_gui(self):
        try:
            while True:
                msg = self.chan.recv_text()
                # Show typing indicator
                self.root.after(0, lambda: self.show_typing_indicator(True))
                # Small delay to simulate typing
                time.sleep(0.5)
                # Update UI in main thread
                self.root.after(0, lambda m=msg: [
                    self.add_message(self.peer_name, m, is_me=False),
                    self.show_typing_indicator(False)
                ])
        except Exception as e:
            if self.connected:  # Only show disconnect message once
                self.root.after(0, lambda: [
                    self.update_connection_status(False),
                    self.add_message("System", "Connection to peer was lost.", is_me=False)
                ])
    
    def copy_to_clipboard(self, text: str):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
        
        # Show a small notification
        notification = tk.Toplevel(self.root)
        notification.overrideredirect(True)
        notification.attributes('-alpha', 0.0)
        notification.geometry(f"200x40+{self.root.winfo_x() + self.root.winfo_width() - 220}+{self.root.winfo_y() + 50}")
        
        label = ttk.Label(notification, text="Copied to clipboard!", background="#4CAF50", 
                         foreground="white", padding=10)
        label.pack(fill=tk.BOTH, expand=True)
        
        # Animate fade in and out
        def fade_in(alpha=0.0):
            if alpha < 1.0:
                alpha += 0.1
                notification.attributes('-alpha', alpha)
                notification.after(20, lambda: fade_in(alpha))
            else:
                notification.after(1500, fade_out)
        
        def fade_out(alpha=1.0):
            if alpha > 0.0:
                alpha -= 0.05
                notification.attributes('-alpha', alpha)
                notification.after(20, lambda: fade_out(alpha))
            else:
                notification.destroy()
        
        fade_in()
    
    def on_quit(self):
        if self.connected:
            try:
                self.chan.close()
            except:
                pass
        self.root.destroy()


class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)
    
    def enter(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        
        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")
        
        label = ttk.Label(self.tooltip, text=self.text, background="#ffffe0", 
                         relief="solid", borderwidth=1, padding=5, wraplength=300)
        label.pack()
    
    def leave(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None


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
