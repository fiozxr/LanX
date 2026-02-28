#!/usr/bin/env python3
"""
LanX v1.1 - Serverless LAN Chat Application with Multi-Layered Encryption
A lightweight, P2P chat application compatible with Linux and Termux (Android).

Usage:
    lanx [-w|--web] [-u USERNAME] [-p PORT] [-c CONFIG]

Features:
    - Serverless P2P architecture (no central server)
    - UDP beacon discovery for peer finding
    - TCP transport for reliable message delivery
    - AES-GCM encryption with PBKDF2 key derivation
    - Encrypted file sharing
    - Message persistence
    - CLI/TUI and Web UI modes

Version: 1.1.0
"""

import argparse
import base64
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time
import queue
import logging
import pathlib
import pickle
from datetime import datetime
from typing import Dict, Optional, Tuple, List, Callable, Any
from dataclasses import dataclass, asdict

# Encryption imports
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# Web UI imports (only loaded when needed)
try:
    from flask import Flask, request, jsonify, render_template_string, send_from_directory
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

# =============================================================================
# CONFIGURATION & CONSTANTS
# =============================================================================

VERSION = "1.1.0"
DEFAULT_TCP_PORT = 5000
DEFAULT_UDP_PORT = 5001
DEFAULT_WEB_PORT = 8080
BROADCAST_INTERVAL = 3.0
PEER_TIMEOUT = 15.0
DISCOVERY_MAGIC = b"LANX_HELLO:"
FILE_MAGIC = b"LANX_FILE:"
BUFFER_SIZE = 8192
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB max file size
CHUNK_SIZE = 65536
CONFIG_DIR = pathlib.Path.home() / '.lanx'
HISTORY_FILE = CONFIG_DIR / 'history.pkl'
CONFIG_FILE = CONFIG_DIR / 'config.json'
LOG_FILE = CONFIG_DIR / 'lanx.log'
DOWNLOADS_DIR = CONFIG_DIR / 'downloads'

# ANSI Colors for CLI
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GRAY = "\033[90m"
    CLEAR_SCREEN = "\033[2J"
    CURSOR_HOME = "\033[H"
    CLEAR_LINE = "\033[2K"
    SAVE_CURSOR = "\033[s"
    RESTORE_CURSOR = "\033[u"

# Message types
MSG_TYPE_CHAT = 'chat'
MSG_TYPE_FILE = 'file'
MSG_TYPE_ACK = 'ack'
MSG_TYPE_TYPING = 'typing'

# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class FileTransfer:
    """Represents an incoming or outgoing file transfer."""
    file_id: str
    filename: str
    size: int
    sender: str
    timestamp: str
    chunks_received: int = 0
    total_chunks: int = 0
    data: bytes = None
    completed: bool = False
    save_path: Optional[pathlib.Path] = None

@dataclass
class Config:
    """Application configuration."""
    username: str = ''
    tcp_port: int = DEFAULT_TCP_PORT
    udp_port: int = DEFAULT_UDP_PORT
    web_port: int = DEFAULT_WEB_PORT
    download_dir: str = str(DOWNLOADS_DIR)
    save_history: bool = True
    max_history: int = 1000
    log_level: str = 'INFO'
    theme: str = 'dark'
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Config':
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

# =============================================================================
# LOGGING SETUP
# =============================================================================

def setup_logging(log_level: str = 'INFO') -> logging.Logger:
    """Setup application logging."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    
    logger = logging.getLogger('lanx')
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # File handler
    fh = logging.FileHandler(LOG_FILE)
    fh.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    
    return logger

# =============================================================================
# CONFIGURATION MANAGER
# =============================================================================

class ConfigManager:
    """Manages application configuration."""
    
    def __init__(self):
        self.config = Config()
        self.load()
    
    def load(self):
        """Load configuration from file."""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r') as f:
                    data = json.load(f)
                    self.config = Config.from_dict(data)
            except Exception as e:
                logging.getLogger('lanx').warning(f"Failed to load config: {e}")
    
    def save(self):
        """Save configuration to file."""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config.to_dict(), f, indent=2)
        except Exception as e:
            logging.getLogger('lanx').error(f"Failed to save config: {e}")
    
    def get(self, key: str, default=None):
        """Get configuration value."""
        return getattr(self.config, key, default)
    
    def set(self, key: str, value):
        """Set configuration value."""
        if hasattr(self.config, key):
            setattr(self.config, key, value)
            self.save()

# =============================================================================
# ENCRYPTION MODULE
# =============================================================================

class CryptoManager:
    """
    Manages AES-GCM encryption with PBKDF2 key derivation.
    All messages are encrypted locally before network transmission.
    """
    
    def __init__(self, password: str, salt: Optional[bytes] = None):
        self._stored_password = password
        self.salt = salt or os.urandom(16)
        self.key = self._derive_key(password, self.salt)
        self.aesgcm = AESGCM(self.key)
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive 256-bit AES key from password using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode('utf-8'))
    
    def encrypt(self, plaintext: str) -> bytes:
        """Encrypt plaintext with AES-GCM."""
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        return self.salt + nonce + ciphertext
    
    def encrypt_bytes(self, data: bytes) -> bytes:
        """Encrypt binary data with AES-GCM."""
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, data, None)
        return self.salt + nonce + ciphertext
    
    def decrypt(self, encrypted_data: bytes) -> Optional[str]:
        """Decrypt AES-GCM encrypted message."""
        try:
            if len(encrypted_data) < 28:
                return None
            
            salt = encrypted_data[:16]
            nonce = encrypted_data[16:28]
            ciphertext = encrypted_data[28:]
            
            key = self._derive_key(self._stored_password, salt)
            aesgcm = AESGCM(key)
            
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
        except (InvalidTag, UnicodeDecodeError, Exception):
            return None
    
    def decrypt_bytes(self, encrypted_data: bytes) -> Optional[bytes]:
        """Decrypt AES-GCM encrypted binary data."""
        try:
            if len(encrypted_data) < 28:
                return None
            
            salt = encrypted_data[:16]
            nonce = encrypted_data[16:28]
            ciphertext = encrypted_data[28:]
            
            key = self._derive_key(self._stored_password, salt)
            aesgcm = AESGCM(key)
            
            return aesgcm.decrypt(nonce, ciphertext, None)
        except (InvalidTag, Exception):
            return None

# =============================================================================
# PEER DISCOVERY MODULE (UDP)
# =============================================================================

class PeerDiscovery:
    """UDP-based peer discovery using broadcast beacons."""
    
    def __init__(self, username: str, tcp_port: int, udp_port: int = DEFAULT_UDP_PORT,
                 logger: Optional[logging.Logger] = None):
        self.username = username
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.peers: Dict[str, dict] = {}
        self.running = False
        self.socket: Optional[socket.socket] = None
        self.lock = threading.Lock()
        self.thread: Optional[threading.Thread] = None
        self.broadcast_thread: Optional[threading.Thread] = None
        self.logger = logger or logging.getLogger('lanx')
    
    def start(self) -> bool:
        """Start discovery service."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('', self.udp_port))
            self.socket.settimeout(1.0)
        except Exception as e:
            self.logger.error(f"Failed to bind UDP port {self.udp_port}: {e}")
            return False
        
        self.running = True
        
        self.thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.thread.start()
        
        self.broadcast_thread = threading.Thread(target=self._broadcast_loop, daemon=True)
        self.broadcast_thread.start()
        
        self.logger.info(f"Discovery service started on UDP port {self.udp_port}")
        return True
    
    def stop(self):
        """Stop discovery service."""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.logger.info("Discovery service stopped")
    
    def _listen_loop(self):
        """Background thread: Listen for peer beacons."""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(256)
                self._handle_beacon(data, addr[0])
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.logger.debug(f"UDP listen error: {e}")
                    time.sleep(0.1)
    
    def _handle_beacon(self, data: bytes, ip: str):
        """Process received beacon packet."""
        if not data.startswith(DISCOVERY_MAGIC):
            return
        
        try:
            parts = data[len(DISCOVERY_MAGIC):].decode('utf-8').split(':')
            if len(parts) >= 2:
                username = parts[0]
                port = int(parts[1])
                
                if username == self.username and port == self.tcp_port:
                    return
                
                with self.lock:
                    is_new = ip not in self.peers
                    self.peers[ip] = {
                        'username': username,
                        'port': port,
                        'last_seen': time.time()
                    }
                    if is_new:
                        self.logger.info(f"New peer discovered: {username}@{ip}:{port}")
        except Exception as e:
            self.logger.debug(f"Failed to parse beacon: {e}")
    
    def _broadcast_loop(self):
        """Background thread: Broadcast our presence."""
        while self.running:
            try:
                beacon = f"{DISCOVERY_MAGIC.decode()}{self.username}:{self.tcp_port}".encode()
                self.socket.sendto(beacon, ('<broadcast>', self.udp_port))
            except Exception as e:
                self.logger.debug(f"Broadcast error: {e}")
            time.sleep(BROADCAST_INTERVAL)
    
    def get_peers(self) -> Dict[str, dict]:
        """Get current peer list, removing stale entries."""
        with self.lock:
            now = time.time()
            stale = [ip for ip, info in self.peers.items() 
                     if now - info['last_seen'] > PEER_TIMEOUT]
            for ip in stale:
                del self.peers[ip]
            return dict(self.peers)
    
    def get_peer_count(self) -> int:
        """Get number of active peers."""
        return len(self.get_peers())

# =============================================================================
# FILE TRANSFER MANAGER
# =============================================================================

class FileTransferManager:
    """Manages encrypted file transfers."""
    
    def __init__(self, crypto: CryptoManager, download_dir: pathlib.Path,
                 logger: Optional[logging.Logger] = None):
        self.crypto = crypto
        self.download_dir = download_dir
        self.download_dir.mkdir(parents=True, exist_ok=True)
        self.transfers: Dict[str, FileTransfer] = {}
        self.lock = threading.Lock()
        self.logger = logger or logging.getLogger('lanx')
        self.progress_callbacks: List[Callable] = []
    
    def add_progress_callback(self, callback: Callable):
        """Add callback for transfer progress updates."""
        self.progress_callbacks.append(callback)
    
    def _notify_progress(self, transfer: FileTransfer):
        """Notify all progress callbacks."""
        for callback in self.progress_callbacks:
            try:
                callback(transfer)
            except:
                pass
    
    def send_file(self, filepath: pathlib.Path, ip: str, port: int, 
                  sender: str) -> Tuple[bool, str]:
        """
        Send a file to a peer.
        
        Returns:
            (success: bool, message: str)
        """
        try:
            if not filepath.exists():
                return False, f"File not found: {filepath}"
            
            file_size = filepath.stat().st_size
            if file_size > MAX_FILE_SIZE:
                return False, f"File too large (max {MAX_FILE_SIZE // 1024 // 1024}MB)"
            
            # Read and encrypt file
            with open(filepath, 'rb') as f:
                file_data = f.read()
            
            encrypted_data = self.crypto.encrypt_bytes(file_data)
            
            # Calculate chunks
            total_chunks = (len(encrypted_data) + CHUNK_SIZE - 1) // CHUNK_SIZE
            file_id = hashlib.sha256(f"{filepath.name}{time.time()}".encode()).hexdigest()[:16]
            
            # Build file metadata
            metadata = {
                'type': MSG_TYPE_FILE,
                'file_id': file_id,
                'filename': filepath.name,
                'size': file_size,
                'encrypted_size': len(encrypted_data),
                'total_chunks': total_chunks,
                'sender': sender,
                'timestamp': datetime.now().isoformat()
            }
            
            # Send metadata first
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30.0)
            sock.connect((ip, port))
            
            meta_json = json.dumps(metadata)
            meta_encrypted = self.crypto.encrypt(meta_json)
            
            # Send: [FILE_MAGIC][meta_length(4)][encrypted_metadata][chunks...]
            sock.sendall(FILE_MAGIC)
            sock.sendall(struct.pack('!I', len(meta_encrypted)))
            sock.sendall(meta_encrypted)
            
            # Send file chunks
            for i in range(total_chunks):
                start = i * CHUNK_SIZE
                end = min(start + CHUNK_SIZE, len(encrypted_data))
                chunk = encrypted_data[start:end]
                
                # Send chunk length and data
                sock.sendall(struct.pack('!I', len(chunk)))
                sock.sendall(chunk)
                
                self.logger.debug(f"Sent chunk {i+1}/{total_chunks} ({len(chunk)} bytes)")
            
            sock.close()
            self.logger.info(f"File sent: {filepath.name} ({file_size} bytes)")
            return True, f"File sent successfully: {filepath.name}"
            
        except Exception as e:
            self.logger.error(f"File send failed: {e}")
            return False, f"Failed to send file: {e}"
    
    def receive_file_metadata(self, sock: socket.socket, ip: str) -> Optional[FileTransfer]:
        """Receive file metadata and initialize transfer."""
        try:
            # Read metadata length
            length_data = sock.recv(4)
            if len(length_data) != 4:
                return None
            
            meta_length = struct.unpack('!I', length_data)[0]
            
            # Read encrypted metadata
            encrypted_meta = b''
            while len(encrypted_meta) < meta_length:
                chunk = sock.recv(min(4096, meta_length - len(encrypted_meta)))
                if not chunk:
                    return None
                encrypted_meta += chunk
            
            # Decrypt metadata
            meta_json = self.crypto.decrypt(encrypted_meta)
            if not meta_json:
                self.logger.warning("Failed to decrypt file metadata (wrong password?)")
                return None
            
            metadata = json.loads(meta_json)
            
            # Create transfer record
            transfer = FileTransfer(
                file_id=metadata['file_id'],
                filename=metadata['filename'],
                size=metadata['size'],
                sender=metadata['sender'],
                timestamp=metadata['timestamp'],
                total_chunks=metadata['total_chunks'],
                data=b''
            )
            
            with self.lock:
                self.transfers[transfer.file_id] = transfer
            
            self.logger.info(f"Receiving file: {transfer.filename} ({transfer.size} bytes)")
            return transfer
            
        except Exception as e:
            self.logger.error(f"Failed to receive file metadata: {e}")
            return None
    
    def receive_file_chunk(self, transfer: FileTransfer, sock: socket.socket) -> bool:
        """Receive a file chunk."""
        try:
            # Read chunk length
            length_data = sock.recv(4)
            if len(length_data) != 4:
                return False
            
            chunk_length = struct.unpack('!I', length_data)[0]
            
            # Read chunk data
            chunk_data = b''
            while len(chunk_data) < chunk_length:
                chunk = sock.recv(min(CHUNK_SIZE, chunk_length - len(chunk_data)))
                if not chunk:
                    return False
                chunk_data += chunk
            
            # Append to transfer
            transfer.data += chunk_data
            transfer.chunks_received += 1
            
            self._notify_progress(transfer)
            
            # Check if complete
            if transfer.chunks_received >= transfer.total_chunks:
                return self._finalize_transfer(transfer)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to receive chunk: {e}")
            return False
    
    def _finalize_transfer(self, transfer: FileTransfer) -> bool:
        """Finalize and save received file."""
        try:
            # Decrypt file data
            decrypted_data = self.crypto.decrypt_bytes(transfer.data)
            if decrypted_data is None:
                self.logger.error("Failed to decrypt file (wrong password?)")
                transfer.completed = False
                return False
            
            # Save file
            safe_filename = pathlib.Path(transfer.filename).name
            save_path = self.download_dir / safe_filename
            
            # Handle duplicate filenames
            counter = 1
            original_path = save_path
            while save_path.exists():
                stem = original_path.stem
                suffix = original_path.suffix
                save_path = self.download_dir / f"{stem}_{counter}{suffix}"
                counter += 1
            
            with open(save_path, 'wb') as f:
                f.write(decrypted_data)
            
            transfer.save_path = save_path
            transfer.completed = True
            
            self.logger.info(f"File saved: {save_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save file: {e}")
            transfer.completed = False
            return False
    
    def get_transfer(self, file_id: str) -> Optional[FileTransfer]:
        """Get transfer by ID."""
        with self.lock:
            return self.transfers.get(file_id)
    
    def get_all_transfers(self) -> List[FileTransfer]:
        """Get all transfers."""
        with self.lock:
            return list(self.transfers.values())

# =============================================================================
# MESSAGE TRANSPORT MODULE (TCP)
# =============================================================================

class MessageTransport:
    """TCP-based message transport for reliable delivery."""
    
    def __init__(self, port: int, crypto: CryptoManager, 
                 message_callback: Callable[[str, str, str], None],
                 file_manager: Optional[FileTransferManager] = None,
                 logger: Optional[logging.Logger] = None):
        self.port = port
        self.crypto = crypto
        self.on_message = message_callback
        self.file_manager = file_manager
        self.running = False
        self.socket: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.logger = logger or logging.getLogger('lanx')
        self.pending_acks: Dict[str, threading.Event] = {}
    
    def start(self) -> bool:
        """Start TCP listener."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('', self.port))
            self.socket.listen(10)
            self.socket.settimeout(1.0)
        except Exception as e:
            self.logger.error(f"Failed to bind TCP port {self.port}: {e}")
            return False
        
        self.running = True
        self.thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.thread.start()
        
        self.logger.info(f"TCP transport started on port {self.port}")
        return True
    
    def stop(self):
        """Stop TCP listener."""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.logger.info("TCP transport stopped")
    
    def _listen_loop(self):
        """Background thread: Accept incoming connections."""
        while self.running:
            try:
                conn, addr = self.socket.accept()
                handler = threading.Thread(
                    target=self._handle_connection, 
                    args=(conn, addr[0]), 
                    daemon=True
                )
                handler.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.logger.debug(f"Accept error: {e}")
                    time.sleep(0.1)
    
    def _handle_connection(self, conn: socket.socket, ip: str):
        """Handle single incoming connection."""
        try:
            conn.settimeout(30.0)
            
            # Check if it's a file transfer
            magic = conn.recv(len(FILE_MAGIC))
            if magic == FILE_MAGIC:
                self._handle_file_transfer(conn, ip)
                return
            
            # It's a regular message, but we already read some bytes
            # Need to handle this properly - for now, assume it's a message
            # and prepend the magic back (this is a simplification)
            
            # Read message length
            if len(magic) != 4:
                return
            
            length_data = magic
            while len(length_data) < 4:
                chunk = conn.recv(4 - len(length_data))
                if not chunk:
                    return
                length_data += chunk
            
            msg_length = struct.unpack('!I', length_data)[0]
            if msg_length > 65536:
                return
            
            # Read encrypted message
            encrypted_data = b''
            while len(encrypted_data) < msg_length:
                chunk = conn.recv(min(BUFFER_SIZE, msg_length - len(encrypted_data)))
                if not chunk:
                    return
                encrypted_data += chunk
            
            # Decrypt
            plaintext = self.crypto.decrypt(encrypted_data)
            
            if plaintext:
                try:
                    msg_data = json.loads(plaintext)
                    msg_type = msg_data.get('type', MSG_TYPE_CHAT)
                    
                    if msg_type == MSG_TYPE_CHAT:
                        sender = msg_data.get('sender', 'Unknown')
                        content = msg_data.get('content', '')
                        timestamp = msg_data.get('timestamp', '')
                        msg_id = msg_data.get('msg_id', '')
                        
                        self.on_message(sender, content, timestamp)
                        
                        # Send acknowledgment
                        if msg_id:
                            self._send_ack(conn, msg_id)
                            
                    elif msg_type == MSG_TYPE_ACK:
                        msg_id = msg_data.get('msg_id', '')
                        if msg_id in self.pending_acks:
                            self.pending_acks[msg_id].set()
                            
                except json.JSONDecodeError:
                    self.on_message('Unknown', plaintext, '')
            else:
                self.on_message('Unknown', '[ENCRYPTED DATA]', '')
                
        except Exception as e:
            self.logger.debug(f"Connection handler error: {e}")
        finally:
            try:
                conn.close()
            except:
                pass
    
    def _handle_file_transfer(self, conn: socket.socket, ip: str):
        """Handle incoming file transfer."""
        if not self.file_manager:
            self.logger.warning("File transfer received but no file manager configured")
            conn.close()
            return
        
        transfer = self.file_manager.receive_file_metadata(conn, ip)
        if not transfer:
            conn.close()
            return
        
        # Receive all chunks
        while transfer.chunks_received < transfer.total_chunks:
            if not self.file_manager.receive_file_chunk(transfer, conn):
                self.logger.error(f"File transfer failed: {transfer.filename}")
                break
        
        if transfer.completed:
            # Notify about received file
            self.on_message(
                transfer.sender,
                f"[FILE RECEIVED] {transfer.filename} → {transfer.save_path}",
                transfer.timestamp
            )
        
        conn.close()
    
    def _send_ack(self, conn: socket.socket, msg_id: str):
        """Send acknowledgment for a message."""
        try:
            ack_data = json.dumps({
                'type': MSG_TYPE_ACK,
                'msg_id': msg_id,
                'timestamp': datetime.now().isoformat()
            })
            encrypted = self.crypto.encrypt(ack_data)
            length_prefix = struct.pack('!I', len(encrypted))
            conn.sendall(length_prefix + encrypted)
        except Exception as e:
            self.logger.debug(f"Failed to send ACK: {e}")
    
    def send_message(self, ip: str, port: int, sender: str, content: str,
                     wait_for_ack: bool = False, timeout: float = 5.0) -> Tuple[bool, Optional[str]]:
        """
        Send encrypted message to peer.
        
        Returns:
            (success: bool, error_message: Optional[str])
        """
        msg_id = hashlib.sha256(f"{sender}{content}{time.time()}".encode()).hexdigest()[:12]
        
        try:
            payload = json.dumps({
                'type': MSG_TYPE_CHAT,
                'sender': sender,
                'content': content,
                'timestamp': datetime.now().isoformat(),
                'msg_id': msg_id
            })
            
            encrypted = self.crypto.encrypt(payload)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            length_prefix = struct.pack('!I', len(encrypted))
            sock.sendall(length_prefix + encrypted)
            
            if wait_for_ack:
                self.pending_acks[msg_id] = threading.Event()
                
                # Wait for acknowledgment
                sock.settimeout(timeout)
                try:
                    ack_length_data = sock.recv(4)
                    if len(ack_length_data) == 4:
                        ack_length = struct.unpack('!I', ack_length_data)[0]
                        ack_data = b''
                        while len(ack_data) < ack_length:
                            chunk = sock.recv(min(BUFFER_SIZE, ack_length - len(ack_data)))
                            if not chunk:
                                break
                            ack_data += chunk
                        
                        ack_plaintext = self.crypto.decrypt(ack_data)
                        if ack_plaintext:
                            ack_json = json.loads(ack_plaintext)
                            if ack_json.get('type') == MSG_TYPE_ACK:
                                self.logger.debug(f"Received ACK for {msg_id}")
                except socket.timeout:
                    pass
            
            sock.close()
            return True, None
            
        except Exception as e:
            return False, str(e)

# =============================================================================
# MESSAGE HISTORY
# =============================================================================

class MessageHistory:
    """Thread-safe message history storage with persistence."""
    
    def __init__(self, max_size: int = 1000, save_file: Optional[pathlib.Path] = None,
                 logger: Optional[logging.Logger] = None):
        self.messages: List[dict] = []
        self.max_size = max_size
        self.save_file = save_file
        self.lock = threading.Lock()
        self.logger = logger or logging.getLogger('lanx')
        
        if self.save_file:
            self.load()
    
    def add(self, sender: str, content: str, timestamp: str = '', 
            is_me: bool = False, is_system: bool = False,
            msg_type: str = MSG_TYPE_CHAT):
        """Add message to history."""
        with self.lock:
            if not timestamp:
                timestamp = datetime.now().strftime('%H:%M:%S')
            
            message = {
                'sender': sender,
                'content': content,
                'timestamp': timestamp,
                'is_me': is_me,
                'is_system': is_system,
                'type': msg_type,
                'id': hashlib.sha256(f"{sender}{content}{time.time()}".encode()).hexdigest()[:12]
            }
            
            self.messages.append(message)
            
            if len(self.messages) > self.max_size:
                self.messages = self.messages[-self.max_size:]
            
            if self.save_file:
                self._save_async()
    
    def _save_async(self):
        """Save history asynchronously."""
        threading.Thread(target=self.save, daemon=True).start()
    
    def save(self):
        """Save history to file."""
        try:
            if self.save_file:
                self.save_file.parent.mkdir(parents=True, exist_ok=True)
                with open(self.save_file, 'wb') as f:
                    pickle.dump(self.messages, f)
        except Exception as e:
            self.logger.error(f"Failed to save history: {e}")
    
    def load(self):
        """Load history from file."""
        try:
            if self.save_file and self.save_file.exists():
                with open(self.save_file, 'rb') as f:
                    self.messages = pickle.load(f)
                self.logger.info(f"Loaded {len(self.messages)} messages from history")
        except Exception as e:
            self.logger.warning(f"Failed to load history: {e}")
    
    def clear(self):
        """Clear all messages."""
        with self.lock:
            self.messages = []
            if self.save_file and self.save_file.exists():
                try:
                    self.save_file.unlink()
                except:
                    pass
    
    def get_all(self) -> List[dict]:
        """Get all messages."""
        with self.lock:
            return list(self.messages)
    
    def get_recent(self, count: int = 50) -> List[dict]:
        """Get recent messages."""
        with self.lock:
            return list(self.messages[-count:])
    
    def search(self, query: str) -> List[dict]:
        """Search messages by content or sender."""
        with self.lock:
            query = query.lower()
            return [m for m in self.messages if 
                    query in m['content'].lower() or 
                    query in m['sender'].lower()]

# =============================================================================
# CLI/TUI INTERFACE
# =============================================================================

class CLIInterface:
    """Terminal-based UI using ANSI escape codes."""
    
    def __init__(self, username: str, discovery: PeerDiscovery, 
                 transport: MessageTransport, history: MessageHistory,
                 file_manager: Optional[FileTransferManager] = None,
                 logger: Optional[logging.Logger] = None):
        self.username = username
        self.discovery = discovery
        self.transport = transport
        self.history = history
        self.file_manager = file_manager
        self.logger = logger or logging.getLogger('lanx')
        self.running = False
        self.input_queue: queue.Queue = queue.Queue()
        self.display_lock = threading.Lock()
        self.last_peer_count = 0
    
    def start(self):
        """Start CLI interface."""
        self.running = True
        
        self._clear_screen()
        self._draw_header()
        
        refresh_thread = threading.Thread(target=self._refresh_loop, daemon=True)
        refresh_thread.start()
        
        self._input_loop()
    
    def stop(self):
        """Stop CLI interface."""
        self.running = False
    
    def _clear_screen(self):
        """Clear terminal screen."""
        print(Colors.CLEAR_SCREEN + Colors.CURSOR_HOME, end='')
    
    def _draw_header(self):
        """Draw application header."""
        header = f"""
{Colors.BOLD}{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║                    LanX v{VERSION} - Secure LAN Chat                      ║
║              Serverless • Encrypted • P2P • File Sharing              ║
╚══════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
        print(header)
    
    def _draw_status_bar(self):
        """Draw status bar with peer count."""
        peer_count = self.discovery.get_peer_count()
        peers = self.discovery.get_peers()
        
        # Show new peer notification
        if peer_count > self.last_peer_count:
            new_peers = peer_count - self.last_peer_count
            self.history.add('System', f'{new_peers} new peer(s) joined', is_system=True)
        self.last_peer_count = peer_count
        
        peer_list = ', '.join([f"{p['username']}@{ip}" for ip, p in list(peers.items())[:3]])
        if len(peers) > 3:
            peer_list += f" (+{len(peers)-3} more)"
        
        status = f"{Colors.DIM}[{Colors.GREEN}●{Colors.DIM}] Online | User: {Colors.WHITE}{self.username}{Colors.DIM} | Peers: {Colors.CYAN}{peer_count}{Colors.DIM} {peer_list}{Colors.RESET}"
        print(status)
        print(f"{Colors.DIM}{'─' * 74}{Colors.RESET}")
    
    def _draw_messages(self):
        """Draw message history."""
        messages = self.history.get_recent(25)
        
        for msg in messages:
            if msg['is_system']:
                print(f"{Colors.YELLOW}*** {msg['content']} ***{Colors.RESET}")
            elif msg['is_me']:
                print(f"{Colors.GRAY}[{msg['timestamp']}] {Colors.MAGENTA}You{Colors.RESET}: {msg['content']}")
            else:
                if msg['content'].startswith('[FILE RECEIVED]'):
                    print(f"{Colors.GRAY}[{msg['timestamp']}] {Colors.CYAN}{msg['sender']}{Colors.RESET}: {Colors.GREEN}{msg['content']}{Colors.RESET}")
                elif msg['content'] == '[ENCRYPTED DATA]':
                    print(f"{Colors.GRAY}[{msg['timestamp']}] {Colors.CYAN}{msg['sender']}{Colors.RESET}: {Colors.RED}{msg['content']}{Colors.RESET}")
                else:
                    print(f"{Colors.GRAY}[{msg['timestamp']}] {Colors.CYAN}{msg['sender']}{Colors.RESET}: {msg['content']}")
    
    def _draw_input_prompt(self):
        """Draw input prompt."""
        print(f"\n{Colors.DIM}{'─' * 74}{Colors.RESET}")
        print(f"{Colors.BOLD}> {Colors.RESET}", end='', flush=True)
    
    def _refresh_loop(self):
        """Background thread: Refresh display periodically."""
        while self.running:
            with self.display_lock:
                print(f"{Colors.SAVE_CURSOR}{Colors.CURSOR_HOME}{Colors.CLEAR_SCREEN}", end='')
                self._draw_header()
                self._draw_status_bar()
                self._draw_messages()
                self._draw_input_prompt()
                print(Colors.RESTORE_CURSOR, end='', flush=True)
            time.sleep(1.0)
    
    def _input_loop(self):
        """Main input loop."""
        while self.running:
            try:
                message = input()
                
                if not message.strip():
                    continue
                
                if message.startswith('/'):
                    self._handle_command(message)
                    continue
                
                self._broadcast_message(message)
                
                self.history.add(
                    sender=self.username,
                    content=message,
                    is_me=True
                )
                
            except EOFError:
                break
            except KeyboardInterrupt:
                break
        
        self.running = False
    
    def _handle_command(self, cmd: str):
        """Handle slash commands."""
        parts = cmd.split(maxsplit=1)
        command = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ''
        
        if command in ['/quit', '/exit', '/q']:
            self.running = False
            
        elif command == '/peers':
            peers = self.discovery.get_peers()
            if peers:
                msg = "Connected peers:\n" + "\n".join(
                    [f"  • {p['username']}@{ip}:{p['port']}" for ip, p in peers.items()]
                )
            else:
                msg = "No peers discovered yet."
            self.history.add('System', msg, is_system=True)
            
        elif command == '/send':
            self._handle_send_file(arg)
            
        elif command == '/files':
            self._show_file_transfers()
            
        elif command == '/search':
            if arg:
                results = self.history.search(arg)
                if results:
                    msg = f"Found {len(results)} messages:\n" + "\n".join(
                        [f"  [{m['timestamp']}] {m['sender']}: {m['content'][:50]}..." 
                         for m in results[-10:]]
                    )
                else:
                    msg = f"No messages found for '{arg}'"
                self.history.add('System', msg, is_system=True)
            else:
                self.history.add('System', 'Usage: /search <query>', is_system=True)
                
        elif command == '/clear':
            self.history.clear()
            self.history.add('System', 'Chat history cleared', is_system=True)
            
        elif command == '/save':
            self.history.save()
            self.history.add('System', 'Chat history saved', is_system=True)
            
        elif command == '/downloads':
            if self.file_manager:
                path = self.file_manager.download_dir
                msg = f"Downloads folder: {path}\nFiles: {len(list(path.glob('*')))}"
                self.history.add('System', msg, is_system=True)
            
        elif command == '/help':
            help_text = """Commands:
/quit, /exit, /q  - Exit application
/peers            - List connected peers
/send <filepath>  - Send file to all peers
/files            - Show file transfers
/search <query>   - Search message history
/clear            - Clear chat history
/save             - Save chat history
/downloads        - Show downloads folder
/help             - Show this help message"""
            self.history.add('System', help_text, is_system=True)
            
        else:
            self.history.add('System', f"Unknown command: {command}", is_system=True)
    
    def _handle_send_file(self, filepath: str):
        """Handle file send command."""
        if not self.file_manager:
            self.history.add('System', 'File sharing not available', is_system=True)
            return
        
        if not filepath:
            self.history.add('System', 'Usage: /send <filepath>', is_system=True)
            return
        
        path = pathlib.Path(filepath).expanduser()
        if not path.exists():
            self.history.add('System', f'File not found: {filepath}', is_system=True)
            return
        
        peers = self.discovery.get_peers()
        if not peers:
            self.history.add('System', 'No peers to send file to', is_system=True)
            return
        
        self.history.add('System', f'Sending {path.name} to {len(peers)} peer(s)...', is_system=True)
        
        success_count = 0
        for ip, info in peers.items():
            success, msg = self.file_manager.send_file(path, ip, info['port'], self.username)
            if success:
                success_count += 1
            else:
                self.logger.warning(f"Failed to send to {ip}: {msg}")
        
        self.history.add('System', f'File sent to {success_count}/{len(peers)} peer(s)', is_system=True)
    
    def _show_file_transfers(self):
        """Show file transfer status."""
        if not self.file_manager:
            self.history.add('System', 'File sharing not available', is_system=True)
            return
        
        transfers = self.file_manager.get_all_transfers()
        if not transfers:
            self.history.add('System', 'No file transfers', is_system=True)
            return
        
        lines = ['File transfers:']
        for t in transfers[-5:]:
            status = '✓' if t.completed else f'{t.chunks_received}/{t.total_chunks}'
            lines.append(f"  [{status}] {t.filename} ({t.size} bytes) from {t.sender}")
        
        self.history.add('System', '\n'.join(lines), is_system=True)
    
    def _broadcast_message(self, content: str):
        """Send message to all discovered peers."""
        peers = self.discovery.get_peers()
        sent_count = 0
        
        for ip, info in peers.items():
            success, _ = self.transport.send_message(ip, info['port'], self.username, content)
            if success:
                sent_count += 1
        
        if sent_count == 0 and peers:
            self.history.add('System', 'Message queued (no peers reachable)', is_system=True)

# =============================================================================
# WEB INTERFACE
# =============================================================================

class WebInterface:
    """Flask-based web UI with minimalist dark theme."""
    
    HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LanX v{{ version }} - LAN Chat</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        :root {
            --bg-primary: #000000;
            --bg-secondary: #0a0a0a;
            --bg-tertiary: #111111;
            --text-primary: #ffffff;
            --text-secondary: #888888;
            --accent: #00ff88;
            --accent-dim: #00aa55;
            --error: #ff4444;
            --warning: #ffaa00;
            --border: #222222;
            --info: #4488ff;
        }
        
        body {
            font-family: 'SF Mono', 'Consolas', 'Monaco', monospace;
            background: var(--bg-primary);
            color: var(--text-primary);
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        
        .header {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
            padding: 12px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            font-size: 16px;
            font-weight: 600;
            letter-spacing: 2px;
        }
        
        .header h1 span {
            color: var(--accent);
        }
        
        .status {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 12px;
            color: var(--text-secondary);
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--accent);
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .toolbar {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
            padding: 8px 20px;
            display: flex;
            gap: 10px;
        }
        
        .btn {
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            color: var(--text-secondary);
            padding: 6px 14px;
            font-family: inherit;
            font-size: 11px;
            cursor: pointer;
            border-radius: 3px;
            transition: all 0.2s;
        }
        
        .btn:hover {
            border-color: var(--accent);
            color: var(--text-primary);
        }
        
        .messages-container {
            flex: 1;
            overflow-y: auto;
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        
        .message {
            display: flex;
            flex-direction: column;
            gap: 2px;
            max-width: 80%;
            animation: fadeIn 0.2s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(5px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .message.own { align-self: flex-end; align-items: flex-end; }
        .message.system { align-self: center; align-items: center; }
        
        .message-header {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 11px;
        }
        
        .message.own .message-header { flex-direction: row-reverse; }
        
        .message-sender { color: var(--accent); font-weight: 600; }
        .message.own .message-sender { color: var(--accent-dim); }
        .message.system .message-sender { color: var(--warning); }
        
        .message-time { color: var(--text-secondary); }
        
        .message-content {
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 10px 14px;
            font-size: 13px;
            line-height: 1.5;
            word-break: break-word;
        }
        
        .message.own .message-content {
            background: var(--bg-secondary);
            border-color: var(--accent-dim);
        }
        
        .message.system .message-content {
            background: transparent;
            border: none;
            color: var(--warning);
            font-style: italic;
        }
        
        .message.file .message-content { color: var(--accent); }
        .message.encrypted .message-content { color: var(--error); font-style: italic; }
        
        .input-container {
            background: var(--bg-secondary);
            border-top: 1px solid var(--border);
            padding: 15px 20px;
            display: flex;
            gap: 10px;
        }
        
        .message-input {
            flex: 1;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 10px 14px;
            color: var(--text-primary);
            font-family: inherit;
            font-size: 13px;
            outline: none;
            transition: border-color 0.2s;
        }
        
        .message-input:focus { border-color: var(--accent); }
        .message-input::placeholder { color: var(--text-secondary); }
        
        .send-btn {
            background: var(--accent);
            color: #000;
            border: none;
            border-radius: 4px;
            padding: 10px 24px;
            font-family: inherit;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        
        .send-btn:hover { opacity: 0.9; }
        .send-btn:active { opacity: 0.8; }
        
        .file-input { display: none; }
        
        .empty-state {
            text-align: center;
            color: var(--text-secondary);
            padding: 40px;
            font-size: 12px;
        }
        
        .peer-list {
            position: absolute;
            top: 50px;
            right: 20px;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 10px;
            min-width: 200px;
            display: none;
            z-index: 100;
        }
        
        .peer-list.show { display: block; }
        
        .peer-item {
            padding: 6px 10px;
            font-size: 12px;
            border-bottom: 1px solid var(--border);
        }
        
        .peer-item:last-child { border-bottom: none; }
        
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: var(--bg-primary); }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--text-secondary); }
    </style>
</head>
<body>
    <div class="header">
        <h1>LANX <span>v{{ version }}</span></h1>
        <div class="status">
            <div class="status-dot"></div>
            <span>{{ username }}</span>
            <span class="peer-count" id="peerCount">(0 peers)</span>
        </div>
    </div>
    
    <div class="toolbar">
        <button class="btn" onclick="togglePeerList()">Peers</button>
        <button class="btn" onclick="document.getElementById('fileInput').click()">Send File</button>
        <button class="btn" onclick="clearHistory()">Clear</button>
        <button class="btn" onclick="saveHistory()">Save</button>
        <input type="file" id="fileInput" class="file-input" onchange="sendFile(this)">
    </div>
    
    <div class="peer-list" id="peerList">
        <div class="peer-item">No peers connected</div>
    </div>
    
    <div class="messages-container" id="messages">
        <div class="empty-state">Waiting for messages...</div>
    </div>
    
    <div class="input-container">
        <input type="text" class="message-input" id="messageInput" 
               placeholder="Type a message..." autocomplete="off" autofocus>
        <button class="send-btn" onclick="sendMessage()">SEND</button>
    </div>
    
    <script>
        const username = "{{ username }}";
        let lastMessageCount = 0;
        let peersData = [];
        
        async function sendMessage() {
            const input = document.getElementById('messageInput');
            const content = input.value.trim();
            if (!content) return;
            
            try {
                await fetch('/api/send', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ content })
                });
                input.value = '';
                input.focus();
                fetchMessages();
            } catch (err) {
                console.error('Failed to send:', err);
            }
        }
        
        async function sendFile(input) {
            if (!input.files.length) return;
            
            const file = input.files[0];
            const formData = new FormData();
            formData.append('file', file);
            
            try {
                await fetch('/api/send-file', {
                    method: 'POST',
                    body: formData
                });
                input.value = '';
                fetchMessages();
            } catch (err) {
                console.error('Failed to send file:', err);
            }
        }
        
        async function fetchMessages() {
            try {
                const response = await fetch('/api/messages');
                const data = await response.json();
                
                updatePeerCount(data.peer_count);
                peersData = data.peers || [];
                
                if (data.messages.length !== lastMessageCount) {
                    renderMessages(data.messages);
                    lastMessageCount = data.messages.length;
                }
            } catch (err) {
                console.error('Failed to fetch:', err);
            }
        }
        
        function updatePeerCount(count) {
            document.getElementById('peerCount').textContent = `(${count} peer${count !== 1 ? 's' : ''})`;
        }
        
        function togglePeerList() {
            const list = document.getElementById('peerList');
            list.classList.toggle('show');
            
            if (peersData.length > 0) {
                list.innerHTML = peersData.map(p => 
                    `<div class="peer-item">${escapeHtml(p.username)} @ ${p.ip}</div>`
                ).join('');
            } else {
                list.innerHTML = '<div class="peer-item">No peers connected</div>';
            }
        }
        
        function renderMessages(messages) {
            const container = document.getElementById('messages');
            
            if (messages.length === 0) {
                container.innerHTML = '<div class="empty-state">Waiting for messages...</div>';
                return;
            }
            
            container.innerHTML = messages.map(msg => {
                const isOwn = msg.is_me;
                const isSystem = msg.is_system;
                const isEncrypted = msg.content === '[ENCRYPTED DATA]';
                const isFile = msg.content.startsWith('[FILE RECEIVED]');
                
                let className = 'message';
                if (isOwn) className += ' own';
                if (isSystem) className += ' system';
                if (isEncrypted) className += ' encrypted';
                if (isFile) className += ' file';
                
                return `
                    <div class="${className}">
                        <div class="message-header">
                            <span class="message-sender">${escapeHtml(msg.sender)}</span>
                            <span class="message-time">${escapeHtml(msg.timestamp)}</span>
                        </div>
                        <div class="message-content">${escapeHtml(msg.content)}</div>
                    </div>
                `;
            }).join('');
            
            container.scrollTop = container.scrollHeight;
        }
        
        async function clearHistory() {
            await fetch('/api/clear', { method: 'POST' });
            fetchMessages();
        }
        
        async function saveHistory() {
            await fetch('/api/save', { method: 'POST' });
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        document.getElementById('messageInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendMessage();
        });
        
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.btn') && !e.target.closest('.peer-list')) {
                document.getElementById('peerList').classList.remove('show');
            }
        });
        
        setInterval(fetchMessages, 1000);
        fetchMessages();
    </script>
</body>
</html>
'''
    
    def __init__(self, username: str, port: int, discovery: PeerDiscovery,
                 transport: MessageTransport, history: MessageHistory,
                 file_manager: Optional[FileTransferManager] = None):
        self.username = username
        self.port = port
        self.discovery = discovery
        self.transport = transport
        self.history = history
        self.file_manager = file_manager
        self.app = Flask(__name__)
        self.setup_routes()
    
    def setup_routes(self):
        """Configure Flask routes."""
        
        @self.app.route('/')
        def index():
            return render_template_string(
                self.HTML_TEMPLATE,
                version=VERSION,
                username=self.username
            )
        
        @self.app.route('/api/messages')
        def get_messages():
            peers = self.discovery.get_peers()
            return jsonify({
                'messages': self.history.get_all(),
                'peer_count': len(peers),
                'peers': [{'username': p['username'], 'ip': ip} for ip, p in peers.items()]
            })
        
        @self.app.route('/api/send', methods=['POST'])
        def send_message():
            data = request.get_json()
            content = data.get('content', '').strip()
            
            if content:
                self.history.add(sender=self.username, content=content, is_me=True)
                
                peers = self.discovery.get_peers()
                for ip, info in peers.items():
                    self.transport.send_message(ip, info['port'], self.username, content)
                
                return jsonify({'success': True})
            
            return jsonify({'success': False, 'error': 'Empty message'}), 400
        
        @self.app.route('/api/send-file', methods=['POST'])
        def send_file():
            if not self.file_manager:
                return jsonify({'success': False, 'error': 'File sharing not available'}), 400
            
            if 'file' not in request.files:
                return jsonify({'success': False, 'error': 'No file provided'}), 400
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({'success': False, 'error': 'Empty filename'}), 400
            
            # Save temporarily
            temp_path = CONFIG_DIR / 'temp' / file.filename
            temp_path.parent.mkdir(parents=True, exist_ok=True)
            file.save(temp_path)
            
            # Send to peers
            peers = self.discovery.get_peers()
            success_count = 0
            
            for ip, info in peers.items():
                success, _ = self.file_manager.send_file(temp_path, ip, info['port'], self.username)
                if success:
                    success_count += 1
            
            # Cleanup temp file
            try:
                temp_path.unlink()
            except:
                pass
            
            self.history.add(
                'System',
                f'File "{file.filename}" sent to {success_count}/{len(peers)} peer(s)',
                is_system=True
            )
            
            return jsonify({'success': True, 'sent_to': success_count})
        
        @self.app.route('/api/clear', methods=['POST'])
        def clear_history():
            self.history.clear()
            return jsonify({'success': True})
        
        @self.app.route('/api/save', methods=['POST'])
        def save_history():
            self.history.save()
            return jsonify({'success': True})
    
    def start(self):
        """Start web server."""
        print(f"{Colors.GREEN}Starting web interface at http://127.0.0.1:{self.port}{Colors.RESET}")
        print(f"{Colors.DIM}Press Ctrl+C to exit{Colors.RESET}\n")
        
        import logging
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
        
        try:
            self.app.run(
                host='127.0.0.1',
                port=self.port,
                debug=False,
                use_reloader=False
            )
        except KeyboardInterrupt:
            pass

# =============================================================================
# MAIN APPLICATION
# =============================================================================

class LanXApp:
    """Main LanX application orchestrator."""
    
    def __init__(self):
        self.username: str = ""
        self.password: str = ""
        self.tcp_port: int = DEFAULT_TCP_PORT
        self.web_port: int = DEFAULT_WEB_PORT
        self.web_mode: bool = False
        self.config_manager = ConfigManager()
        self.logger: Optional[logging.Logger] = None
        
        self.crypto: Optional[CryptoManager] = None
        self.discovery: Optional[PeerDiscovery] = None
        self.transport: Optional[MessageTransport] = None
        self.history: Optional[MessageHistory] = None
        self.file_manager: Optional[FileTransferManager] = None
        self.ui: Optional[CLIInterface or WebInterface] = None
    
    def parse_args(self):
        """Parse command line arguments."""
        parser = argparse.ArgumentParser(
            description='LanX - Serverless LAN Chat with Encryption',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=f'''
LanX v{VERSION} - Secure P2P LAN Chat

Examples:
  lanx                              # Start with CLI mode
  lanx -w                           # Start with Web UI
  lanx -u Alice -p 5005             # Custom username and port
  lanx --config ~/.lanx/config.json # Use custom config file

Commands (CLI mode):
  /quit, /exit, /q  - Exit application
  /peers            - List connected peers
  /send <filepath>  - Send file to all peers
  /files            - Show file transfers
  /search <query>   - Search message history
  /clear            - Clear chat history
  /save             - Save chat history
  /downloads        - Show downloads folder
  /help             - Show help message

File Sharing:
  Files are automatically saved to: ~/.lanx/downloads/
  Maximum file size: 100MB

For more information: https://github.com/lanx/lanx-chat
            '''
        )
        
        parser.add_argument('-w', '--web', action='store_true',
                            help='Start in web UI mode (default: CLI)')
        parser.add_argument('-u', '--username', type=str, default='',
                            help='Your username (default: hostname or from config)')
        parser.add_argument('-p', '--port', type=int, default=0,
                            help=f'TCP port for messaging (default: {DEFAULT_TCP_PORT} or from config)')
        parser.add_argument('--web-port', type=int, default=0,
                            help=f'Web UI port (default: {DEFAULT_WEB_PORT} or from config)')
        parser.add_argument('-c', '--config', type=str, default='',
                            help='Path to config file')
        parser.add_argument('--no-save', action='store_true',
                            help='Do not save chat history')
        parser.add_argument('--log-level', type=str, default='INFO',
                            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                            help='Logging level (default: INFO)')
        parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {VERSION}')
        
        args = parser.parse_args()
        
        # Setup logging first
        self.logger = setup_logging(args.log_level)
        
        # Load custom config if specified
        if args.config:
            global CONFIG_FILE
            CONFIG_FILE = pathlib.Path(args.config)
            self.config_manager = ConfigManager()
        
        # Apply arguments (CLI overrides config)
        self.web_mode = args.web
        self.username = args.username or self.config_manager.get('username') or socket.gethostname()
        self.tcp_port = args.port or self.config_manager.get('tcp_port') or DEFAULT_TCP_PORT
        self.web_port = args.web_port or self.config_manager.get('web_port') or DEFAULT_WEB_PORT
        
        # Save config
        self.config_manager.set('username', self.username)
        self.config_manager.set('tcp_port', self.tcp_port)
        self.config_manager.set('web_port', self.web_port)
    
    def setup_password(self):
        """Get room password from user."""
        import getpass
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}LanX v{VERSION} - Secure LAN Chat{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}\n")
        
        print(f"{Colors.YELLOW}Enter the Room Password to join/create a secure channel.{Colors.RESET}")
        print(f"{Colors.DIM}All users must use the same password to communicate.{Colors.RESET}\n")
        
        while True:
            password = getpass.getpass(f"{Colors.BOLD}Room Password: {Colors.RESET}")
            if len(password) >= 4:
                self.password = password
                break
            print(f"{Colors.RED}Password must be at least 4 characters.{Colors.RESET}\n")
    
    def initialize(self) -> bool:
        """Initialize all components."""
        # Initialize crypto
        self.crypto = CryptoManager(self.password)
        
        # Initialize message history
        save_history = self.config_manager.get('save_history', True)
        history_file = HISTORY_FILE if save_history else None
        self.history = MessageHistory(
            max_size=self.config_manager.get('max_history', 1000),
            save_file=history_file,
            logger=self.logger
        )
        
        # Add welcome message
        self.history.add(
            'System',
            f'Welcome to LanX v{VERSION}! You are "{self.username}" on port {self.tcp_port}',
            is_system=True
        )
        
        # Initialize file manager
        download_dir = pathlib.Path(self.config_manager.get('download_dir', str(DOWNLOADS_DIR)))
        self.file_manager = FileTransferManager(
            self.crypto,
            download_dir,
            logger=self.logger
        )
        
        # Initialize discovery
        udp_port = self.config_manager.get('udp_port', DEFAULT_UDP_PORT)
        self.discovery = PeerDiscovery(
            self.username,
            self.tcp_port,
            udp_port,
            logger=self.logger
        )
        if not self.discovery.start():
            return False
        
        # Initialize transport
        self.transport = MessageTransport(
            self.tcp_port,
            self.crypto,
            self._on_message_received,
            file_manager=self.file_manager,
            logger=self.logger
        )
        if not self.transport.start():
            return False
        
        return True
    
    def _on_message_received(self, sender: str, content: str, timestamp: str):
        """Callback for received messages."""
        self.history.add(sender, content, timestamp)
    
    def run(self):
        """Main entry point."""
        self.parse_args()
        self.setup_password()
        
        print(f"\n{Colors.GREEN}Initializing LanX...{Colors.RESET}")
        
        if not self.initialize():
            print(f"{Colors.RED}Failed to initialize. Check port availability.{Colors.RESET}")
            sys.exit(1)
        
        print(f"{Colors.GREEN}✓ Discovery service started (UDP){Colors.RESET}")
        print(f"{Colors.GREEN}✓ Message transport started (TCP port {self.tcp_port}){Colors.RESET}")
        print(f"{Colors.GREEN}✓ Encryption initialized (AES-256-GCM){Colors.RESET}")
        print(f"{Colors.GREEN}✓ File sharing enabled (max 100MB){Colors.RESET}")
        print(f"{Colors.GREEN}✓ Downloads: {self.file_manager.download_dir}{Colors.RESET}")
        
        # Start UI
        if self.web_mode:
            if not FLASK_AVAILABLE:
                print(f"{Colors.RED}Flask not installed. Run: pip install flask{Colors.RESET}")
                sys.exit(1)
            
            self.ui = WebInterface(
                self.username,
                self.web_port,
                self.discovery,
                self.transport,
                self.history,
                file_manager=self.file_manager
            )
            self.ui.start()
        else:
            print(f"{Colors.GREEN}✓ CLI interface starting...{Colors.RESET}\n")
            time.sleep(0.5)
            
            self.ui = CLIInterface(
                self.username,
                self.discovery,
                self.transport,
                self.history,
                file_manager=self.file_manager,
                logger=self.logger
            )
            self.ui.start()
    
    def shutdown(self):
        """Clean shutdown."""
        if self.logger: self.logger.info("Shutting down LanX...")
        
        if self.history:
            self.history.save()
        
        if self.discovery:
            self.discovery.stop()
        
        if self.transport:
            self.transport.stop()
        
        if self.logger: self.logger.info("LanX shutdown complete")


def main():
    """Application entry point."""
    app = LanXApp()
    
    try:
        app.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Shutting down...{Colors.RESET}")
    finally:
        app.shutdown()


if __name__ == '__main__':
    main()
