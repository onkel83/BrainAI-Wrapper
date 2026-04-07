import ctypes
import os
import platform

# --- KONSTANTEN & FEHLERCODES ---
class ProChatConfig:
    PC_PKT_SIZE = 1024     # Feste Paketgröße
    PC_MAX_PAYLOAD = 988   # Maximale Nutzlast

class ProChatStatus:
    PC_OK = 0
    PC_ERR_PARAM = -1      # Ungültige Parameter
    PC_ERR_AUTH = -2       # Authentifizierungsfehler (MAC ungültig)
    PC_ERR_REPLAY = -3     # Replay-Attacke erkannt
    PC_ERR_DESYNC = -4     # Ratchet-Desynchronisation

# --- LIBRARY LOADER ---
def _load_lib():
    name = "prochat"
    system = platform.system()
    if system == "Windows":
        lib_name = f"{name}.dll"
    else:
        lib_name = f"lib{name}.so"
    
    try:
        # Sucht im aktuellen Verzeichnis oder im Systempfad
        return ctypes.CDLL(os.path.abspath(lib_name))
    except OSError:
        return ctypes.CDLL(lib_name)

_lib = _load_lib()

# --- FUNKTIONS-SIGNATUREN ---

# const char* pc_get_version_info(uint8_t* out_major, uint8_t* out_minor, uint8_t* out_patch)
_lib.pc_get_version_info.argtypes = [
    ctypes.POINTER(ctypes.c_uint8), 
    ctypes.POINTER(ctypes.c_uint8), 
    ctypes.POINTER(ctypes.c_uint8)
]
_lib.pc_get_version_info.restype = ctypes.c_char_p

# void pc_init(uint32_t uid, const uint8_t* seed)
_lib.pc_init.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint8)]
_lib.pc_init.restype = None

# int pc_add_peer(uint32_t uid, const uint8_t* k)
_lib.pc_add_peer.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint8)]
_lib.pc_add_peer.restype = ctypes.c_int

# int pc_encrypt(uint32_t target, uint8_t type, const uint8_t* msg, size_t len, uint8_t* out)
_lib.pc_encrypt.argtypes = [
    ctypes.c_uint32, ctypes.c_uint8, 
    ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, 
    ctypes.POINTER(ctypes.c_uint8)
]
_lib.pc_encrypt.restype = ctypes.c_int

# int pc_decrypt(uint8_t* pkt, uint32_t* out_sender, uint8_t* out_buf)
_lib.pc_decrypt.argtypes = [
    ctypes.POINTER(ctypes.c_uint8), 
    ctypes.POINTER(ctypes.c_uint32), 
    ctypes.POINTER(ctypes.c_uint8)
]
_lib.pc_decrypt.restype = ctypes.c_int

# --- HIGH-LEVEL API ---

class ProChat:
    def __init__(self, uid: int, seed: bytes):
        """Initialisiert die Engine mit eigener UID und 32-Byte Seed."""
        if len(seed) != 32:
            raise ValueError("Seed muss exakt 32 Bytes lang sein.")
        
        self.uid = uid
        seed_ptr = (ctypes.c_uint8 * 32).from_buffer_copy(seed)
        _lib.pc_init(uid, seed_ptr)

    @staticmethod
    def get_version():
        """Gibt die Versionsinfo der Library zurück."""
        major, minor, patch = ctypes.c_uint8(), ctypes.c_uint8(), ctypes.c_uint8()
        info = _lib.pc_get_version_info(ctypes.byref(major), ctypes.byref(minor), ctypes.byref(patch))
        return info.decode('utf-8'), major.value, minor.value, patch.value

    def add_peer(self, peer_uid: int, key: bytes):
        """Fügt einen Kommunikationspartner hinzu (Schlüssel: 32 Bytes)."""
        if len(key) != 32:
            raise ValueError("Key muss exakt 32 Bytes lang sein.")
        
        key_ptr = (ctypes.c_uint8 * 32).from_buffer_copy(key)
        res = _lib.pc_add_peer(peer_uid, key_ptr)
        return res == ProChatStatus.PC_OK

    def encrypt(self, target_uid: int, msg_type: int, message: bytes) -> bytes:
        """Verschlüsselt eine Nachricht in ein 1024-Byte Paket."""
        if len(message) > ProChatConfig.PC_MAX_PAYLOAD:
            raise ValueError(f"Nachricht zu lang (max {ProChatConfig.PC_MAX_PAYLOAD} Bytes).")
        
        out_pkt = (ctypes.c_uint8 * ProChatConfig.PC_PKT_SIZE)()
        msg_ptr = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
        
        res = _lib.pc_encrypt(target_uid, msg_type, msg_ptr, len(message), out_pkt)
        if res != ProChatStatus.PC_OK:
            return None
            
        return bytes(out_pkt)

    def decrypt(self, packet: bytes):
        """Entschlüsselt ein Paket. Gibt (sender_uid, payload) oder None zurück."""
        if len(packet) != ProChatConfig.PC_PKT_SIZE:
            return None
            
        pkt_ptr = (ctypes.c_uint8 * len(packet)).from_buffer_copy(packet)
        sender_uid = ctypes.c_uint32()
        out_buf = (ctypes.c_uint8 * ProChatConfig.PC_MAX_PAYLOAD)()
        
        bytes_done = _lib.pc_decrypt(pkt_ptr, ctypes.byref(sender_uid), out_buf)
        
        if bytes_done < 0:
            return None
            
        return sender_uid.value, bytes(out_buf[:bytes_done])

# --- BEISPIEL ---
if __name__ == "__main__":
    ver_str, ma, mi, pa = ProChat.get_version()
    print(f"Library geladen: {ver_str}")

    # Initialisierung (UID 100)
    seed = b"\x01" * 32
    client = ProChat(100, seed)
    
    # Partner hinzufügen (UID 200)
    peer_key = b"\x02" * 32
    client.add_peer(200, peer_key)
    print("Partner UID 200 hinzugefügt.")
