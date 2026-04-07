import ctypes
import os
import platform

# --- STRUKTUREN (Mapping zu ProHash.h) ---

class ProHashCtx(ctypes.Structure):
    """
    Entspricht ProHash_Ctx (136 Bytes)
    """
    _pack_ = 8
    _fields_ = [
        ("belt", ctypes.c_uint32 * 16),   # 512-Bit Internal State
        ("count", ctypes.c_uint64),      # Processed Bytes
        ("buffer", ctypes.c_uint8 * 64),  # Block Buffer
        ("buf_idx", ctypes.c_uint32)      # Buffer Position
    ]

# --- LIBRARY LOADER ---

def _load_prohash_lib():
    system = platform.system()
    if system == "Windows":
        lib_name = "prohash.dll"
    else:
        lib_name = "libprohash.so"
    
    # Versuche im aktuellen Verzeichnis oder System-Pfad zu laden
    try:
        return ctypes.CDLL(os.path.join(os.getcwd(), lib_name))
    except OSError:
        return ctypes.CDLL(lib_name)

_lib = _load_prohash_lib()

# --- FUNKTIONS-DEFINITIONEN ---

_lib.prohash_init.argtypes = [ctypes.POINTER(ProHashCtx)]
_lib.prohash_init.restype = None

_lib.prohash_update.argtypes = [ctypes.POINTER(ProHashCtx), ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
_lib.prohash_update.restype = None

_lib.prohash_final.argtypes = [ctypes.POINTER(ProHashCtx), ctypes.POINTER(ctypes.c_uint8)]
_lib.prohash_final.restype = None

_lib.prohash_get_version_info.argtypes = []
_lib.prohash_get_version_info.restype = ctypes.c_char_p

# --- HIGH-LEVEL API ---

class ProHash:
    """
    ProHash-256 Python Wrapper ("The Shredder")
    """
    def __init__(self):
        self._ctx = ProHashCtx()
        _lib.prohash_init(ctypes.byref(self._ctx))
        self._finalized = False

    @staticmethod
    def get_version():
        """Gibt Versions- und Entwickler-Infos zurück"""
        return _lib.prohash_get_version_info().decode('utf-8')

    def update(self, data):
        """Verarbeitet Bytes oder Bytearrays"""
        if self._finalized:
            raise RuntimeError("Hash already finalized.")
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        if not data:
            return

        # Erzeuge Pointer auf die Daten
        data_ptr = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        _lib.prohash_update(ctypes.byref(self._ctx), data_ptr, len(data))

    def finalize(self):
        """Schließt die Berechnung ab und gibt 32 Bytes zurück"""
        if self._finalized:
            raise RuntimeError("Hash already finalized.")
        
        digest = (ctypes.c_uint8 * 32)()
        _lib.prohash_final(ctypes.byref(self._ctx), digest)
        self._finalized = True
        
        return bytes(digest)

    @staticmethod
    def quick_hash(data, hex_format=True):
        """Einfache statische Methode für schnelles Hashing"""
        hasher = ProHash()
        hasher.update(data)
        digest = hasher.finalize()
        return digest.hex().upper() if hex_format else digest

# --- BEISPIEL ---
if __name__ == "__main__":
    print(f"Using: {ProHash.get_version()}")
    
    # Text-Hashing
    test_str = "BrainAI Zero-Trust"
    print(f"Hash of '{test_str}': {ProHash.quick_hash(test_str)}")
    
    # Streaming-Beispiel
    hasher = ProHash()
    hasher.update(b"Part 1 ")
    hasher.update(b"Part 2")
    print(f"Streaming Result: {hasher.finalize().hex().upper()}")