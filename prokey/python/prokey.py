import ctypes
import os
import platform
from enum import IntEnum

# --- KONSTANTEN & ENUMS ---

class ProKeyStatus(IntEnum):
    SUCCESS = 0
    ERROR_PARAM = -1
    ERROR_HARDWARE = -2
    ERROR_STREAM = -3

class ProKeyBits(IntEnum):
    BIT_128 = 128
    BIT_256 = 256
    BIT_512 = 512
    BIT_1024 = 1024

    @property
    def bytes(self):
        return self.value // 8

# --- LIBRARY LOADER ---

def _load_prokey_lib():
    system = platform.system()
    if system == "Windows":
        lib_name = "prokey.dll"
    else:
        lib_name = "libprokey.so"
    
    # Versuche im aktuellen Verzeichnis oder System-Pfad zu laden
    try:
        return ctypes.CDLL(os.path.join(os.getcwd(), lib_name))
    except OSError:
        return ctypes.CDLL(lib_name)

_lib = _load_prokey_lib()

# --- FUNKTIONS-SIGNATUREN ---

_lib.ProKey_GetVersion.argtypes = []
_lib.ProKey_GetVersion.restype = ctypes.c_char_p

_lib.ProKey_Generate.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
_lib.ProKey_Generate.restype = None

_lib.ProKey_Fill256Bit.argtypes = [ctypes.POINTER(ctypes.c_uint8)]
_lib.ProKey_Fill256Bit.restype = None

# --- HIGH-LEVEL API ---

class ProKey:
    """
    ProKey Python Wrapper (Hardware Entropie / RNG)
    """

    @staticmethod
    def get_version() -> str:
        """
        Gibt die Versions- und Entwicklerinformationen der Library zurück.
        """
        return _lib.ProKey_GetVersion().decode('utf-8')

    @staticmethod
    def generate_bytes(length_in_bytes: int) -> bytes:
        """
        Generiert eine angegebene Menge an kryptografisch starkem Zufall in Bytes.
        """
        if length_in_bytes <= 0:
            raise ValueError("Length must be greater than zero.")
        
        # Allokiere C-kompatiblen Speicher (Byte-Array)
        buffer = (ctypes.c_uint8 * length_in_bytes)()
        _lib.ProKey_Generate(buffer, length_in_bytes)
        
        return bytes(buffer)

    @staticmethod
    def generate_key(bits: ProKeyBits) -> bytes:
        """
        Generiert kryptografisch starken Zufall basierend auf den vordefinierten Bit-Längen.
        """
        if not isinstance(bits, ProKeyBits):
            raise TypeError("bits must be an instance of ProKeyBits Enum")
            
        return ProKey.generate_bytes(bits.bytes)

    @staticmethod
    def generate_256bit_key() -> bytes:
        """
        Convenience-Wrapper für genau 256 Bit (32 Byte), nutzt die optimierte C-Funktion.
        """
        buffer = (ctypes.c_uint8 * 32)()
        _lib.ProKey_Fill256Bit(buffer)
        return bytes(buffer)

# --- BEISPIELNUTZUNG ---
if __name__ == "__main__":
    print(f"Engine: {ProKey.get_version()}")
    
    # 1. Schnelle Erzeugung eines 256-Bit Schlüssels
    master_key = ProKey.generate_256bit_key()
    print(f"AES-256 Master Key (Hex): {master_key.hex().upper()}")
    
    # 2. Erzeugung eines 512-Bit Tokens über das Enum
    session_token = ProKey.generate_key(ProKeyBits.BIT_512)
    print(f"Session Token (Hex): {session_token.hex().upper()}")
    
    # 3. Benutzerdefinierte Länge (z.B. 16 Bytes für IV/Nonce)
    iv = ProKey.generate_bytes(16)
    print(f"Initialization Vector: {iv.hex().upper()}")