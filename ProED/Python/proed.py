import ctypes
import os
import platform
import struct

# --- KONSTANTEN ---
class ProEDConfig:
    HEADER_SIZE = 48  # 16 Byte IV + 32 Byte HMAC
    KEY_SIZE = 32     # 256-Bit Key
    CTX_SIZE = 120    # Größe der ProED_Context Struct

    # --- Windows IOCTL Konstanten ---
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    FILE_DEVICE_UNKNOWN = 0x00000022
    METHOD_BUFFERED = 0
    FILE_ANY_ACCESS = 0

    # IOCTL_PROKM_PROED = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
    IOCTL_PROKM_PROED = (FILE_DEVICE_UNKNOWN << 16) | (FILE_ANY_ACCESS << 14) | (0x801 << 2) | METHOD_BUFFERED


# --- LIBRARY LOADER ---
is_win = platform.system() == "Windows"

def _load_lib(name):
    lib_name = f"{name}.dll" if is_win else f"lib{name}.so"
    try:
        return ctypes.CDLL(os.path.abspath(lib_name))
    except OSError:
        return ctypes.CDLL(lib_name)

proed_lib = _load_lib("proed")

# --- KERNEL32 API (nur Windows) ---
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True) if is_win else None

if kernel32:
    kernel32.CreateFileA.argtypes = [ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    kernel32.CreateFileA.restype = ctypes.c_void_p

    kernel32.DeviceIoControl.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
    kernel32.DeviceIoControl.restype = ctypes.c_bool

    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_bool


# --- PROED DLL SIGNATUREN ---
proed_lib.proed_get_version_info.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8)]
proed_lib.proed_get_version_info.restype = ctypes.c_char_p

proed_lib.proed_encrypt_envelope.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
proed_lib.proed_encrypt_envelope.restype = ctypes.c_int

proed_lib.proed_decrypt_envelope.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
proed_lib.proed_decrypt_envelope.restype = ctypes.c_int


# --- HIGH-LEVEL HYBRID CLIENT ---
class ProED:
    def __init__(self, key: bytes):
        if len(key) != ProEDConfig.KEY_SIZE:
            raise ValueError(f"Key muss exakt {ProEDConfig.KEY_SIZE} Bytes lang sein.")
        
        self.key = key
        self.key_ptr = (ctypes.c_uint8 * len(key)).from_buffer_copy(key)
        self.key_len = len(key)
        
        self.h_device = None
        self.is_kernel_mode_active = False

        # Prüfen, ob der Windows Kernel-Treiber geladen und erreichbar ist
        if is_win and kernel32:
            handle = kernel32.CreateFileA(
                b"\\\\.\\ProKM",
                ProEDConfig.GENERIC_READ | ProEDConfig.GENERIC_WRITE,
                0, None, ProEDConfig.OPEN_EXISTING, 0, None
            )
            
            # Überprüfe auf INVALID_HANDLE_VALUE (-1)
            if handle is not None and handle != -1 and handle != 0xffffffffffffffff:
                self.h_device = handle
                self.is_kernel_mode_active = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        """Gibt das Kernel-Handle sauber frei."""
        if self.is_kernel_mode_active and self.h_device is not None and kernel32:
            kernel32.CloseHandle(self.h_device)
            self.h_device = None
            self.is_kernel_mode_active = False

    @staticmethod
    def get_version():
        ma, mi, pa = ctypes.c_uint8(), ctypes.c_uint8(), ctypes.c_uint8()
        info = proed_lib.proed_get_version_info(ctypes.byref(ma), ctypes.byref(mi), ctypes.byref(pa))
        return info.decode('utf-8'), ma.value, mi.value, pa.value

    # =========================================================================
    # METHODE 1: KERNEL-MODE (Ring-0) - Raw High-Speed Verschlüsselung
    # =========================================================================
    def process_kernel(self, payload: bytes, iv: bytes, is_decrypt: bool) -> bytes:
        if not self.is_kernel_mode_active:
            raise RuntimeError("ProKM Kernel-Driver ist nicht geladen. Fallback auf Software-Envelope erforderlich.")
        if len(iv) != 16:
            raise ValueError("IV muss exakt 16 Bytes lang sein.")

        mode = 1 if is_decrypt else 0
        data_len = len(payload)

        # Struct zusammenbauen: Key(32) + IV(16) + Mode(4, LE) + DataLen(4, LE) + Payload(N)
        # "<II" steht für Little Endian, zwei unsigned Integer (4 Bytes)
        request_data = self.key + iv + struct.pack("<II", mode, data_len) + payload
        req_size = len(request_data)

        in_buffer = ctypes.create_string_buffer(request_data, req_size)
        out_buffer = ctypes.create_string_buffer(req_size)
        bytes_returned = ctypes.c_uint32(0)

        success = kernel32.DeviceIoControl(
            self.h_device,
            ProEDConfig.IOCTL_PROKM_PROED,
            in_buffer, req_size,
            out_buffer, req_size,
            ctypes.byref(bytes_returned), None
        )

        if not success:
            err = ctypes.get_last_error()
            raise OSError(f"Kernel DeviceIoControl fehlgeschlagen. Windows Error Code: {err}")

        # Die verarbeitete Payload beginnt im out_buffer ab Byte 56
        return out_buffer.raw[56:56+data_len]

    # =========================================================================
    # METHODE 2: SOFTWARE-MODE (Ring-3) - Armored Envelope (inkl. MAC)
    # =========================================================================
    def encrypt_envelope_software(self, payload: bytes) -> bytes:
        total_len = len(payload) + ProEDConfig.HEADER_SIZE
        buffer = (ctypes.c_uint8 * total_len)()
        
        # Payload hinter den Header kopieren
        ctypes.memmove(ctypes.addressof(buffer) + ProEDConfig.HEADER_SIZE, payload, len(payload))
        
        ctx = (ctypes.c_uint8 * ProEDConfig.CTX_SIZE)()
        res = proed_lib.proed_encrypt_envelope(ctx, self.key_ptr, self.key_len, buffer, total_len)
        
        if res == 0:
            return None
        return bytes(buffer)

    def decrypt_envelope_software(self, packet: bytes):
        if len(packet) < ProEDConfig.HEADER_SIZE:
            return None
            
        total_len = len(packet)
        buffer = (ctypes.c_uint8 * total_len).from_buffer_copy(packet)
        ctx = (ctypes.c_uint8 * ProEDConfig.CTX_SIZE)()
        
        res = proed_lib.proed_decrypt_envelope(ctx, self.key_ptr, self.key_len, buffer, total_len)
        
        if res == 0:
            return None # HMAC Check fehlgeschlagen!
            
        return bytes(buffer)[ProEDConfig.HEADER_SIZE:]