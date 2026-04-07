const ffi = require('ffi-napi');
const ref = require('ref-napi');

// --- DATENTYPEN ---
const uint8 = ref.types.uint8;
const uint32 = ref.types.uint32;
const size_t = ref.types.size_t;
const pointer = ref.refType(ref.types.void);

// --- KONSTANTEN ---
const HEADER_SIZE = 48; // 16 Byte IV + 32 Byte HMAC
const KEY_SIZE = 32;    // 256-Bit Key
const CTX_SIZE = 120;   // Größe der ProED_Context Struct

// --- Windows IOCTL Konstanten ---
const GENERIC_READ = 0x80000000;
const GENERIC_WRITE = 0x40000000;
const OPEN_EXISTING = 3;
const FILE_DEVICE_UNKNOWN = 0x00000022;
const METHOD_BUFFERED = 0;
const FILE_ANY_ACCESS = 0;

// IOCTL_PROKM_PROED = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Entspricht ((0x22 << 16) | (0 << 14) | (0x801 << 2) | 0) = 0x222004
const IOCTL_PROKM_PROED = 0x222004;

// --- LIBRARY DEFINITIONEN ---
const isWin = process.platform === 'win32';
const libName = isWin ? 'proed.dll' : 'libproed.so';

const proedLib = ffi.Library(libName, {
    'proed_get_version_info': ['string', ['pointer', 'pointer', 'pointer']],
    'proed_encrypt_envelope': ['int', ['pointer', 'pointer', size_t, 'pointer', size_t]],
    'proed_decrypt_envelope': ['int', ['pointer', 'pointer', size_t, 'pointer', size_t]]
});

// Windows Kernel32 API (nur laden, wenn wir auf Windows sind)
let kernel32 = null;
if (isWin) {
    kernel32 = ffi.Library('kernel32', {
        'CreateFileA': [pointer, ['string', uint32, uint32, pointer, uint32, uint32, pointer]],
        'DeviceIoControl': ['int', [pointer, uint32, pointer, uint32, pointer, uint32, pointer, pointer]],
        'CloseHandle': ['int', [pointer]]
    });
}

class ProED {
    /**
     * @param {Buffer} key 32-Byte Session Key
     */
    constructor(key) {
        if (!Buffer.isBuffer(key) || key.length !== KEY_SIZE) {
            throw new Error(`Key muss ein Buffer von exakt ${KEY_SIZE} Bytes sein.`);
        }
        this.key = key;
        this.hDevice = null;
        this.isKernelModeActive = false;

        // Prüfen, ob der Windows ProKM Kernel-Treiber erreichbar ist
        if (isWin && kernel32) {
            // GENERIC_READ | GENERIC_WRITE in JS Bitwise sicher machen (da JS Bitwise in 32-Bit signed ist)
            const access = (GENERIC_READ | GENERIC_WRITE) >>> 0;

            this.hDevice = kernel32.CreateFileA(
                "\\\\.\\ProKM", access, 0, null, OPEN_EXISTING, 0, null
            );

            // Pointer.address() gibt die Speicheradresse. -1 (0xFFFFFFFF) ist INVALID_HANDLE_VALUE
            if (!this.hDevice.isNull() && this.hDevice.address() !== -1) {
                this.isKernelModeActive = true;
            }
        }
    }

    static getVersion() {
        const major = ref.alloc(uint8);
        const minor = ref.alloc(uint8);
        const patch = ref.alloc(uint8);
        const info = proedLib.proed_get_version_info(major, minor, patch);
        return {
            info,
            version: `${major.deref()}.${minor.deref()}.${patch.deref()}`
        };
    }

    // =========================================================================
    // METHODE 1: KERNEL-MODE (Ring-0) - Raw High-Speed Verschlüsselung
    // =========================================================================
    processKernel(payload, iv, isDecrypt) {
        if (!this.isKernelModeActive) {
            throw new Error("ProKM Kernel-Driver ist nicht geladen. Fallback auf Software-Envelope erforderlich.");
        }
        if (!Buffer.isBuffer(iv) || iv.length !== 16) {
            throw new Error("IV muss exakt 16 Bytes lang sein.");
        }

        const payloadBuf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
        const mode = isDecrypt ? 1 : 0;
        const dataLen = payloadBuf.length;

        // Struct Layout: Key(32) + IV(16) + Mode(4) + DataLen(4) + Payload(N)
        const reqSize = 32 + 16 + 4 + 4 + dataLen;
        const requestBuffer = Buffer.alloc(reqSize);

        this.key.copy(requestBuffer, 0);                 // [0-31] Key
        iv.copy(requestBuffer, 32);                      // [32-47] IV
        requestBuffer.writeUInt32LE(mode, 48);           // [48-51] Mode
        requestBuffer.writeUInt32LE(dataLen, 52);        // [52-55] DataLen
        payloadBuf.copy(requestBuffer, 56);              // [56-..] Payload

        const outBuffer = Buffer.alloc(reqSize);
        const bytesReturned = ref.alloc(uint32);

        // IOCTL Call an den Windows Kernel
        const success = kernel32.DeviceIoControl(
            this.hDevice, IOCTL_PROKM_PROED,
            requestBuffer, reqSize,
            outBuffer, reqSize,
            bytesReturned, null
        );

        if (success === 0) {
            throw new Error("Kernel DeviceIoControl fehlgeschlagen.");
        }

        // Die verarbeitete Payload beginnt im outBuffer ab Byte 56
        return outBuffer.slice(56, 56 + dataLen);
    }

    // =========================================================================
    // METHODE 2: SOFTWARE-MODE (Ring-3) - Armored Envelope (inkl. MAC)
    // =========================================================================
    encryptEnvelopeSoftware(payload) {
        const payloadBuf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
        const totalLen = HEADER_SIZE + payloadBuf.length;

        const buffer = Buffer.alloc(totalLen);
        payloadBuf.copy(buffer, HEADER_SIZE); // Payload hinter den Header kopieren

        const ctx = Buffer.alloc(CTX_SIZE);
        const res = proedLib.proed_encrypt_envelope(ctx, this.key, this.key.length, buffer, totalLen);

        return res === 1 ? buffer : null;
    }

    decryptEnvelopeSoftware(packet) {
        if (!Buffer.isBuffer(packet) || packet.length < HEADER_SIZE) return null;

        const buffer = Buffer.from(packet);
        const ctx = Buffer.alloc(CTX_SIZE);

        const res = proedLib.proed_decrypt_envelope(ctx, this.key, this.key.length, buffer, buffer.length);

        if (res === 0) return null; // HMAC Check fehlgeschlagen!

        // Gibt nur die Payload (ohne Header) zurück
        return buffer.slice(HEADER_SIZE);
    }

    close() {
        if (this.isKernelModeActive && this.hDevice && kernel32) {
            kernel32.CloseHandle(this.hDevice);
            this.hDevice = null;
            this.isKernelModeActive = false;
        }
    }
}

module.exports = ProED;