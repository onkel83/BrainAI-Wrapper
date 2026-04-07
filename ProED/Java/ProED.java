package com.brainai.proed;

import com.sun.jna.*;
import com.sun.jna.ptr.IntByReference;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class ProED implements AutoCloseable {

    // --- KONSTANTEN ---
    public interface Config {
        int HEADER_SIZE = 48; // 16 Byte IV + 32 Byte HMAC
        int KEY_SIZE = 32;    // 256-Bit Key
        int CTX_SIZE = 120;   // Größe der ProED_Context Struct
        
        // --- Windows IOCTL Konstanten ---
        int GENERIC_READ = 0x80000000;
        int GENERIC_WRITE = 0x40000000;
        int OPEN_EXISTING = 3;
        int FILE_DEVICE_UNKNOWN = 0x00000022;
        int METHOD_BUFFERED = 0;
        int FILE_ANY_ACCESS = 0;
        
        // IOCTL_PROKM_PROED = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
        int IOCTL_PROKM_PROED = (FILE_DEVICE_UNKNOWN << 16) | (FILE_ANY_ACCESS << 14) | (0x801 << 2) | METHOD_BUFFERED;
    }

    // --- NATIVE INTERFACE: ProED DLL/SO (Software Fallback) ---
    public interface IProED extends Library {
        IProED INSTANCE = Native.load("proed", IProED.class);

        String proed_get_version_info(Pointer outMajor, Pointer outMinor, Pointer outPatch);
        int proed_encrypt_envelope(byte[] ctx, byte[] key, NativeSize keyLen, byte[] buffer, NativeSize totalLen);
        int proed_decrypt_envelope(byte[] ctx, byte[] key, NativeSize keyLen, byte[] buffer, NativeSize totalLen);
    }

    // --- NATIVE INTERFACE: Windows Kernel32 (Für Ring-0 IOCTL) ---
    public interface Kernel32 extends Library {
        Kernel32 INSTANCE = Platform.isWindows() ? Native.load("kernel32", Kernel32.class) : null;

        Pointer CreateFileA(String lpFileName, int dwDesiredAccess, int dwShareMode, Pointer lpSecurityAttributes, int dwCreationDisposition, int dwFlagsAndAttributes, Pointer hTemplateFile);
        boolean DeviceIoControl(Pointer hDevice, int dwIoControlCode, byte[] lpInBuffer, int nInBufferSize, byte[] lpOutBuffer, int nOutBufferSize, IntByReference lpBytesReturned, Pointer lpOverlapped);
        boolean CloseHandle(Pointer hObject);
    }

    // --- KLASSEN-LOGIK ---
    private final byte[] key;
    private Pointer hDevice = Pointer.NULL;
    private boolean isKernelModeActive = false;

    /**
     * Initialisiert den ProED Client und prüft, ob der Ring-0 Kernel-Treiber verfügbar ist.
     */
    public ProED(byte[] key) {
        if (key == null || key.length != Config.KEY_SIZE) {
            throw new IllegalArgumentException("Key muss exakt 32 Bytes lang sein.");
        }
        this.key = key;

        // Versuche, den Windows-Kernel-Treiber zu mounten (nur auf Windows)
        if (Platform.isWindows() && Kernel32.INSTANCE != null) {
            hDevice = Kernel32.INSTANCE.CreateFileA("\\\\.\\ProKM", 
                    Config.GENERIC_READ | Config.GENERIC_WRITE, 
                    0, Pointer.NULL, Config.OPEN_EXISTING, 0, Pointer.NULL);
                    
            // Pointer.createConstant(-1) entspricht INVALID_HANDLE_VALUE
            if (hDevice != null && Pointer.nativeValue(hDevice) != -1 && Pointer.nativeValue(hDevice) != 0) {
                isKernelModeActive = true;
            }
        }
    }

    public boolean isKernelModeActive() {
        return isKernelModeActive;
    }

    public String getVersionInfo() {
        Memory major = new Memory(1);
        Memory minor = new Memory(1);
        Memory patch = new Memory(1);
        return IProED.INSTANCE.proed_get_version_info(major, minor, patch);
    }

    // =========================================================================
    // METHODE 1: KERNEL-MODE (Ring-0) - Raw High-Speed Verschlüsselung
    // =========================================================================
    public byte[] processKernel(byte[] payload, byte[] iv, boolean isDecrypt) {
        if (!isKernelModeActive) {
            throw new IllegalStateException("ProKM Kernel-Driver ist nicht geladen. Fallback auf Software-Envelope erforderlich.");
        }
        if (iv == null || iv.length != 16) {
            throw new IllegalArgumentException("IV muss exakt 16 Bytes lang sein.");
        }

        int mode = isDecrypt ? 1 : 0;
        int dataLen = payload.length;

        // Struct Layout: Key(32) + IV(16) + Mode(4) + DataLen(4) + Payload(N)
        int reqSize = 32 + 16 + 4 + 4 + payload.length;
        byte[] requestBuffer = new byte[reqSize];

        // Speicher zusammenbauen (Little Endian für die Integer-Werte)
        ByteBuffer bb = ByteBuffer.wrap(requestBuffer).order(ByteOrder.LITTLE_ENDIAN);
        bb.put(key);
        bb.put(iv);
        bb.putInt(mode);
        bb.putInt(dataLen);
        bb.put(payload);

        byte[] outBuffer = new byte[reqSize];
        IntByReference bytesReturned = new IntByReference();

        // IOCTL Call an den Windows Kernel
        boolean success = Kernel32.INSTANCE.DeviceIoControl(
                hDevice, Config.IOCTL_PROKM_PROED,
                requestBuffer, reqSize,
                outBuffer, reqSize,
                bytesReturned, Pointer.NULL);

        if (!success) {
            int err = Native.getLastError();
            throw new RuntimeException("Kernel DeviceIoControl fehlgeschlagen. Windows Error Code: " + err);
        }

        // Die verarbeitete Payload beginnt im outBuffer ab Byte 56
        byte[] result = new byte[payload.length];
        System.arraycopy(outBuffer, 56, result, 0, payload.length);

        return result;
    }

    // =========================================================================
    // METHODE 2: SOFTWARE-MODE (Ring-3) - Armored Envelope (inkl. MAC)
    // =========================================================================
    public byte[] encryptEnvelopeSoftware(byte[] payload) {
        if (payload == null) throw new IllegalArgumentException("Payload darf nicht null sein.");
        
        byte[] buffer = new byte[Config.HEADER_SIZE + payload.length];
        System.arraycopy(payload, 0, buffer, Config.HEADER_SIZE, payload.length);
        
        byte[] ctx = new byte[Config.CTX_SIZE];
        int res = IProED.INSTANCE.proed_encrypt_envelope(
                ctx, key, new NativeSize(key.length), buffer, new NativeSize(buffer.length));
        
        return (res == 1) ? buffer : null;
    }

    public byte[] decryptEnvelopeSoftware(byte[] packet) {
        if (packet == null || packet.length < Config.HEADER_SIZE) return null;
        
        byte[] buffer = Arrays.copyOf(packet, packet.length);
        byte[] ctx = new byte[Config.CTX_SIZE];
        
        int res = IProED.INSTANCE.proed_decrypt_envelope(
                ctx, key, new NativeSize(key.length), buffer, new NativeSize(buffer.length));
        
        if (res == 0) return null; // MAC Error (Manipulation erkannt!)
        
        byte[] payload = new byte[buffer.length - Config.HEADER_SIZE];
        System.arraycopy(buffer, Config.HEADER_SIZE, payload, 0, payload.length);
        
        return payload;
    }

    @Override
    public void close() {
        if (isKernelModeActive && hDevice != null) {
            Kernel32.INSTANCE.CloseHandle(hDevice);
            hDevice = Pointer.NULL;
            isKernelModeActive = false;
        }
    }
}