Imports System.Runtime.InteropServices
Imports System.IO

Namespace ProED

    ' --- KONSTANTEN ---
    Public NotInheritable Class ProEDConstants
        Public Const HEADER_SIZE As Integer = 48 ' 16 Byte IV + 32 Byte HMAC
        Public Const KEY_SIZE As Integer = 32    ' 256-Bit Key
        Public Const CTX_SIZE As Integer = 120   ' Größe der ProED_Context Struct

        ' --- Windows IOCTL Konstanten ---
        Public Const GENERIC_READ As UInteger = &H80000000UI
        Public Const GENERIC_WRITE As UInteger = &H40000000UI
        Public Const OPEN_EXISTING As UInteger = 3
        Public Const FILE_DEVICE_UNKNOWN As UInteger = &H22
        Public Const METHOD_BUFFERED As UInteger = 0
        Public Const FILE_ANY_ACCESS As UInteger = 0

        ' IOCTL_PROKM_PROED = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
        Public Const IOCTL_PROKM_PROED As UInteger = (FILE_DEVICE_UNKNOWN << 16) Or (FILE_ANY_ACCESS << 14) Or (&H801 << 2) Or METHOD_BUFFERED
    End Class

    Public NotInheritable Class ProEDNative
        Private Const LibName As String = "proed"

        ' --- NATIVE DLL API (Software Fallback) ---
        <DllImport(LibName, CallingConvention:=CallingConvention.Cdecl)>
        Public Shared Function proed_get_version_info(ByRef out_major As Byte, ByRef out_minor As Byte, ByRef out_patch As Byte) As IntPtr
        End Function

        <DllImport(LibName, CallingConvention:=CallingConvention.Cdecl)>
        Public Shared Function proed_encrypt_envelope(ByVal ctx As Byte(), ByVal key As Byte(), ByVal key_len As UIntPtr, ByVal buffer As Byte(), ByVal total_len As UIntPtr) As Integer
        End Function

        <DllImport(LibName, CallingConvention:=CallingConvention.Cdecl)>
        Public Shared Function proed_decrypt_envelope(ByVal ctx As Byte(), ByVal key As Byte(), ByVal key_len As UIntPtr, ByVal buffer As Byte(), ByVal total_len As UIntPtr) As Integer
        End Function

        ' --- KERNEL32 API (Ring-0 IOCTL) ---
        <DllImport("kernel32.dll", CharSet:=CharSet.Auto, SetLastError:=True)>
        Public Shared Function CreateFile(ByVal lpFileName As String, ByVal dwDesiredAccess As UInteger, ByVal dwShareMode As UInteger, ByVal SecurityAttributes As IntPtr, ByVal dwCreationDisposition As UInteger, ByVal dwFlagsAndAttributes As UInteger, ByVal hTemplateFile As IntPtr) As IntPtr
        End Function

        <DllImport("kernel32.dll", SetLastError:=True)>
        Public Shared Function CloseHandle(ByVal hObject As IntPtr) As Boolean
        End Function

        <DllImport("kernel32.dll", ExactSpelling:=True, SetLastError:=True, CharSet:=CharSet.Auto)>
        Public Shared Function DeviceIoControl(ByVal hDevice As IntPtr, ByVal dwIoControlCode As UInteger, ByVal lpInBuffer As Byte(), ByVal nInBufferSize As UInteger, ByVal lpOutBuffer As Byte(), ByVal nOutBufferSize As UInteger, ByRef lpBytesReturned As UInteger, ByVal lpOverlapped As IntPtr) As Boolean
        End Function
    End Class

    ' --- HIGH-LEVEL HYBRID CLIENT ---
    Public Class ProEDClient
        Implements IDisposable

        Private ReadOnly _key As Byte()
        Private _hDevice As IntPtr = IntPtr.Zero
        Private _isDisposed As Boolean = False

        ' Zeigt an, ob Ring-0 Beschleunigung verfügbar ist
        Public ReadOnly Property IsKernelModeActive As Boolean
            Get
                Return _hDevice <> IntPtr.Zero AndAlso _hDevice <> New IntPtr(-1)
            End Get
        End Property

        Public Sub New(ByVal key As Byte())
            If key Is Nothing OrElse key.Length <> ProEDConstants.KEY_SIZE Then
                Throw New ArgumentException("Key muss exakt 32 Bytes lang sein.")
            End If
            _key = key

            ' Versuche, den Windows-Kernel-Treiber zu mounten
            _hDevice = ProEDNative.CreateFile("\\.\ProKM",
                ProEDConstants.GENERIC_READ Or ProEDConstants.GENERIC_WRITE,
                0, IntPtr.Zero, ProEDConstants.OPEN_EXISTING, 0, IntPtr.Zero)
        End Sub

        Public Function GetVersion(ByRef major As Byte, ByRef minor As Byte, ByRef patch As Byte) As String
            Dim ptr As IntPtr = ProEDNative.proed_get_version_info(major, minor, patch)
            Return Marshal.PtrToStringAnsi(ptr)
        End Function

        ' =========================================================================
        ' METHODE 1: KERNEL-MODE (Ring-0) - Raw High-Speed Verschlüsselung
        ' =========================================================================
        Public Function ProcessKernel(ByVal payload As Byte(), ByVal iv As Byte(), ByVal isDecrypt As Boolean) As Byte()
            If Not IsKernelModeActive Then
                Throw New InvalidOperationException("ProKM Kernel-Driver ist nicht geladen. Fallback auf Software-Envelope erforderlich.")
            End If
            If iv Is Nothing OrElse iv.Length <> 16 Then
                Throw New ArgumentException("IV muss exakt 16 Bytes lang sein.")
            End If

            Dim mode As UInteger = If(isDecrypt, 1UI, 0UI)
            Dim dataLen As UInteger = CUInt(payload.Length)

            ' Struct Layout: Key(32) + IV(16) + Mode(4) + DataLen(4) + Payload(N)
            Dim reqSize As Integer = 32 + 16 + 4 + 4 + payload.Length
            Dim requestBuffer(reqSize - 1) As Byte

            ' Struct zusammenbauen
            Buffer.BlockCopy(_key, 0, requestBuffer, 0, 32)
            Buffer.BlockCopy(iv, 0, requestBuffer, 32, 16)
            BitConverter.GetBytes(mode).CopyTo(requestBuffer, 48)
            BitConverter.GetBytes(dataLen).CopyTo(requestBuffer, 52)
            Buffer.BlockCopy(payload, 0, requestBuffer, 56, payload.Length)

            Dim outBuffer(reqSize - 1) As Byte
            Dim bytesReturned As UInteger = 0

            ' IOCTL Call an den Windows Kernel
            Dim success As Boolean = ProEDNative.DeviceIoControl(
                _hDevice,
                ProEDConstants.IOCTL_PROKM_PROED,
                requestBuffer, CUInt(reqSize),
                outBuffer, CUInt(reqSize),
                bytesReturned, IntPtr.Zero)

            If Not success Then
                Dim errCode As Integer = Marshal.GetLastWin32Error()
                Throw New Exception("Kernel DeviceIoControl fehlgeschlagen. Windows Error Code: " & errCode)
            End If

            ' Die verarbeitete Payload beginnt im outBuffer ab Byte 56
            Dim result(payload.Length - 1) As Byte
            Buffer.BlockCopy(outBuffer, 56, result, 0, payload.Length)

            Return result
        End Function

        ' =========================================================================
        ' METHODE 2: SOFTWARE-MODE (Ring-3) - Armored Envelope (inkl. MAC)
        ' =========================================================================
        Public Function EncryptEnvelopeSoftware(ByVal payload As Byte()) As Byte()
            If payload Is Nothing Then Throw New ArgumentNullException(NameOf(payload))

            Dim totalLen As Integer = ProEDConstants.HEADER_SIZE + payload.Length
            Dim packet(totalLen - 1) As Byte

            ' Payload hinter den Header kopieren
            Array.Copy(payload, 0, packet, ProEDConstants.HEADER_SIZE, payload.Length)

            Dim ctx(ProEDConstants.CTX_SIZE - 1) As Byte
            Dim res As Integer = ProEDNative.proed_encrypt_envelope(ctx, _key, New UIntPtr(CUInt(_key.Length)), packet, New UIntPtr(CUInt(packet.Length)))

            If res = 0 Then Return Nothing
            Return packet
        End Function

        Public Function DecryptEnvelopeSoftware(ByVal packet As Byte()) As Byte()
            If packet Is Nothing OrElse packet.Length < ProEDConstants.HEADER_SIZE Then Return Nothing

            Dim buffer(packet.Length - 1) As Byte
            Array.Copy(packet, buffer, packet.Length)

            Dim ctx(ProEDConstants.CTX_SIZE - 1) As Byte
            Dim res As Integer = ProEDNative.proed_decrypt_envelope(ctx, _key, New UIntPtr(CUInt(_key.Length)), buffer, New UIntPtr(CUInt(buffer.Length)))

            If res = 0 Then Return Nothing ' HMAC / Integrity Check fehlgeschlagen

            ' Payload extrahieren
            Dim payloadLen As Integer = buffer.Length - ProEDConstants.HEADER_SIZE
            Dim payload(payloadLen - 1) As Byte
            Array.Copy(buffer, ProEDConstants.HEADER_SIZE, payload, 0, payloadLen)

            Return payload
        End Function

        ' =========================================================================
        ' DISPOSABLE PATTERN (Wichtig für Kernel-Handles)
        ' =========================================================================
        Protected Overridable Sub Dispose(disposing As Boolean)
            If Not _isDisposed Then
                If _hDevice <> IntPtr.Zero AndAlso _hDevice <> New IntPtr(-1) Then
                    ProEDNative.CloseHandle(_hDevice)
                    _hDevice = IntPtr.Zero
                End If
                _isDisposed = True
            End If
        End Sub

        Public Sub Dispose() Implements IDisposable.Dispose
            Dispose(True)
            GC.SuppressFinalize(Me)
        End Sub

        Protected Overrides Sub Finalize()
            Dispose(False)
        End Sub
    End Class

End Namespace