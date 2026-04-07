Imports System.Runtime.InteropServices
Imports System.Text

Namespace ProChat.Core.Crypto
    ''' <summary>
    ''' Status-Codes der ProKey Engine.
    ''' </summary>
    Public Enum ProKeyStatus As Integer
        Success = 0
        ErrorParam = -1
        ErrorHardware = -2
        ErrorStream = -3
    End Enum

    ''' <summary>
    ''' Vordefinierte Schlüssellängen in Bit.
    ''' </summary>
    Public Enum ProKeyBits As Integer
        Bit128 = 128
        Bit256 = 256
        Bit512 = 512
        Bit1024 = 1024
    End Enum

    ''' <summary>
    ''' VB.NET Wrapper für die native ProKey Engine (Entropie / RNG).
    ''' </summary>
    Public NotInheritable Class ProKey
        Private Const LibName As String = "prokey.dll"

        ' --- Native API Imports ---

        <DllImport(LibName, CallingConvention:=CallingConvention.Cdecl)>
        Private Shared Function ProKey_GetVersion() As IntPtr
        End Function

        <DllImport(LibName, CallingConvention:=CallingConvention.Cdecl)>
        Private Shared Sub ProKey_Generate(ByVal buffer As Byte(), ByVal length As UIntPtr)
        End Sub

        <DllImport(LibName, CallingConvention:=CallingConvention.Cdecl)>
        Private Shared Sub ProKey_Fill256Bit(ByVal buffer As Byte())
        End Sub

        ' --- High-Level Methoden ---

        ''' <summary>
        ''' Gibt die Versions- und Entwicklerinformationen der Library zurück.
        ''' </summary>
        Public Shared Function GetVersion() As String
            Dim ptr As IntPtr = ProKey_GetVersion()
            Return Marshal.PtrToStringAnsi(ptr)
        End Function

        ''' <summary>
        ''' Generiert eine angegebene Menge an kryptografisch starkem Zufall in Bytes.
        ''' </summary>
        ''' <param name="lengthInBytes">Die gewünschte Länge in Bytes.</param>
        ''' <returns>Ein Byte-Array mit Entropie.</returns>
        Public Shared Function GenerateBytes(ByVal lengthInBytes As Integer) As Byte()
            If lengthInBytes <= 0 Then
                Throw New ArgumentOutOfRangeException(NameOf(lengthInBytes), "Length must be greater than zero.")
            End If

            Dim buffer(lengthInBytes - 1) As Byte
            ProKey_Generate(buffer, New UIntPtr(CType(lengthInBytes, UInteger)))

            Return buffer
        End Function

        ''' <summary>
        ''' Generiert kryptografisch starken Zufall basierend auf den vordefinierten Bit-Längen.
        ''' </summary>
        ''' <param name="bits">Die gewünschte Schlüssellänge (z.B. Bit256).</param>
        ''' <returns>Ein Byte-Array mit Entropie.</returns>
        Public Shared Function GenerateKey(ByVal bits As ProKeyBits) As Byte()
            Dim lengthInBytes As Integer = CInt(bits) \ 8
            Return GenerateBytes(lengthInBytes)
        End Function

        ''' <summary>
        ''' Convenience-Wrapper für genau 256 Bit (32 Byte), nutzt die optimierte C-Funktion.
        ''' </summary>
        ''' <returns>Ein 32-Byte Array mit Entropie.</returns>
        Public Shared Function Generate256BitKey() As Byte()
            Dim buffer(31) As Byte
            ProKey_Fill256Bit(buffer)
            Return buffer
        End Function

        ''' <summary>
        ''' Hilfsmethode zur Hex-String-Konvertierung.
        ''' </summary>
        Public Shared Function BytesToHex(ByVal bytes As Byte()) As String
            Dim sb As New StringBuilder(bytes.Length * 2)
            For Each b As Byte In bytes
                sb.Append(b.ToString("X2"))
            Next
            Return sb.ToString()
        End Function

    End Class
End Namespace