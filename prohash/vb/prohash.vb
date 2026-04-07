Imports System.Runtime.InteropServices
Imports System.Text

Namespace ProChat.Core.Hashing
    ''' <summary>
    ''' VB.NET Wrapper für den ProHash-256 Algorithmus ("The Shredder").
    ''' </summary>
    Public NotInheritable Class ProHash
        Implements IDisposable

        Private Const LibName As String = "prohash.dll"

        ''' <summary>
        ''' Mapping der nativen ProHash_Ctx Struktur (136 Bytes).
        ''' Pack:=8 stellt sicher, dass der uint64_t count korrekt ausgerichtet ist.
        ''' </summary>
        <StructLayout(LayoutKind.Sequential, Pack:=8)>
        Private Structure ProHashCtx
            <MarshalAs(UnmanagedType.ByValArray, SizeConst:=16)>
            Public belt As UInteger()   ' 512-Bit Interner Zustand
            Public count As ULong       ' Anzahl verarbeiteter Bytes
            <MarshalAs(UnmanagedType.ByValArray, SizeConst:=64)>
            Public buffer As Byte()     ' Eingabe-Puffer
            Public bufIdx As UInteger   ' Aktuelle Position
        End Structure

        ' --- Native API Imports ---
        <DllImport(LibName, CallingConvention:=CallingConvention.Cdecl)>
        Private Shared Sub prohash_init(ByRef ctx As ProHashCtx)
        End Sub

        <DllImport(LibName, CallingConvention:=CallingConvention.Cdecl)>
        Private Shared Sub prohash_update(ByRef ctx As ProHashCtx, ByVal data As Byte(), ByVal len As UIntPtr)
        End Sub

        <DllImport(LibName, CallingConvention:=CallingConvention.Cdecl)>
        Private Shared Sub prohash_final(ByRef ctx As ProHashCtx, ByVal digest As Byte())
        End Sub

        <DllImport(LibName, CallingConvention:=CallingConvention.Cdecl)>
        Private Shared Function prohash_get_version_info() As IntPtr
        End Function

        Private _ctx As ProHashCtx
        Private _finalized As Boolean = False
        Private _disposed As Boolean = False

        Public Sub New()
            _ctx = New ProHashCtx()
            ' Initialisierung der Arrays innerhalb der Struktur
            _ctx.belt = New UInteger(15) {}
            _ctx.buffer = New Byte(63) {}
            prohash_init(_ctx)
        End Sub

        ''' <summary>
        ''' Gibt die Versionsinformationen der nativen Library zurück.
        ''' </summary>
        Public Shared Function GetVersion() As String
            Dim ptr As IntPtr = prohash_get_version_info()
            Return Marshal.PtrToStringAnsi(ptr)
        End Function

        ''' <summary>
        ''' Verarbeitet einen Datenblock.
        ''' </summary>
        Public Sub Update(ByVal data As Byte())
            If data Is Nothing OrElse data.Length = 0 Then Return
            If _finalized Then Throw New InvalidOperationException("Hash already finalized.")

            prohash_update(_ctx, data, New UIntPtr(Convert.ToUInt32(data.Length)))
        End Sub

        ''' <summary>
        ''' Schließt die Berechnung ab und gibt den 32-Byte Digest zurück.
        ''' </summary>
        Public Function FinalizeHash() As Byte()
            If _finalized Then Throw New InvalidOperationException("Hash already finalized.")

            Dim digest(31) As Byte
            prohash_final(_ctx, digest)
            _finalized = True
            Return digest
        End Function

        ''' <summary>
        ''' Statische Hilfsfunktion für schnelles Hashing von Strings.
        ''' </summary>
        Public Shared Function ComputeHash(ByVal text As String) As String
            Using hasher As New ProHash()
                hasher.Update(Encoding.UTF8.GetBytes(text))
                Dim hashBytes = hasher.FinalizeHash()

                Dim sb As New StringBuilder()
                For Each b In hashBytes
                    sb.Append(b.ToString("x2")) ' Hexadezimale Formatierung
                Next
                Return sb.ToString().ToUpper()
            End Using
        End Function

        Public Sub Dispose() Implements IDisposable.Dispose
            If Not _disposed Then
                ' Zero-Trust: Wir verlassen uns auf das native prohash_final für den Wipe,
                ' setzen aber die verwalteten Arrays zusätzlich zurück.
                Array.Clear(_ctx.belt, 0, _ctx.belt.Length)
                Array.Clear(_ctx.buffer, 0, _ctx.buffer.Length)
                _disposed = True
            End If
            GC.SuppressFinalize(Me)
        End Sub
    End Class
End Namespace