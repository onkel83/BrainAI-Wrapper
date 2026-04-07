Imports System.Runtime.InteropServices

Namespace ProChat
    ''' <summary>
    ''' Fehlercodes der ProChat Engine (aus prochat_core.h)
    ''' </summary>
    Public Enum ProChatStatus As Integer
        PC_OK = 0
        PC_ERR_PARAM = -1    ' Ungültige Parameter
        PC_ERR_AUTH = -2     ' Authentifizierungsfehler (MAC ungültig)
        PC_ERR_REPLAY = -3    ' Replay-Attacke erkannt
        PC_ERR_DESYNC = -4    ' Ratchet-Desynchronisation
    End Enum

    Public NotInheritable Class ProChatNative
        ' Name der Library (entspricht PROJECT in den Makefiles)
        Private Const LibProChat As String = "prochat"

        ' --- KONSTANTEN ---
        Public Const PC_PKT_SIZE As Integer = 1024     ' Feste Paketgröße
        Public Const PC_MAX_PAYLOAD As Integer = 988   ' Maximale Nutzlast

        ' --- API DEFINITIONEN ---

        <DllImport(LibProChat, CallingConvention:=CallingConvention.Cdecl)>
        Private Shared Function pc_get_version_info(ByRef out_major As Byte, ByRef out_minor As Byte, ByRef out_patch As Byte) As IntPtr
        End Function

        <DllImport(LibProChat, CallingConvention:=CallingConvention.Cdecl)>
        Public Shared Sub pc_init(ByVal uid As UInteger, ByVal seed As Byte())
        End Sub

        <DllImport(LibProChat, CallingConvention:=CallingConvention.Cdecl)>
        Public Shared Function pc_add_peer(ByVal uid As UInteger, ByVal k As Byte()) As Integer
        End Function

        <DllImport(LibProChat, CallingConvention:=CallingConvention.Cdecl)>
        Public Shared Function pc_encrypt(ByVal target As UInteger, ByVal type As Byte, ByVal msg As Byte(), ByVal len As UIntPtr, ByVal outPkt As Byte()) As Integer
        End Function

        <DllImport(LibProChat, CallingConvention:=CallingConvention.Cdecl)>
        Public Shared Function pc_decrypt(ByVal pkt As Byte(), ByRef out_sender As UInteger, ByVal out_buf As Byte()) As Integer
        End Function

        ' --- HELPER FÜR VERSION ---
        Public Shared Function GetVersion(ByRef major As Byte, ByRef minor As Byte, ByRef patch As Byte) As String
            Dim ptr As IntPtr = pc_get_version_info(major, minor, patch)
            Return Marshal.PtrToStringAnsi(ptr)
        End Function
    End Class

    ''' <summary>
    ''' High-Level Client Klasse für die einfache Nutzung in VB.NET
    ''' </summary>
    Public Class ProChatClient
        Public Property MyUID As UInteger

        Public Sub New(ByVal uid As UInteger, ByVal seed As Byte())
            If seed Is Nothing OrElse seed.Length <> 32 Then
                Throw New ArgumentException("Seed muss exakt 32 Bytes lang sein.")
            End If
            MyUID = uid
            ProChatNative.pc_init(uid, seed)
        End Sub

        Public Function AddPeer(ByVal uid As UInteger, ByVal key As Byte()) As Boolean
            If key Is Nothing OrElse key.Length <> 32 Then
                Throw New ArgumentException("Key muss exakt 32 Bytes lang sein.")
            End If
            Return ProChatNative.pc_add_peer(uid, key) = ProChatStatus.PC_OK
        End Function

        Public Function EncryptMessage(ByVal targetUID As UInteger, ByVal type As Byte, ByVal message As Byte()) As Byte()
            Dim packet(ProChatNative.PC_PKT_SIZE - 1) As Byte
            Dim res As Integer = ProChatNative.pc_encrypt(targetUID, type, message, New UIntPtr(Convert.ToUInt32(message.Length)), packet)
            
            If res <> ProChatStatus.PC_OK Then Return Nothing
            Return packet
        End Function

        Public Function DecryptPacket(ByVal packet As Byte(), ByRef senderUID As UInteger) As Byte()
            If packet.Length <> ProChatNative.PC_PKT_SIZE Then Return Nothing

            Dim outputBuffer(ProChatNative.PC_MAX_PAYLOAD - 1) As Byte
            Dim bytesDecrypted As Integer = ProChatNative.pc_decrypt(packet, senderUID, outputBuffer)

            If bytesDecrypted < 0 Then Return Nothing

            ' Buffer auf die tatsächliche Größe kürzen
            Dim finalMsg(bytesDecrypted - 1) As Byte
            Array.Copy(outputBuffer, finalMsg, bytesDecrypted)
            Return finalMsg
        End Function
    End Class
End Namespace
