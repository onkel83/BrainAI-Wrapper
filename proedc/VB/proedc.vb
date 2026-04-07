Imports System.Runtime.InteropServices

Namespace ProEDC
    ''' <summary>
    ''' Entspricht ProED_Mode (aus ProED_Interface.h)
    ''' </summary>
    Public Enum ProEDMode As UInteger
        ENCRYPT = 0
        DECRYPT = 1
    End Enum

    ''' <summary>
    ''' Fehlercodes der ProEDC (aus ProEDC.h)
    ''' </summary>
    Public Enum ProEDCStatus As Integer
        SUCCESS = 0
        ERR_PARAM = -1
        ERR_FILE_IO = -2
        ERR_CRYPTO = -3
        ERR_HASH = -4
        ERR_KEYGEN = -5
        ERR_MEMORY = -6
        ERR_LIMIT_REACHED = -7
    End Enum

    ''' <summary>
    ''' Entspricht ProED_Context (72 Bytes, 4 Byte Alignment)
    ''' </summary>
    <StructLayout(LayoutKind.Sequential, Pack:=4)>
    Public Structure ProEDContext
        <MarshalAs(UnmanagedType.ByValArray, SizeConst:=8)>
        Public state As UInteger()
        <MarshalAs(UnmanagedType.ByValArray, SizeConst:=32)>
        Public stream As Byte()
        Public idx As UInteger
        Public mode As ProEDMode
    End Structure

    ''' <summary>
    ''' Entspricht ProHash_Ctx (aus ProHash.h)
    ''' </summary>
    <StructLayout(LayoutKind.Sequential, Pack:=8)>
    Public Structure ProHashCtx
        <MarshalAs(UnmanagedType.ByValArray, SizeConst:=16)>
        Public belt As UInteger()
        Public count As ULong
        <MarshalAs(UnmanagedType.ByValArray, SizeConst:=64)>
        Public buffer As Byte()
        Public bufIdx As UInteger
    End Structure

    Public NotInheritable Class ProNative
        ' Bibliotheksnamen
        Private Const LibProED As String = "proed"
        Private Const LibProHash As String = "prohash"
        Private Const LibProKey As String = "prokey"
        Private Const LibProEDC As String = "proedc"

        ' --- ProED CORE (Verschlüsselung) ---
        <DllImport(LibProED, CallingConvention:=CallingConvention.Cdecl, EntryPoint:="proed_init")>
        Public Shared Sub proed_init(ByRef ctx As ProEDContext, ByVal key As Byte(), ByVal keyLen As UIntPtr, ByVal iv As Byte(), ByVal ivLen As UIntPtr, ByVal mode As ProEDMode)
        End Sub

        <DllImport(LibProED, CallingConvention:=CallingConvention.Cdecl, EntryPoint:="proed_process")>
        Public Shared Sub proed_process(ByRef ctx As ProEDContext, ByVal data As Byte(), ByVal len As UIntPtr)
        End Sub


        ' --- ProHash (Hashing) ---
        <DllImport(LibProHash, CallingConvention:=CallingConvention.Cdecl)>
        Public Shared Sub prohash_init(ByRef ctx As ProHashCtx)
        End Sub

        <DllImport(LibProHash, CallingConvention:=CallingConvention.Cdecl)>
        Public Shared Sub prohash_update(ByRef ctx As ProHashCtx, ByVal data As Byte(), ByVal len As UIntPtr)
        End Sub

        <DllImport(LibProHash, CallingConvention:=CallingConvention.Cdecl)>
        Public Shared Sub prohash_final(ByRef ctx As ProHashCtx, ByVal digest As Byte())
        End Sub


        ' --- ProKey (Schlüsselgenerierung) ---
        <DllImport(LibProKey, CallingConvention:=CallingConvention.Cdecl)>
        Public Shared Sub ProKey_Generate(ByVal buffer As Byte(), ByVal length As UIntPtr)
        End Sub


        ' --- ProEDC (High-Level API) ---
        <DllImport(LibProEDC, CallingConvention:=CallingConvention.Cdecl)>
        Public Shared Sub ProEDC_Init()
        End Sub

        <DllImport(LibProEDC, CallingConvention:=CallingConvention.Cdecl, CharSet:=CharSet.Ansi)>
        Public Shared Function ProEDC_EncryptFile(ByVal input As String, ByVal output As String, ByVal keyfile As String) As ProEDCStatus
        End Function

        <DllImport(LibProEDC, CallingConvention:=CallingConvention.Cdecl, CharSet:=CharSet.Ansi)>
        Public Shared Function ProEDC_DecryptFile(ByVal input As String, ByVal output As String, ByVal keyfile As String) As ProEDCStatus
        End Function

        <DllImport(LibProEDC, CallingConvention:=CallingConvention.Cdecl)>
        Public Shared Function ProEDC_GetVersion() As IntPtr
        End Function

        ' Hilfsfunktion für die Version (da C-Strings gemarshallt werden müssen)
        Public Shared Function GetVersionString() As String
            Dim ptr As IntPtr = ProEDC_GetVersion()
            Return Marshal.PtrToStringAnsi(ptr)
        End Function

    End Class
End Namespace
