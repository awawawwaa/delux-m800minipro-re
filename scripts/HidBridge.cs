using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

// P/Invoke direto para hid.dll / setupapi.dll do Windows.
// Usado para contornar o bloqueio do WebHID (que zera os reports de qualquer
// colecao HID com usage page "Generic Desktop / Mouse"), acessando o mesmo
// dispositivo por fora do navegador.
public static class HidBridge
{
    const uint GENERIC_READ = 0x80000000;
    const uint GENERIC_WRITE = 0x40000000;
    const uint FILE_SHARE_READ = 0x1;
    const uint FILE_SHARE_WRITE = 0x2;
    const uint OPEN_EXISTING = 3;
    const int DIGCF_PRESENT = 0x2;
    const int DIGCF_DEVICEINTERFACE = 0x10;

    [DllImport("hid.dll")] static extern void HidD_GetHidGuid(out Guid gu);
    [DllImport("hid.dll")] static extern bool HidD_GetAttributes(IntPtr hidHandle, ref HIDD_ATTRIBUTES attributes);
    [DllImport("hid.dll")] static extern bool HidD_GetPreparsedData(IntPtr hidHandle, out IntPtr preparsedData);
    [DllImport("hid.dll")] static extern bool HidD_FreePreparsedData(IntPtr preparsedData);
    [DllImport("hid.dll")] static extern bool HidD_SetFeature(IntPtr hidHandle, byte[] reportBuffer, int reportBufferLength);
    [DllImport("hid.dll")] static extern bool HidD_GetFeature(IntPtr hidHandle, byte[] reportBuffer, int reportBufferLength);
    [DllImport("hid.dll")] static extern bool HidD_GetInputReport(IntPtr hidHandle, byte[] reportBuffer, int reportBufferLength);
    [DllImport("hid.dll")] static extern int HidP_GetCaps(IntPtr preparsedData, ref HIDP_CAPS caps);
    [DllImport("hid.dll", CharSet = CharSet.Unicode)] static extern bool HidD_GetProductString(IntPtr hidHandle, StringBuilder buffer, int bufferLength);

    [DllImport("setupapi.dll", SetLastError = true)]
    static extern IntPtr SetupDiGetClassDevs(ref Guid classGuid, IntPtr enumerator, IntPtr hwndParent, int flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    static extern bool SetupDiEnumDeviceInterfaces(IntPtr deviceInfoSet, IntPtr deviceInfoData, ref Guid interfaceClassGuid, uint memberIndex, ref SP_DEVICE_INTERFACE_DATA deviceInterfaceData);

    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool SetupDiGetDeviceInterfaceDetail(IntPtr deviceInfoSet, ref SP_DEVICE_INTERFACE_DATA deviceInterfaceData, IntPtr deviceInterfaceDetailData, int deviceInterfaceDetailDataSize, ref int requiredSize, IntPtr deviceInfoData);

    [DllImport("setupapi.dll", SetLastError = true)]
    static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern IntPtr CreateFile(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadFile(IntPtr handle, byte[] buffer, uint numberOfBytesToRead, out uint numberOfBytesRead, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadFile(IntPtr handle, byte[] buffer, uint numberOfBytesToRead, IntPtr numberOfBytesReadUnused, ref OVERLAPPED overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetOverlappedResult(IntPtr hFile, ref OVERLAPPED lpOverlapped, out uint lpNumberOfBytesTransferred, bool bWait);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CancelIo(IntPtr hFile);

    const uint FILE_FLAG_OVERLAPPED = 0x40000000;
    const uint WAIT_OBJECT_0 = 0;
    const uint WAIT_TIMEOUT = 258;

    [StructLayout(LayoutKind.Sequential)]
    struct OVERLAPPED
    {
        public IntPtr Internal;
        public IntPtr InternalHigh;
        public uint Offset;
        public uint OffsetHigh;
        public IntPtr hEvent;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct HIDD_ATTRIBUTES { public int Size; public ushort VendorID; public ushort ProductID; public ushort VersionNumber; }

    [StructLayout(LayoutKind.Sequential)]
    struct HIDP_CAPS
    {
        public ushort Usage;
        public ushort UsagePage;
        public ushort InputReportByteLength;
        public ushort OutputReportByteLength;
        public ushort FeatureReportByteLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 17)] public ushort[] Reserved;
        public ushort NumberLinkCollectionNodes;
        public ushort NumberInputButtonCaps;
        public ushort NumberInputValueCaps;
        public ushort NumberInputDataIndices;
        public ushort NumberOutputButtonCaps;
        public ushort NumberOutputValueCaps;
        public ushort NumberOutputDataIndices;
        public ushort NumberFeatureButtonCaps;
        public ushort NumberFeatureValueCaps;
        public ushort NumberFeatureDataIndices;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SP_DEVICE_INTERFACE_DATA
    {
        public int cbSize;
        public Guid InterfaceClassGuid;
        public int Flags;
        public IntPtr Reserved;
    }

    public class DeviceEntry
    {
        public string Path;
        public ushort VendorId;
        public ushort ProductId;
        public ushort UsagePage;
        public ushort Usage;
        public ushort FeatureReportByteLength;
        public string ProductName;
    }

    static List<string> EnumeratePaths()
    {
        var paths = new List<string>();
        Guid hidGuid;
        HidD_GetHidGuid(out hidGuid);

        IntPtr deviceInfoSet = SetupDiGetClassDevs(ref hidGuid, IntPtr.Zero, IntPtr.Zero, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
        if (deviceInfoSet == IntPtr.Zero || deviceInfoSet.ToInt64() == -1) return paths;

        try
        {
            uint index = 0;
            while (true)
            {
                var ifaceData = new SP_DEVICE_INTERFACE_DATA();
                ifaceData.cbSize = Marshal.SizeOf(typeof(SP_DEVICE_INTERFACE_DATA));
                bool ok = SetupDiEnumDeviceInterfaces(deviceInfoSet, IntPtr.Zero, ref hidGuid, index, ref ifaceData);
                if (!ok) break;

                int requiredSize = 0;
                SetupDiGetDeviceInterfaceDetail(deviceInfoSet, ref ifaceData, IntPtr.Zero, 0, ref requiredSize, IntPtr.Zero);

                IntPtr detailBuffer = Marshal.AllocHGlobal(requiredSize);
                try
                {
                    Marshal.WriteInt32(detailBuffer, IntPtr.Size == 8 ? 8 : 6);
                    int outSize = requiredSize;
                    if (SetupDiGetDeviceInterfaceDetail(deviceInfoSet, ref ifaceData, detailBuffer, outSize, ref outSize, IntPtr.Zero))
                    {
                        IntPtr pathPtr = new IntPtr(detailBuffer.ToInt64() + 4);
                        string path = Marshal.PtrToStringAuto(pathPtr);
                        paths.Add(path);
                    }
                }
                finally { Marshal.FreeHGlobal(detailBuffer); }

                index++;
            }
        }
        finally { SetupDiDestroyDeviceInfoList(deviceInfoSet); }

        return paths;
    }

    public static List<DeviceEntry> EnumerateDevices(ushort vid, ushort pid)
    {
        var result = new List<DeviceEntry>();
        foreach (var path in EnumeratePaths())
        {
            IntPtr handle = CreateFile(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (handle == IntPtr.Zero || handle.ToInt64() == -1) continue;

            try
            {
                var attrs = new HIDD_ATTRIBUTES();
                attrs.Size = Marshal.SizeOf(typeof(HIDD_ATTRIBUTES));
                if (!HidD_GetAttributes(handle, ref attrs)) continue;
                if (attrs.VendorID != vid || attrs.ProductID != pid) continue;

                IntPtr preparsed;
                ushort usagePage = 0, usage = 0, featLen = 0;
                if (HidD_GetPreparsedData(handle, out preparsed))
                {
                    var caps = new HIDP_CAPS();
                    HidP_GetCaps(preparsed, ref caps);
                    usagePage = caps.UsagePage;
                    usage = caps.Usage;
                    featLen = caps.FeatureReportByteLength;
                    HidD_FreePreparsedData(preparsed);
                }

                var sb = new StringBuilder(128);
                string productName = "";
                try { if (HidD_GetProductString(handle, sb, sb.Capacity * 2)) productName = sb.ToString(); } catch { }

                result.Add(new DeviceEntry
                {
                    Path = path,
                    VendorId = attrs.VendorID,
                    ProductId = attrs.ProductID,
                    UsagePage = usagePage,
                    Usage = usage,
                    FeatureReportByteLength = featLen,
                    ProductName = productName
                });
            }
            finally { CloseHandle(handle); }
        }
        return result;
    }

    public static string SetFeatureReport(string path, byte[] report)
    {
        IntPtr handle = CreateFile(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (handle == IntPtr.Zero || handle.ToInt64() == -1)
            return "ERRO: CreateFile falhou (" + Marshal.GetLastWin32Error() + ")";

        try
        {
            bool ok = HidD_SetFeature(handle, report, report.Length);
            if (!ok) return "ERRO: HidD_SetFeature falhou (" + Marshal.GetLastWin32Error() + ")";
            return "OK";
        }
        finally { CloseHandle(handle); }
    }

    public static byte[] GetFeatureReportBytes(string path, byte reportId, int length)
    {
        IntPtr handle = CreateFile(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (handle == IntPtr.Zero || handle.ToInt64() == -1) return null;

        try
        {
            byte[] buffer = new byte[length];
            buffer[0] = reportId;
            bool ok = HidD_GetFeature(handle, buffer, buffer.Length);
            return ok ? buffer : null;
        }
        finally { CloseHandle(handle); }
    }

    public static string ReadFileBlocking(string path, int bufferSize)
    {
        IntPtr handle = CreateFile(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (handle == IntPtr.Zero || handle.ToInt64() == -1)
            return "ERRO: CreateFile falhou (" + Marshal.GetLastWin32Error() + ")";

        try
        {
            byte[] buffer = new byte[bufferSize];
            uint read;
            bool ok = ReadFile(handle, buffer, (uint)bufferSize, out read, IntPtr.Zero);
            if (!ok) return "ERRO: ReadFile falhou (" + Marshal.GetLastWin32Error() + ")";
            var sb = new StringBuilder();
            for (int i = 0; i < read; i++) sb.AppendFormat("{0:x2} ", buffer[i]);
            return "OK bytes=" + read + " data=" + sb.ToString().Trim();
        }
        finally { CloseHandle(handle); }
    }

    // Le um input report com timeout (via I/O overlapped), pra nao travar o
    // bridge indefinidamente se o dispositivo nao mandar dados a tempo (o
    // heartbeat deste mouse chega a cada ~2-4s quando ocioso).
    public static byte[] ReadFileWithTimeout(string path, int bufferSize, int timeoutMs)
    {
        IntPtr handle = CreateFile(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, IntPtr.Zero);
        if (handle == IntPtr.Zero || handle.ToInt64() == -1) return null;

        IntPtr evt = CreateEvent(IntPtr.Zero, true, false, null);
        try
        {
            var overlapped = new OVERLAPPED();
            overlapped.hEvent = evt;

            byte[] buffer = new byte[bufferSize];
            bool immediate = ReadFile(handle, buffer, (uint)bufferSize, IntPtr.Zero, ref overlapped);

            uint bytesTransferred;
            if (!immediate)
            {
                int err = Marshal.GetLastWin32Error();
                const int ERROR_IO_PENDING = 997;
                if (err != ERROR_IO_PENDING) return null;

                uint waitResult = WaitForSingleObject(evt, (uint)timeoutMs);
                if (waitResult == WAIT_TIMEOUT)
                {
                    CancelIo(handle);
                    return null;
                }
            }

            if (!GetOverlappedResult(handle, ref overlapped, out bytesTransferred, true)) return null;
            if (bytesTransferred == 0) return null;

            byte[] result = new byte[bytesTransferred];
            Array.Copy(buffer, result, (int)bytesTransferred);
            return result;
        }
        finally
        {
            if (evt != IntPtr.Zero) CloseHandle(evt);
            CloseHandle(handle);
        }
    }

    public static string GetInputReportBytes(string path, byte reportId, int length)
    {
        IntPtr handle = CreateFile(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (handle == IntPtr.Zero || handle.ToInt64() == -1)
            return "ERRO: CreateFile falhou (" + Marshal.GetLastWin32Error() + ")";

        try
        {
            byte[] buffer = new byte[length];
            buffer[0] = reportId;
            bool ok = HidD_GetInputReport(handle, buffer, buffer.Length);
            if (!ok) return "ERRO: HidD_GetInputReport falhou (" + Marshal.GetLastWin32Error() + ")";
            var sb = new StringBuilder();
            foreach (byte b in buffer) sb.AppendFormat("{0:x2} ", b);
            return "OK " + sb.ToString().Trim();
        }
        finally { CloseHandle(handle); }
    }
}
