using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;

namespace Launcher
{
    public static class FastInt32Scanner
    {
        #region PInvoke

        [Flags]
        private enum ProcessAccessFlags : uint
        {
            VMRead = 0x0010,
            VMOperation = 0x0008,
            QueryInformation = 0x0400,
            ReadFlags = VMRead | VMOperation | QueryInformation
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION64
        {
            public ulong BaseAddress;
            public ulong AllocationBase;
            public uint AllocationProtect;
            public ulong RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        private const uint MEM_COMMIT = 0x1000;
        private const uint PAGE_NOACCESS = 0x01;
        private const uint PAGE_GUARD = 0x100;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION64 lpBuffer, IntPtr dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        #endregion

        public static List<IntPtr> ScanInt32Value(int processId, int targetValue,
            ulong startAddress = 0,
            ulong endAddress = 0x00007FFFFFFF0000,
            int blockSize = 16 * 1024 * 1024) // 16MB
        {
            var handle = OpenProcess(ProcessAccessFlags.ReadFlags, false, processId);
            if (handle == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess 失败");

            var results = new List<IntPtr>();
            byte[] buffer = new byte[blockSize];

            try
            {
                ulong addr = startAddress;
                while (addr < endAddress)
                {
                    if (VirtualQueryEx(handle, new IntPtr((long)addr),
                        out var info,
                        new IntPtr(Marshal.SizeOf<MEMORY_BASIC_INFORMATION64>())) == IntPtr.Zero)
                    {
                        addr += 0x1000;
                        continue;
                    }

                    ulong regionBase = info.BaseAddress;
                    ulong regionSize = info.RegionSize;
                    ulong next = regionBase + regionSize;

                    bool readable = info.State == MEM_COMMIT &&
                                    (info.Protect != PAGE_NOACCESS) &&
                                    (info.Protect & PAGE_GUARD) == 0;

                    if (!readable || regionSize == 0)
                    {
                        addr = next;
                        continue;
                    }

                    ulong scanStart = Math.Max(regionBase, startAddress);
                    ulong scanEnd = Math.Min(regionBase + regionSize, endAddress);

                    ulong p = scanStart;
                    while (p < scanEnd)
                    {
                        ulong remain = scanEnd - p;
                        int toRead = (int)Math.Min((ulong)blockSize, remain);

                        if (buffer.Length != toRead)
                            buffer = new byte[toRead]; // 只在最后一块缩小，避免多次分配，可改进为 ArrayPool

                        if (!ReadProcessMemory(handle, new IntPtr((long)p), buffer, new IntPtr(toRead), out var read))
                        {
                            p += 0x1000; // 跳过一个页大小
                            continue;
                        }

                        int got = read.ToInt32();
                        if (got <= 0)
                        {
                            p += (ulong)toRead;
                            continue;
                        }

                        int limit = got - 4;
                        for (int i = 0; i <= limit; i++)
                        {
                            // 读取 4 字节（小端）
                            int val = BitConverter.ToInt32(buffer, i);
                            if (val == targetValue)
                            {
                                long absolute = (long)p + i;
                                results.Add(new IntPtr(absolute));
                            }
                        }

                        p += (ulong)got;
                    }

                    addr = next;
                }
            }
            finally
            {
                CloseHandle(handle);
            }

            return results;
        }

        /// <summary>
        /// 输入十六进制字符串转 int。例如 "63090217" -> 0x63090217
        /// </summary>
        public static int ParseHexInt32(string hex)
        {
            if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                hex = hex.Substring(2);

            if (hex.Length > 8)
                throw new ArgumentException("超过 32 位整数长度");

            return int.Parse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }

    }
}