using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;

namespace Launcher
{
    public static class MemoryHexScanner
    {
        #region PInvoke

        [Flags]
        private enum ProcessAccessFlags : uint
        {
            VMRead = 0x0010,
            VMOperation = 0x0008,
            QueryInformation = 0x0400,
            VMWrite = 0x0020,
            // 组合常用访问：读 + 查询
            ReadFlags = VMRead | QueryInformation | VMOperation
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

        // 常量取自 winnt.h
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_FREE = 0x10000;
        private const uint MEM_RESERVE = 0x2000;

        private const uint PAGE_GUARD = 0x100;
        private const uint PAGE_NOACCESS = 0x01;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(
            ProcessAccessFlags dwDesiredAccess,
            bool bInheritHandle,
            int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            IntPtr nSize,
            out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualQueryEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION64 lpBuffer,
            IntPtr dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        #endregion

        public class ScanResult
        {
            public IntPtr Address { get; set; }
            public override string ToString() => $"0x{Address.ToInt64():X}";
        }

        public class Pattern
        {
            public byte[] Bytes { get; set; } = new byte[] { };
            public bool[] Mask { get; set; } = new bool[] { }; // true = 必须匹配，false = 通配符
            public int Length => Bytes.Length;
        }

        /// <summary>
        /// 解析 CE 风格模式字符串，例如 "48 8B ?? 45 89 ?? 33 FF"
        /// 支持连续写法 "488B??4589??33FF"
        /// </summary>
        public static Pattern ParsePattern(string pattern)
        {
            var cleaned = pattern
                .Replace("\r", " ")
                .Replace("\n", " ")
                .Replace("\t", " ")
                .Trim();

            var tokens = new List<string>();
            // 拆分（允许用户不加空格直接连续写，故需要重新切分）
            foreach (var part in cleaned.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (part.Contains("??"))
                {
                    // 一个 token 如果包含多组 ??（例如 "????"）按每两个字符一组拆
                    int i = 0;
                    while (i < part.Length)
                    {
                        if (i + 1 < part.Length && part[i] == '?' && part[i + 1] == '?')
                        {
                            tokens.Add("??");
                            i += 2;
                        }
                        else
                        {
                            // 累积两个字符
                            if (i + 1 < part.Length)
                            {
                                tokens.Add(part.Substring(i, 2));
                                i += 2;
                            }
                            else
                            {
                                // 单独一个字符不足两位，视为无效
                                throw new FormatException("不合法的模式分段：" + part);
                            }
                        }
                    }
                }
                else
                {
                    // 普通 hex，可能是连续的：如 "488B4589"
                    int i = 0;
                    while (i < part.Length)
                    {
                        if (i + 1 < part.Length)
                        {
                            var sub = part.Substring(i, 2);
                            tokens.Add(sub);
                            i += 2;
                        }
                        else
                        {
                            throw new FormatException("不合法的 hex 分段：" + part);
                        }
                    }
                }
            }

            var bytes = new List<byte>();
            var mask = new List<bool>();

            foreach (var tk in tokens)
            {
                if (tk == "??")
                {
                    bytes.Add(0x00); // 值无所谓
                    mask.Add(false);
                }
                else
                {
                    if (!byte.TryParse(tk, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b))
                        throw new FormatException("无法解析字节: " + tk);
                    bytes.Add(b);
                    mask.Add(true);
                }
            }

            return new Pattern
            {
                Bytes = bytes.ToArray(),
                Mask = mask.ToArray()
            };
        }

        /// <summary>
        /// 在一个缓冲区中匹配模式，返回相对偏移列表
        /// </summary>
        private static List<int> MatchPattern(byte[] buffer, Pattern pattern)
        {
            var results = new List<int>();
            if (pattern.Length == 0 || buffer.Length < pattern.Length)
                return results;

            int lastStart = buffer.Length - pattern.Length;
            for (int i = 0; i <= lastStart; i++)
            {
                bool ok = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (pattern.Mask[j] && buffer[i + j] != pattern.Bytes[j])
                    {
                        ok = false;
                        break;
                    }
                }
                if (ok)
                    results.Add(i);
            }

            return results;
        }

        /// <summary>
        /// 进行进程内存扫描
        /// </summary>
        public static List<ScanResult> ScanProcess(int processId, string patternString,
            ulong startAddress = 0,
            ulong endAddress = 0x00007FFFFFFF0000, // 合理用户态上界
            int blockSize = 1024 * 1024) // 1MB 每块
        {
            var pattern = ParsePattern(patternString);
            if (pattern.Length == 0)
                throw new ArgumentException("模式不能为空。");

            var handle = OpenProcess(ProcessAccessFlags.ReadFlags, false, processId);
            if (handle == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess 失败");

            var results = new List<ScanResult>();
            try
            {
                ulong address = startAddress;
                byte[] leftover = new byte[] { };  

                while (address < endAddress)
                {
                    // 查询内存区域信息
                    if (VirtualQueryEx(handle, new IntPtr((long)address),
                        out var memInfo, new IntPtr((long)Marshal.SizeOf<MEMORY_BASIC_INFORMATION64>())) == IntPtr.Zero)
                    {
                        // 到头或错误，推进地址（避免死循环）
                        address += 0x1000;
                        continue;
                    }

                    // 下一块地址（VirtualQueryEx 返回的 RegionSize 可能很大）
                    ulong regionBase = memInfo.BaseAddress;
                    ulong regionSize = memInfo.RegionSize;
                    ulong nextAddress = regionBase + regionSize;

                    bool readable = (memInfo.State == MEM_COMMIT) &&
                                    (memInfo.Protect != PAGE_NOACCESS) &&
                                    ((memInfo.Protect & PAGE_GUARD) == 0);

                    if (!readable || regionSize == 0)
                    {
                        address = nextAddress;
                        leftover = new byte[] { };
                        continue;
                    }

                    // 限定到扫描范围
                    ulong regionScanStart = Math.Max(regionBase, startAddress);
                    ulong regionScanEnd = Math.Min(regionBase + regionSize, endAddress);

                    ulong ptr = regionScanStart;
                    while (ptr < regionScanEnd)
                    {
                        ulong remaining = regionScanEnd - ptr;
                        int toRead = (int)Math.Min((ulong)blockSize, remaining);

                        var buffer = new byte[toRead];
                        if (!ReadProcessMemory(handle, new IntPtr((long)ptr), buffer, new IntPtr(toRead), out var read))
                        {
                            // 读取失败，尝试跳过一页
                            ptr += 0x1000;
                            leftover = new byte[] { };
                            continue;
                        }

                        int actuallyRead = read.ToInt32();
                        if (actuallyRead <= 0)
                        {
                            ptr += (ulong)toRead;
                            leftover = new byte[] { };
                            continue;
                        }

                        if (actuallyRead != toRead)
                        {
                            // 截断
                            Array.Resize(ref buffer, actuallyRead);
                        }

                        // 拼接 leftover (跨块匹配)
                        byte[] scanBuf;
                        int offsetBase; // scanBuf[0] 对应的真实地址
                        if (leftover.Length > 0)
                        {
                            scanBuf = new byte[leftover.Length + buffer.Length];
                            Buffer.BlockCopy(leftover, 0, scanBuf, 0, leftover.Length);
                            Buffer.BlockCopy(buffer, 0, scanBuf, leftover.Length, buffer.Length);
                            offsetBase = (int)(ptr - (ulong)leftover.Length);
                        }
                        else
                        {
                            scanBuf = buffer;
                            offsetBase = (int)ptr;
                        }

                        var matches = MatchPattern(scanBuf, pattern);
                        foreach (var m in matches)
                        {
                            long absolute = offsetBase + m;
                            if (absolute >= 0)
                                results.Add(new ScanResult { Address = new IntPtr(absolute) });
                        }

                        // 为下一块准备 leftover
                        int keep = Math.Min(pattern.Length - 1, scanBuf.Length);
                        leftover = new byte[keep];
                        Buffer.BlockCopy(scanBuf, scanBuf.Length - keep, leftover, 0, keep);

                        ptr += (ulong)actuallyRead;
                    }

                    address = nextAddress;
                    leftover = new byte[] { }; // 一个区域结束，不继续跨区域连接
                }
            }
            finally
            {
                CloseHandle(handle);
            }

           return results;
        }

        /// <summary>
        /// 示例用法：通过进程名称扫描
        /// </summary>
        public static List<ScanResult> ScanByProcessName(string processName, string pattern)
        {
            var proc = Array.Find(Process.GetProcessesByName(processName), p => true)
                       ?? throw new ArgumentException("找不到进程: " + processName);
            return ScanProcess(proc.Id, pattern);
        }
    }

}