using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;

namespace Launcher
{
    public static class MemoryWriter
    {
        #region PInvoke

        [Flags]
        private enum ProcessAccessFlags : uint
        {
            VMRead = 0x0010,
            VMWrite = 0x0020,
            VMOperation = 0x0008,
            QueryInformation = 0x0400,
            // 组合：读 + 写 + 操作 + 查询
            AllForEdit = VMRead | VMWrite | VMOperation | QueryInformation
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(
            ProcessAccessFlags access, bool inheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(
            IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(
            IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtectEx(
            IntPtr hProcess, IntPtr lpAddress,
            IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        // 常见保护常量
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_READWRITE = 0x04;

        #endregion

        /// <summary>
        /// 打开进程获取写入权限句柄
        /// </summary>
        public static IntPtr OpenProcessForEdit(int pid)
        {
            var h = OpenProcess(ProcessAccessFlags.AllForEdit, false, pid);
            if (h == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess 失败，可能需要管理员权限。");
            return h;
        }

        /// <summary>
        /// 写一个 int32（小端）
        /// </summary>
        public static void WriteInt32(IntPtr hProcess, IntPtr address, int newValue, bool protectIfNeeded = true)
        {
            var bytes = BitConverter.GetBytes(newValue); // 小端
            WriteBytes(hProcess, address, bytes, protectIfNeeded);
        }

        /// <summary>
        /// 写任意字节序列
        /// </summary>
        public static void WriteBytes(IntPtr hProcess, IntPtr address, byte[] data, bool protectIfNeeded = true)
        {
            uint oldProtect = 0;
            bool changedProtect = false;

            if (protectIfNeeded)
            {
                // 尝试改成读写或执行读写（长度按 data.Length）
                // 有的页原本就可写；如果 VirtualProtectEx 失败可以忽略继续写，看是否成功。
                if (VirtualProtectEx(hProcess, address, (IntPtr)data.Length, PAGE_EXECUTE_READWRITE, out oldProtect))
                {
                    changedProtect = true;
                }
            }

            if (!WriteProcessMemory(hProcess, address, data, (IntPtr)data.Length, out var written) || written.ToInt32() != data.Length)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"WriteProcessMemory 失败，写入字节数 {written} / {data.Length}");
            }

            // 恢复原保护
            if (changedProtect)
            {
                VirtualProtectEx(hProcess, address, (IntPtr)data.Length, oldProtect, out _);
            }
        }

        /// <summary>
        /// 读回 int32 验证
        /// </summary>
        public static int ReadInt32(IntPtr hProcess, IntPtr address)
        {
            var buf = new byte[4];
            if (!ReadProcessMemory(hProcess, address, buf, (IntPtr)4, out var read) || read.ToInt32() != 4)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "ReadProcessMemory 失败");
            return BitConverter.ToInt32(buf, 0);
        }

        /// <summary>
        /// 简单“冻结”功能：后台线程不断写入固定值
        /// </summary>
        public static Thread FreezeInt32(IntPtr hProcess, IntPtr address, int value, int intervalMs = 100)
        {
            var t = new Thread(() =>
            {
                try
                {
                    while (true)
                    {
                        WriteInt32(hProcess, address, value, protectIfNeeded: false);
                        Thread.Sleep(intervalMs);
                    }
                }
                catch (ThreadInterruptedException) { }
                catch (Exception ex)
                {
                    Console.WriteLine("冻结线程异常: " + ex.Message);
                }
            });
            t.IsBackground = true;
            t.Start();
            return t;
        }

    }
}