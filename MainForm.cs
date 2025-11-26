using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.Windows.Forms;

namespace Launcher
{
    public partial class MainForm: Form
    {
        string version = null;
        const string destVersion = "f2541212";
        public MainForm()
        {
            InitializeComponent();
            InitializeVersion();
        }

        private void InitializeVersion()
        {
            string registryPath = @"SOFTWARE\Tencent\WeChat";
            string valueName = "Version";
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(registryPath))
            {
                if (key != null)
                {
                    object value = key.GetValue(valueName);

                    if (value != null)
                    {
                        if (value is int ver)
                        {
                            version = ver.ToString("X");
                        }
                        Console.WriteLine("WeChat Version: " + value.ToString());
                    }
                    else
                    {
                        Console.WriteLine("未找到 Version 值。");
                    }
                }
                else
                {
                    Console.WriteLine("未找到注册表项。");
                }
            }
        }

        private void Button1_Click(object sender, EventArgs e)
        {
            string procName = "WeChat";
            string pattern = version??"63090217";

            string valStr = destVersion;

            var proc = Array.Find(Process.GetProcessesByName(procName), p => true)
                       ?? throw new ArgumentException("找不到进程: " + procName);
            int target;
            if (pattern.StartsWith("0x", StringComparison.OrdinalIgnoreCase) || System.Text.RegularExpressions.Regex.IsMatch(pattern, @"^[0-9A-Fa-f]+$"))
                target = FastInt32Scanner.ParseHexInt32(pattern);
            else
                target = int.Parse(pattern);

            Console.WriteLine($"扫描进程 {proc.Id} {proc.ProcessName}, 目标值: {target} (hex 0x{target:X8})");

            var hits = FastInt32Scanner.ScanInt32Value(proc.Id, target);

            Console.WriteLine($"匹配数量: {hits.Count}");
            foreach (var address in hits)
            {

                Console.WriteLine($"0x{address.ToInt64():X}");
                //bool doFreeze = args.Length >= 4 && args[3].Equals("freeze", StringComparison.OrdinalIgnoreCase);


                // 解析新值（十进制或十六进制）
                int newVal;
                if (valStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    newVal = int.Parse(valStr.Substring(2), System.Globalization.NumberStyles.HexNumber);
                else if (System.Text.RegularExpressions.Regex.IsMatch(valStr, @"^[0-9A-Fa-f]+$"))
                    newVal = int.Parse(valStr, System.Globalization.NumberStyles.HexNumber);
                else
                    newVal = int.Parse(valStr);

                Console.WriteLine($"目标进程: {proc.ProcessName} (PID {proc.Id})");
                Console.WriteLine($"写入地址: 0x{address.ToInt64():X}");
                Console.WriteLine($"新值: {newVal} (hex 0x{newVal:X8})");

                var hProcess = MemoryWriter.OpenProcessForEdit(proc.Id);
                try
                {
                    // 写入
                    MemoryWriter.WriteInt32(hProcess, address, newVal);
                    var verify = MemoryWriter.ReadInt32(hProcess, address);
                    Console.WriteLine($"写入后读取验证: {verify} (0x{verify:X8})");

                    if (verify != newVal)
                        Console.WriteLine("警告：写入值与读回值不一致，可能地址错误或进程覆盖了此值。");

                    //if (doFreeze)
                    //{
                    //    Console.WriteLine("启动冻结线程，每 100ms 写入一次...");
                    //    var t = MemoryWriter.FreezeInt32(hProcess, address, newVal);
                    //    Console.WriteLine("按 Enter 停止冻结。");
                    //    Console.ReadLine();
                    //    t.Interrupt();
                    //}
                }
                finally
                {
                    MemoryWriter.CloseHandle(hProcess);
                }
                
            }











            //try
            //{
            //    var results = MemoryHexScanner.ScanByProcessName(procName, pattern);
            //    Console.WriteLine($"匹配数量: {results.Count}");
            //    foreach (var r in results)
            //    {
            //        Console.WriteLine(r);
            //    }
            //}
            //catch (Exception ex)
            //{
            //    Console.WriteLine("扫描失败: " + ex);
            //}
        }
    }
}
