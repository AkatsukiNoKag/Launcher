using System;
using System.Diagnostics;
using System.Globalization;
using System.Windows.Forms;

namespace Launcher
{
    public partial class MainForm : Form
    {
        private const string TargetProcessName = "WeChat";
        private const string TargetModuleName = "WeChatWin.dll";
        private const string DestinationVersion = "f254200c";//目标版本
        private const string DestinationVersion2 = "63090217";//自己的版本

        // RVAs relative to WeChatWin.dll. They are validated before the target
        // process is opened, so a typo cannot result in a partial update.
        //private static readonly string[] TargetOffsets =
        //{
        //"2FFEAF8",
        //"3020ELC",
        //"3021AEC",
        //"303C4D8",
        //"303FEF4",
        //"30416EC"
        //};
        private static readonly string TargetOffset = "3020E1C";

        private readonly ToolTip tip = new ToolTip();

        public MainForm()
        {
            Icon = System.Drawing.Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            tip.IsBalloon = true;
            InitializeComponent();
        }

        private void Button1_Click(object sender, EventArgs e)
        {
            if (!(sender is Button button))
            {
                return;
            }

            try
            {
                // Parse all configuration before any target-process memory is changed.
                var offset = ParseOffsets(TargetOffset);
                var newValue = ParseHexInt32(DestinationVersion);
                var process = Array.Find(Process.GetProcessesByName(TargetProcessName), p => true)
                              ?? throw new ArgumentException("进程未启动: " + TargetProcessName);
                var module = FindTargetModule(process);

                Console.WriteLine($"目标进程: {process.ProcessName} (PID {process.Id})");
                Console.WriteLine($"目标模块: {module.ModuleName}, 基址: 0x{module.BaseAddress.ToInt64():X}");

                var processHandle = MemoryWriter.OpenProcessForEdit(process.Id);
                try
                {
                    var address = new IntPtr(checked(module.BaseAddress.ToInt64() + (long)offset));
                    Console.WriteLine($"写入 RVA: 0x{offset:X}, 地址: 0x{address.ToInt64():X}");

                    MemoryWriter.WriteInt32(processHandle, address, newValue);

                    var verifiedValue = MemoryWriter.ReadInt32(processHandle, address);
                    Console.WriteLine($"写入后读取验证: {verifiedValue} (0x{verifiedValue:X8})");
                    if (verifiedValue != newValue)
                    {
                        throw new InvalidOperationException("写入值与读回值不一致，已停止后续写入。");
                    }
                }
                finally
                {
                    MemoryWriter.CloseHandle(processHandle);
                }

                tip.Show("已完成请登录", button, button.Height, 0, 3000);
            }
            catch (Exception ex)
            {
                Console.WriteLine("修改失败: " + ex.Message);
                tip.Show("修改失败，请查看控制台", button, button.Height, 0, 3000);
            }
        }

        private static uint ParseOffsets(string targetOffset)
        {
            if (!uint.TryParse(targetOffset, NumberStyles.AllowHexSpecifier,
                CultureInfo.InvariantCulture, out var ret))
            {
                throw new FormatException("无效的十六进制 RVA: " + targetOffset);
            }
            else
            {
                return ret;
            }
        }

        private static int ParseHexInt32(string value)
        {
            uint parsedValue;
            if (!uint.TryParse(value, NumberStyles.AllowHexSpecifier,
                CultureInfo.InvariantCulture, out parsedValue))
            {
                throw new FormatException("无效的十六进制值: " + value);
            }

            return unchecked((int)parsedValue);
        }

        private static ProcessModule FindTargetModule(Process process)
        {
            foreach (ProcessModule module in process.Modules)
            {
                if (string.Equals(module.ModuleName, TargetModuleName,
                    StringComparison.OrdinalIgnoreCase))
                {
                    return module;
                }
            }

            throw new InvalidOperationException("未找到目标模块: " + TargetModuleName);
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (!(sender is Button button))
            {
                return;
            }

            try
            {
                // Parse all configuration before any target-process memory is changed.
                var offset = ParseOffsets(TargetOffset);
                var newValue = ParseHexInt32(DestinationVersion2);
                var process = Array.Find(Process.GetProcessesByName(TargetProcessName), p => true)
                              ?? throw new ArgumentException("进程未启动: " + TargetProcessName);
                var module = FindTargetModule(process);

                Console.WriteLine($"目标进程: {process.ProcessName} (PID {process.Id})");
                Console.WriteLine($"目标模块: {module.ModuleName}, 基址: 0x{module.BaseAddress.ToInt64():X}");

                var processHandle = MemoryWriter.OpenProcessForEdit(process.Id);
                try
                {
                    var address = new IntPtr(checked(module.BaseAddress.ToInt64() + (long)offset));
                    Console.WriteLine($"写入 RVA: 0x{offset:X}, 地址: 0x{address.ToInt64():X}");

                    MemoryWriter.WriteInt32(processHandle, address, newValue);

                    var verifiedValue = MemoryWriter.ReadInt32(processHandle, address);
                    Console.WriteLine($"写入后读取验证: {verifiedValue} (0x{verifiedValue:X8})");
                    if (verifiedValue != newValue)
                    {
                        throw new InvalidOperationException("写入值与读回值不一致，已停止后续写入。");
                    }
                }
                finally
                {
                    MemoryWriter.CloseHandle(processHandle);
                }

                tip.Show("已完成请登录", button, button.Height, 0, 3000);
            }
            catch (Exception ex)
            {
                Console.WriteLine("修改失败: " + ex.Message);
                tip.Show($"{ex.Message}", button, button.Height, 0, 3000);
            }
        }
    }
}
