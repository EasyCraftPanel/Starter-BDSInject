#nullable enable
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace EasyCraftStarter
{
    public static class Starter
    {
        #region Win32 Code

        // Structures
        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        private struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        public struct SECURITY_ATTRIBUTES
        {
            public int length;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CreateProcess(string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size,
            out int lpNumberOfBytesWritten);


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess,
            IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
            uint dwCreationFlags, IntPtr lpThreadId);


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);


        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CreatePipe(out SafeFileHandle hReadPipe, out SafeFileHandle hWritePipe,
            ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);


        [DllImport("kernel32.dll")]
        static extern int GetExitCodeProcess(IntPtr hProcess, ref int lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            SafeHandle hSourceHandle,
            IntPtr hTargetProcess,
            out SafeFileHandle targetHandle,
            int dwDesiredAccess,
            bool bInheritHandle,
            int dwOptions
        );


        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        internal static extern uint ResumeThread(IntPtr hThread);

        const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        const uint CREATE_SUSPENDED = 0x00000004;
        static IntPtr NULL = IntPtr.Zero;
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint MEM_RELEASE = 0x00008000;
        const uint PAGE_READWRITE = 4;

        const uint INFINITE = 0xFFFFFFFF;

        //private static uint STARTF_USESHOWWINDOW = 0x00000001;
        //private static uint STARTF_USESTDHANDLES = 0x00000100;
        //private static uint STARTF_FORCEONFEEDBACK = 0x00000040;
        //private static uint NORMAL_PRIORITY_CLASS = 0x00000020;
        //private static uint CREATE_BREAKAWAY_FROM_JOB = 0x01000000;
        //private static uint CREATE_NO_WINDOW = 0x08000000;
        //private static short SW_SHOW = 5;
        //private static short SW_HIDE = 0;
        //private const int STD_OUTPUT_HANDLE = -11;
        //private const int HANDLE_FLAG_INHERIT = 1;
        //private static uint GENERIC_READ = 0x80000000;
        //private static uint FILE_ATTRIBUTE_READONLY = 0x00000001;
        //private static uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
        //private const int OPEN_EXISTING = 3;
        private static uint CREATE_NEW_CONSOLE = 0x00000010;
        //private static uint STILL_ACTIVE = 0x00000103;

        #endregion

        public static Dictionary<string, string> StarterInfo = new()
        {
            { "name", "BDS 插件注入器" }, // 开服器友好名称
            { "id", "top.easycraft.starter.bdsinject" }, // 开服器 ID
            { "version", "1.0.0" }, // 版本号
            { "description", "这个开服器可以将服务器 BDS 目录 /dll 下的东西注入到 BDS 进程" }, // 简介信息
            { "author", "Kengwang" } // 作者
        };

        public static Dictionary<int, StreamWriter> Inputs = new();

        public static Dictionary<string, string> InitializeStarter()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            {
                throw new Exception("仅支持 Windows 系统");
            }

            return StarterInfo;
        }

        public static bool OnServerInput(dynamic Server, string input)
        {
            if (Inputs.ContainsKey(Server.BaseInfo.Id))
            {
                ((StreamWriter)Inputs[Server.BaseInfo.Id]).WriteLine(input);
                return true;
            }

            return false;
        }

        public static bool ServerStart(dynamic Server, string program, string argument, dynamic _, dynamic __)
        {
            try
            {
                Server.StatusInfo.OnConsoleOutput("正在注入 DLL");

                // 首先创建进程
                IntPtr hmKernel32dll = GetModuleHandle("kernel32.dll");
                IntPtr lpLoadLibraryW = GetProcAddress(hmKernel32dll, "LoadLibraryA");
                STARTUPINFO stif = new STARTUPINFO()
                    { wShowWindow = 0 };
                stif.cb = (uint)System.Runtime.InteropServices.Marshal.SizeOf(stif);
                PROCESS_INFORMATION psif = new PROCESS_INFORMATION();

                // 创建重定向 - 代码参考自 dotnet/runtime
                CreatePipe(out var parentInputPipeHandle, out var childInputPipeHandle, true);
                CreatePipe(out var parentOutputPipeHandle, out var childOutputPipeHandle, false);
                CreatePipe(out var parentErrorPipeHandle, out var childErrorPipeHandle, false);
                stif.dwFlags = 0x00000100;

                stif.hStdInput = childInputPipeHandle.DangerousGetHandle();
                stif.hStdOutput = childOutputPipeHandle.DangerousGetHandle();
                stif.hStdError = childErrorPipeHandle.DangerousGetHandle();

                var ret = CreateProcess(program, null, NULL, NULL, true,
                    CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
                    NULL,
                    Server.ServerDir, ref stif, out psif);
                if (ret != true)
                {
                    throw new Exception("启动BDS失败! Code: " + Marshal.GetLastWin32Error());
                }

                var input = new StreamWriter(new FileStream(parentInputPipeHandle, FileAccess.Write, 4096, false),
                    new UTF8Encoding(false), 4096); //无BOM
                input.AutoFlush = true;
                Inputs[Server.BaseInfo.Id] = input;

                var output = new StreamReader(new FileStream(parentOutputPipeHandle, FileAccess.Read, 4096, false),
                    Encoding.UTF8, true, 4096);

                var error = new StreamReader(new FileStream(parentErrorPipeHandle, FileAccess.Read, 4096, false),
                    Encoding.UTF8, true, 4096);

                var outputReader = new AsyncStreamReader(output.BaseStream,
                    s => { Server.StatusInfo.OnConsoleOutput(s); }, Encoding.UTF8);
                outputReader.BeginReadLine();

                var errorReader = new AsyncStreamReader(error.BaseStream,
                    s => { Server.StatusInfo.OnConsoleOutput(s, true); }, Encoding.UTF8);
                errorReader.BeginReadLine();

                if (Directory.Exists(Server.ServerDir + "/dll"))
                {
                    foreach (string file in Directory.EnumerateFiles(Server.ServerDir + "/dll", "*.dll"))
                    {
                        try
                        {
                            Server.StatusInfo.OnConsoleOutput("加载插件" + Path.GetFileName(file));
                            RunThreadWithString(psif.hProcess, lpLoadLibraryW, Path.GetFullPath(file));
                        }
                        catch (Exception e)
                        {
                            Server.StatusInfo.OnConsoleOutput("加载插件" + Path.GetFileName(file) + "失败: " + e.Message,
                                true);
                        }
                    }
                }


                Task.Run(() =>
                {
                    // 恢复进程
                    ResumeThread(psif.hThread);
                    CloseHandle(psif.hThread);
                    WaitForSingleObject(psif.hProcess, INFINITE);
                    int exitcode = 0;
                    GetExitCodeProcess(psif.hProcess, ref exitcode);
                    CloseHandle(psif.hProcess);
                    if (exitcode == 0)
                    {
                        Server.StatusInfo.OnConsoleOutput("BDS正常退出");
                    }
                    else
                    {
                        Server.StatusInfo.OnConsoleOutput("BDS异常退出 Code: " + exitcode);
                    }

                    Server.StatusInfo.Status = 0;
                });
                Server.StatusInfo.Status = 2;
                return true;
            }
            catch (Exception e)
            {
                Server.StatusInfo.OnConsoleOutput("启动失败: " + e.Message);
                Server.StatusInfo.Status = 0;
                return false;
            }
        }

        public static bool ServerStop(dynamic Server)
        {
            try
            {
                if (Inputs.ContainsKey(Server.BaseInfo.Id))
                {
                    ((StreamWriter)Inputs[Server.BaseInfo.Id]).WriteLine("stop");
                    return true;
                }

                return false;
            }
            catch (Exception e)
            {
                Server.StatusInfo.OnConsoleOutput("关闭失败: " + e.Message);
                return false;
            }
        }


        public static void RunThreadWithString(IntPtr hProcess, IntPtr lpLoadLibrary, string library_path)
        {
            uint size = (uint)library_path.Length;
            IntPtr lpstr = VirtualAllocEx(hProcess, NULL, (IntPtr)library_path.Length,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (lpstr == NULL)
            {
                throw new Exception("ERR_VIRTUALALLOC_FAILED");
            }

            byte[] bytes = Encoding.ASCII.GetBytes(library_path);
            if (WriteProcessMemory(hProcess, lpstr, bytes,
                size, out var bytewritten) == 0)
            {
                VirtualFreeEx(hProcess, lpstr, 0, MEM_RELEASE);
                throw new Exception("ERR_CREATEREMOTETHREAD_FAILED");
            }

            IntPtr hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, lpLoadLibrary, lpstr, 0, NULL);
            Marshal.GetLastWin32Error();
            if (hRemoteThread == NULL)
            {
                VirtualFreeEx(hProcess, lpstr, 0, MEM_RELEASE);
                throw new Exception("ERR_CREATEREMOTETHREAD_FAILED");
            }

            WaitForSingleObject(hRemoteThread, INFINITE);
            GetExitCodeThread(hRemoteThread, out var exitCode);
            CloseHandle(hRemoteThread);
            VirtualFreeEx(hProcess, lpstr, 0, MEM_RELEASE);
        }


        private static void CreatePipe(out SafeFileHandle parentHandle, out SafeFileHandle childHandle,
            bool parentInputs)
        {
            SECURITY_ATTRIBUTES securityAttributesParent = default;
            securityAttributesParent.bInheritHandle = true;

            SafeFileHandle? hTmp = null;
            try
            {
                if (parentInputs)
                {
                    CreatePipeWithSecurityAttributes(out childHandle, out hTmp, ref securityAttributesParent, 0);
                }
                else
                {
                    CreatePipeWithSecurityAttributes(out hTmp,
                        out childHandle,
                        ref securityAttributesParent,
                        0);
                }

                IntPtr currentProcHandle = GetCurrentProcess();
                if (!DuplicateHandle(currentProcHandle,
                    hTmp,
                    currentProcHandle,
                    out parentHandle,
                    0,
                    false,
                    2))
                {
                    throw new Win32Exception();
                }
            }
            finally
            {
                if (hTmp != null && !hTmp.IsInvalid)
                {
                    hTmp.Dispose();
                }
            }
        }

        private static void CreatePipeWithSecurityAttributes(out SafeFileHandle hReadPipe,
            out SafeFileHandle hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize)
        {
            bool ret = CreatePipe(out hReadPipe, out hWritePipe, ref lpPipeAttributes, nSize);
            if (!ret || hReadPipe.IsInvalid || hWritePipe.IsInvalid)
            {
                throw new Win32Exception();
            }
        }
    }
}