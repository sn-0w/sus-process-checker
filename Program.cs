using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
namespace Crackme_Console
{
    class Program
    {

        static void Main(string[] args)
        {
            startup();
            var heartbeattask = Task.Factory.StartNew(guard_thread, new CancellationToken(), TaskCreationOptions.RunContinuationsAsynchronously, TaskScheduler.Current);

            Console.WriteLine("enter password:");
            string input = Console.ReadLine();
            if (input.Equals("secret_password"))
            {
                Console.WriteLine("right password!");
            }
            else
            {
                Console.WriteLine("wrong password!");
            }
            Console.ReadLine();
            Environment.Exit(1);
        }
        private static bool alreadySigned(string file)
        {
            try
            {
                RunspaceConfiguration runspaceConfiguration = RunspaceConfiguration.Create();
                Runspace runspace = RunspaceFactory.CreateRunspace(runspaceConfiguration);
                runspace.Open();

                Pipeline pipeline = runspace.CreatePipeline();
                pipeline.Commands.AddScript("Get-AuthenticodeSignature \"" + file + "\"");

                Collection<PSObject> results = pipeline.Invoke();
                runspace.Close();
                Signature signature = results[0].BaseObject as Signature;
                return signature == null ? false : (signature.Status != SignatureStatus.NotSigned);
            }
            catch (Exception e)
            {
                throw new Exception("Error when trying to check if file is signed:" + file + " --> " + e.Message);
            }
        }
        static void startup()
        {
            var processes = Process.GetProcesses();
            foreach (var process in processes)
            {
                try
                {
                    string fullPath = process.MainModule.FileName;
                    if (fullPath.ToLower().StartsWith(@"c:\windows")) continue;
                    if (process == Process.GetCurrentProcess()) continue;
                    string processname = Path.GetFileName(fullPath);
                    string processpath = Path.GetDirectoryName(fullPath);
                    string[] fileEntries = Directory.GetFiles(processpath);
                    foreach (var blacklist in list)
                    {
                        foreach (var filename in fileEntries)
                        {
                            
                            if (filename.ToLower().Contains(blacklist) && !alreadySigned(processpath+@"\"+filename))
                            {
                                fatalerror("{Error:0} Illegal Program Detected! Please close " + processname);
                            }
                        }
                    }

                    foreach (var blacklist in list)
                    {
                        if (fullPath.ToLower().Contains(blacklist)) fatalerror("{Error:1} Illegal Program Detected! Please close " + processname);
                    }
                }
                catch { }
            }
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        public static string[] list = {
        "hack",
        "crack",
        "dump",
        "debug",
        "dnspy",
        "ida",
        "dissassemble",
        "dbg"
        };
        static void fatalerror(string reason)
        {
            Process.Start(new ProcessStartInfo("cmd.exe", "/c START CMD /C \"COLOR C && TITLE Security && ECHO " + reason + " && TIMEOUT 10\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false
            });
            Environment.Exit(6547);
            Process.GetCurrentProcess().Kill();
        }

        private static void guard_thread()
        {
            WqlEventQuery query = new WqlEventQuery("__InstanceCreationEvent", new TimeSpan(0, 0, 1), "TargetInstance isa \"Win32_Process\"");

            ManagementEventWatcher watcher = new ManagementEventWatcher
            {
                Query = query
            };
            while (null == null)
            {
                ManagementBaseObject e = watcher.WaitForNextEvent();
                try
                {
                    if (GetModuleHandle("HTTPDebuggerBrowser.dll") != IntPtr.Zero || GetModuleHandle("FiddlerCore4.dll") != IntPtr.Zero || GetModuleHandle("RestSharp.dll") != IntPtr.Zero || GetModuleHandle("Titanium.Web.Proxy.dll") != IntPtr.Zero)
                    {
                        fatalerror("{Error:4} Illegal Program used for Request tampering Detected!");
                    }
                    string processname = ((ManagementBaseObject)e["TargetInstance"])["Name"].ToString();
                    string processpath = ((ManagementBaseObject)e["TargetInstance"])["ExecutablePath"].ToString();
                    if (processpath.ToLower().StartsWith(@"c:\windows")) continue;
                    string processpath2 = Path.GetDirectoryName(processpath);
                    string[] fileEntries = Directory.GetFiles(processpath2);
                    foreach (var blacklist in list)
                    {
                        foreach (var filename in fileEntries)
                        {
                            if (filename.ToLower().Contains(blacklist)) fatalerror("{Error:2} Illegal Program Detected! Please close " + processname);
                        }
                    }

                    foreach (var blacklist in list)
                    {
                        if (processname.ToLower().Contains(blacklist) || processpath.ToLower().Contains(blacklist)) fatalerror("{Error:3} Illegal Program Detected! Please close " + processname);
                    }
                }
                catch { }
            }
        }
    }
}
