using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace DnsDefender.Collector.Attribution;

public sealed class ProcessAttributionService
{
    private const uint ProcessQueryLimitedInformation = 0x1000;

    public (string ProcessName, string ExecutablePath) Resolve(int? processId)
    {
        if (processId is null || processId <= 0)
        {
            return (string.Empty, string.Empty);
        }

        try
        {
            using var process = Process.GetProcessById(processId.Value);
            var name = process.ProcessName;

            string path;
            try
            {
                path = process.MainModule?.FileName ?? string.Empty;
            }
            catch
            {
                path = TryGetExecutablePathViaQueryFullProcessImageName(processId.Value);
            }

            if (string.IsNullOrWhiteSpace(path))
            {
                path = TryGetExecutablePathViaQueryFullProcessImageName(processId.Value);
            }

            return (name, path);
        }
        catch
        {
            return (string.Empty, string.Empty);
        }
    }

    private static string TryGetExecutablePathViaQueryFullProcessImageName(int processId)
    {
        IntPtr handle = IntPtr.Zero;

        try
        {
            handle = OpenProcess(ProcessQueryLimitedInformation, false, processId);
            if (handle == IntPtr.Zero)
            {
                return string.Empty;
            }

            var capacity = 4096;
            var builder = new StringBuilder(capacity);
            var size = capacity;

            if (!QueryFullProcessImageName(handle, 0, builder, ref size) || size <= 0)
            {
                return string.Empty;
            }

            return builder.ToString();
        }
        catch
        {
            return string.Empty;
        }
        finally
        {
            if (handle != IntPtr.Zero)
            {
                CloseHandle(handle);
            }
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder exeName, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
