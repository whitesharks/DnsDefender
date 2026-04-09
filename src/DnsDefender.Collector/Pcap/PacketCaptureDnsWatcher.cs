using System.Net;
using System.Runtime.InteropServices;
using DnsDefender.Common.Models;
using SharpPcap;
using SharpPcap.LibPcap;

namespace DnsDefender.Collector.Pcap;

public sealed class PacketCaptureDnsWatcher : IDisposable
{
    private const int AfInet = 2;
    private const int UdpTableOwnerPid = 1;
    private const int TcpTableOwnerPidAll = 5;
    private const string NpcapInstallHint = "缺少抓包组件。推荐安装 Npcap 1.79+（兼容 Win7/x86），下载：https://npcap.com/#download；安装时勾选 WinPcap API-compatible Mode。";

    private ICaptureDevice? _device;

    public event Action<DnsTelemetryRecord>? DnsRecordCaptured;

    public bool IsRunning { get; private set; }

    public IReadOnlyList<PacketCaptureInterfaceInfo> GetInterfaces()
    {
        try
        {
            var devices = CaptureDeviceList.Instance;
            return devices
                .Select(d => new PacketCaptureInterfaceInfo
                {
                    InterfaceId = d.Name ?? string.Empty,
                    DisplayName = string.IsNullOrWhiteSpace(d.Description)
                        ? (d.Name ?? "未知网卡")
                        : $"{d.Description} ({d.Name})"
                })
                .Where(x => !string.IsNullOrWhiteSpace(x.InterfaceId))
                .ToList();
        }
        catch (DllNotFoundException)
        {
            return Array.Empty<PacketCaptureInterfaceInfo>();
        }
        catch
        {
            return Array.Empty<PacketCaptureInterfaceInfo>();
        }
    }

    public string Start(string interfaceId)
    {
        if (IsRunning)
        {
            return "抓包已在运行。";
        }

        if (string.IsNullOrWhiteSpace(interfaceId))
        {
            return "未选择抓包网卡。";
        }

        ICaptureDevice? device;
        try
        {
            device = CaptureDeviceList.Instance.FirstOrDefault(d => string.Equals(d.Name, interfaceId, StringComparison.OrdinalIgnoreCase));
        }
        catch (DllNotFoundException)
        {
            return NpcapInstallHint;
        }
        catch (Exception ex)
        {
            return $"抓包初始化失败：{ex.Message}；{NpcapInstallHint}";
        }

        if (device is null)
        {
            return "未找到所选网卡。若网卡列表为空，请安装 Npcap 1.79+：https://npcap.com/#download";
        }

        try
        {
            device.OnPacketArrival += OnPacketArrival;
            device.Open(DeviceModes.Promiscuous, 1000);
            device.Filter = "udp port 53 or tcp port 53";
            device.StartCapture();
            _device = device;
            IsRunning = true;
            return "抓包通道已启动。";
        }
        catch (DllNotFoundException)
        {
            return NpcapInstallHint;
        }
        catch (Exception ex)
        {
            try
            {
                device.OnPacketArrival -= OnPacketArrival;
                device.Close();
            }
            catch
            {
            }

            return $"抓包启动失败：{ex.Message}；建议安装 Npcap 1.79+（https://npcap.com/#download）并勾选 WinPcap 兼容模式。";
        }
    }

    public void Stop()
    {
        if (!IsRunning)
        {
            return;
        }

        try
        {
            if (_device is not null)
            {
                _device.OnPacketArrival -= OnPacketArrival;
                _device.StopCapture();
                _device.Close();
                _device = null;
            }
        }
        catch
        {
        }
        finally
        {
            IsRunning = false;
        }
    }

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        RawCapture raw;
        try
        {
            raw = e.GetPacket();
        }
        catch
        {
            return;
        }

        var endpoint = TryExtractDnsEndpoint(raw.Data);
        if (endpoint is null)
        {
            return;
        }

        if (!endpoint.Value.IsDnsRequest)
        {
            return;
        }

        var dnsPayload = endpoint.Value.Payload;
        if (dnsPayload is null || dnsPayload.Length < 12)
        {
            return;
        }

        if (!TryParseDnsQuestion(dnsPayload, out var domain, out var queryType))
        {
            return;
        }

        var pid = endpoint.Value.Protocol == 17
            ? TryResolveUdpOwnerPid(endpoint.Value.LocalAddress, endpoint.Value.LocalPort)
            : TryResolveTcpOwnerPid(endpoint.Value.LocalAddress, endpoint.Value.LocalPort);

        DnsRecordCaptured?.Invoke(new DnsTelemetryRecord
        {
            TimestampUtc = DateTime.UtcNow,
            Domain = domain,
            QueryType = queryType,
            ResponseCode = string.Empty,
            ReturnedIps = string.Empty,
            ProcessId = pid,
            AttributionStatus = pid.HasValue ? AttributionStatus.Direct : AttributionStatus.Unavailable,
            AttributionConfidence = pid.HasValue ? 0.75 : 0,
            Source = "PCAP",
            RawSummary = pid.HasValue ? "PacketCapture+EndpointMap" : "PacketCapture"
        });
    }

    private static DnsEndpoint? TryExtractDnsEndpoint(byte[] data)
    {
        if (data.Length < 14)
        {
            return null;
        }

        var etherType = (data[12] << 8) | data[13];
        if (etherType != 0x0800)
        {
            return null;
        }

        var ipOffset = 14;
        if (data.Length < ipOffset + 20)
        {
            return null;
        }

        var versionAndHeader = data[ipOffset];
        var ipVersion = versionAndHeader >> 4;
        if (ipVersion != 4)
        {
            return null;
        }

        var ipHeaderLen = (versionAndHeader & 0x0F) * 4;
        if (data.Length < ipOffset + ipHeaderLen + 8)
        {
            return null;
        }

        var protocol = data[ipOffset + 9];
        var srcAddress = new IPAddress(new[] { data[ipOffset + 12], data[ipOffset + 13], data[ipOffset + 14], data[ipOffset + 15] });
        var dstAddress = new IPAddress(new[] { data[ipOffset + 16], data[ipOffset + 17], data[ipOffset + 18], data[ipOffset + 19] });

        var transportOffset = ipOffset + ipHeaderLen;

        if (protocol == 17)
        {
            var srcPort = (data[transportOffset] << 8) | data[transportOffset + 1];
            var dstPort = (data[transportOffset + 2] << 8) | data[transportOffset + 3];
            if (srcPort != 53 && dstPort != 53)
            {
                return null;
            }

            var udpPayloadOffset = transportOffset + 8;
            if (udpPayloadOffset >= data.Length)
            {
                return null;
            }

            return new DnsEndpoint(srcAddress, srcPort, dstAddress, dstPort, protocol, data.Skip(udpPayloadOffset).ToArray(), dstPort == 53);
        }

        if (protocol == 6)
        {
            if (data.Length < transportOffset + 20)
            {
                return null;
            }

            var srcPort = (data[transportOffset] << 8) | data[transportOffset + 1];
            var dstPort = (data[transportOffset + 2] << 8) | data[transportOffset + 3];
            if (srcPort != 53 && dstPort != 53)
            {
                return null;
            }

            var tcpHeaderLen = ((data[transportOffset + 12] >> 4) & 0x0F) * 4;
            var payloadOffset = transportOffset + tcpHeaderLen;
            if (payloadOffset + 2 > data.Length)
            {
                return null;
            }

            var dnsLen = (data[payloadOffset] << 8) | data[payloadOffset + 1];
            if (dnsLen <= 0 || payloadOffset + 2 + dnsLen > data.Length)
            {
                return null;
            }

            var payload = data.Skip(payloadOffset + 2).Take(dnsLen).ToArray();
            return new DnsEndpoint(srcAddress, srcPort, dstAddress, dstPort, protocol, payload, dstPort == 53);
        }

        return null;
    }

    private static bool TryParseDnsQuestion(byte[] payload, out string domain, out string queryType)
    {
        domain = string.Empty;
        queryType = string.Empty;

        if (payload.Length < 12)
        {
            return false;
        }

        var flags = (payload[2] << 8) | payload[3];
        var isResponse = (flags & 0x8000) != 0;
        var opcode = (flags >> 11) & 0x0F;
        if (isResponse || opcode != 0)
        {
            return false;
        }

        var qdCount = (payload[4] << 8) | payload[5];
        var anCount = (payload[6] << 8) | payload[7];
        var nsCount = (payload[8] << 8) | payload[9];
        if (qdCount != 1 || anCount != 0 || nsCount != 0)
        {
            return false;
        }

        var offset = 12;
        if (!TryReadDnsName(payload, ref offset, out domain))
        {
            return false;
        }

        if (offset + 3 >= payload.Length)
        {
            return false;
        }

        var type = (payload[offset] << 8) | payload[offset + 1];
        queryType = type switch
        {
            1 => "A",
            5 => "CNAME",
            12 => "PTR",
            16 => "TXT",
            28 => "AAAA",
            33 => "SRV",
            64 => "SVCB",
            65 => "HTTPS",
            _ => type.ToString()
        };

        domain = domain.Trim().TrimEnd('.').ToLowerInvariant();
        return IsLikelyDnsDomain(domain);
    }

    private static bool IsLikelyDnsDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain) || domain.Length > 253)
        {
            return false;
        }

        if (!domain.Contains('.'))
        {
            return false;
        }

        var labels = domain.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length < 2)
        {
            return false;
        }

        foreach (var label in labels)
        {
            if (label.Length is < 1 or > 63)
            {
                return false;
            }

            if (label[0] == '-' || label[^1] == '-')
            {
                return false;
            }

            foreach (var ch in label)
            {
                if (!(char.IsLetterOrDigit(ch) || ch == '-'))
                {
                    return false;
                }
            }
        }

        return true;
    }

    private static bool TryReadDnsName(byte[] payload, ref int offset, out string name)
    {
        name = string.Empty;
        var labels = new List<string>();
        var jumps = 0;
        var cursor = offset;
        var jumped = false;

        while (cursor < payload.Length)
        {
            if (jumps++ > 20)
            {
                return false;
            }

            var len = payload[cursor];
            if (len == 0)
            {
                cursor += 1;
                if (!jumped)
                {
                    offset = cursor;
                }

                name = string.Join('.', labels);
                return true;
            }

            if ((len & 0xC0) == 0xC0)
            {
                if (cursor + 1 >= payload.Length)
                {
                    return false;
                }

                var ptr = ((len & 0x3F) << 8) | payload[cursor + 1];
                if (ptr < 0 || ptr >= payload.Length)
                {
                    return false;
                }

                if (!jumped)
                {
                    offset = cursor + 2;
                }

                cursor = ptr;
                jumped = true;
                continue;
            }

            cursor += 1;
            if (cursor + len > payload.Length)
            {
                return false;
            }

            labels.Add(System.Text.Encoding.ASCII.GetString(payload, cursor, len));
            cursor += len;
        }

        return false;
    }

    private static int? TryResolveUdpOwnerPid(IPAddress localAddress, int localPort)
    {
        return TryResolveOwnerPid(QueryUdpTable, buffer => FindPidInUdpTable(buffer, localAddress, localPort));
    }

    private static int? TryResolveTcpOwnerPid(IPAddress localAddress, int localPort)
    {
        return TryResolveOwnerPid(QueryTcpTable, buffer => FindPidInTcpTable(buffer, localAddress, localPort));
    }

    private static int? TryResolveOwnerPid(IpTableQuery query, Func<IntPtr, int?> resolver)
    {
        var size = 0;
        var init = query(IntPtr.Zero, ref size);
        if (init != 122 && init != 0)
        {
            return null;
        }

        if (size <= 0)
        {
            return null;
        }

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var result = query(buffer, ref size);
            if (result != 0)
            {
                return null;
            }

            return resolver(buffer);
        }
        catch
        {
            return null;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private delegate uint IpTableQuery(IntPtr buffer, ref int size);

    private static uint QueryUdpTable(IntPtr buffer, ref int size)
    {
        return GetExtendedUdpTable(buffer, ref size, true, AfInet, UdpTableOwnerPid, 0);
    }

    private static uint QueryTcpTable(IntPtr buffer, ref int size)
    {
        return GetExtendedTcpTable(buffer, ref size, true, AfInet, TcpTableOwnerPidAll, 0);
    }

    private static int? FindPidInUdpTable(IntPtr tablePtr, IPAddress localAddress, int localPort)
    {
        var count = Marshal.ReadInt32(tablePtr);
        var rowSize = Marshal.SizeOf<MibUdpRowOwnerPid>();
        var rowPtr = IntPtr.Add(tablePtr, 4);

        int? fallbackPid = null;

        for (var i = 0; i < count; i++)
        {
            var row = Marshal.PtrToStructure<MibUdpRowOwnerPid>(rowPtr);
            var rowPort = ParsePort(row.LocalPort);
            if (rowPort == localPort)
            {
                if (IsLocalAddressMatch(row.LocalAddr, localAddress))
                {
                    return (int)row.OwningPid;
                }

                if (IsAnyAddress(row.LocalAddr) && fallbackPid is null)
                {
                    fallbackPid = (int)row.OwningPid;
                }
            }

            rowPtr = IntPtr.Add(rowPtr, rowSize);
        }

        return fallbackPid;
    }

    private static int? FindPidInTcpTable(IntPtr tablePtr, IPAddress localAddress, int localPort)
    {
        var count = Marshal.ReadInt32(tablePtr);
        var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
        var rowPtr = IntPtr.Add(tablePtr, 4);

        int? fallbackPid = null;

        for (var i = 0; i < count; i++)
        {
            var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPtr);
            var rowPort = ParsePort(row.LocalPort);
            if (rowPort == localPort)
            {
                if (IsLocalAddressMatch(row.LocalAddr, localAddress))
                {
                    return (int)row.OwningPid;
                }

                if (IsAnyAddress(row.LocalAddr) && fallbackPid is null)
                {
                    fallbackPid = (int)row.OwningPid;
                }
            }

            rowPtr = IntPtr.Add(rowPtr, rowSize);
        }

        return fallbackPid;
    }

    private static bool IsLocalAddressMatch(uint rowAddr, IPAddress target)
    {
        var rowBytes = BitConverter.GetBytes(rowAddr);
        var targetBytes = target.GetAddressBytes();

        if (rowBytes.SequenceEqual(targetBytes))
        {
            return true;
        }

        Array.Reverse(rowBytes);
        return rowBytes.SequenceEqual(targetBytes);
    }

    private static bool IsAnyAddress(uint rowAddr)
    {
        return rowAddr == 0;
    }

    private static ushort ParsePort(int tablePort)
    {
        var bytes = BitConverter.GetBytes(tablePort);
        var p1 = (ushort)((bytes[0] << 8) | bytes[1]);
        if (p1 > 0)
        {
            return p1;
        }

        return (ushort)((bytes[2] << 8) | bytes[3]);
    }

    private readonly record struct DnsEndpoint(
        IPAddress LocalAddress,
        int LocalPort,
        IPAddress RemoteAddress,
        int RemotePort,
        int Protocol,
        byte[] Payload,
        bool IsDnsRequest);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdpRowOwnerPid
    {
        public uint LocalAddr;
        public int LocalPort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public int LocalPort;
        public uint RemoteAddr;
        public int RemotePort;
        public uint OwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen, bool order, int ipVersion, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool order, int ipVersion, int tableClass, uint reserved);

    public void Dispose()
    {
        Stop();
    }
}
