// vtimidiports - Windows MIDI ports for the Virus TI (design-midi-ports.md, option A).
//
// Creates two Windows MIDI Services virtual devices and relays them to the Virus through the TI Revive broker (it is
// just another pipe client, vtiproto.h):
//   "Virus TI Synth (Revive)" <-> USB-MIDI cable 1 on MI_03 (the synth engine: keys, knobs, notes in)
//   "Virus TI MIDI (Revive)"  <-> USB-MIDI cable 0 on MI_03 (the Virus' MIDI In/Out DIN sockets)
// One device per port because Windows names a device's MIDI 1.0 ports "<device>", "<device> Gr 2", ... and refuses a
// runtime custom name for virtual devices; one group each gives exactly the names above.
// Synth -> PC: EP 0x85 packets are split by cable and sent as UMP. PC -> synth: UMP is packed into USB-MIDI packets
// and written to EP 0x05. The plug-in's own channel (MI_04, cables 2/3) is not touched.
//
// Needs Windows MIDI Services (in-box on Windows 11 25H2+); the Windows.Devices.Midi2 API ships app-local from the
// preview NuGet package until it is in-box. Log: %TEMP%\vtimidiports.log.
//
// Stop it with `vtimidiports --quit`, not by killing it: a killed process leaves its virtual devices registered and the
// Windows MIDI Service then hangs on the next MidiSession.Create until it is restarted (seen on 26H2, 2026-10-14, and
// by the TI Revive author in E090). --quit detaches the devices (RemoveMessageProcessingPlugin) before disconnecting.

using System.IO.Pipes;
using Windows.Devices.Midi2;
using Windows.Devices.Midi2.Enumeration;
using Windows.Devices.Midi2.Transports.Virtual;

namespace TiRevive.MidiPorts;

sealed class Port
{
    public required string Name;
    public required string ProductInstanceId;
    public required byte Cable;
    public MidiEndpointConnection? Conn;
    public MidiVirtualDevice? Device;
    public readonly List<byte> SysexIn = new();   // synth -> PC, without F0/F7
    public bool SysexInStarted;
    public readonly List<byte> SysexOut = new();  // PC -> synth, with F0/F7
}

static class Program
{
    const ushort MSG_HELLO = 1, MSG_WRITE = 2, MSG_RX = 0x81, MSG_STATE = 0x84;
    const byte EP_MI03_OUT = 0x05, EP_MI03_IN = 0x85;
    const int PROTO = 3;

    static readonly Port[] Ports = {
        new() { Name = "Virus TI Synth (Revive)", ProductInstanceId = "TIREVIVE_VIRUS_TI_SYNTH", Cable = 1 },
        new() { Name = "Virus TI MIDI (Revive)", ProductInstanceId = "TIREVIVE_VIRUS_TI_MIDI", Cable = 0 },
    };

    static StreamWriter? _log;
    static NamedPipeClientStream? _pipe;
    static readonly object _pipeLock = new();
    static readonly object _logLock = new();

    static void Log(string s)
    {
        lock (_logLock) {
            _log?.WriteLine($"{DateTime.Now:HH:mm:ss.fff} {s}");
            _log?.Flush();
        }
    }

    static int Main(string[] args)
    {
        _log = new StreamWriter(new FileStream(Path.Combine(Path.GetTempPath(), "vtimidiports.log"), FileMode.Append,
            FileAccess.Write, FileShare.ReadWrite | FileShare.Delete));
        using var quit = new EventWaitHandle(false, EventResetMode.ManualReset, @"Local\TiReviveMidiPorts.Quit");
        if (args.Length > 0 && args[0] == "--quit") { // ask a running instance to close its ports cleanly
            quit.Set();
            return 0;
        }
        using var single = new Mutex(true, @"Local\TiReviveMidiPorts", out bool first);
        if (!first) {
            Log("already running");
            return 0;
        }
        quit.Reset();
        Log($"start, pid {Environment.ProcessId}");
        try {
            if (!MidiApi.EnsureServiceAvailable()) {
                Log("Windows MIDI Service not available (needs Windows 11 25H2 or newer)");
                return 3;
            }
            using var session = MidiSession.Create("TI Revive MIDI ports");
            foreach (var port in Ports) {
                // the service can refuse right after it started; give it a few tries
                MidiVirtualDevice? device = null;
                for (int attempt = 0; device == null && attempt < 5; attempt++) {
                    if (attempt > 0)
                        Thread.Sleep(2000);
                    device = MidiVirtualDeviceManager.CreateVirtualDevice(DefineDevice(port));
                }
                if (device == null) {
                    Log($"could not create the virtual device {port.Name}");
                    return 4;
                }
                device.SuppressHandledMessages = true;
                var conn = session.CreateEndpointConnection(device.DeviceEndpointDeviceId);
                if (conn.AddMessageProcessingPlugin(device) != MidiMessageProcessingPluginAddResult.Succeeded) {
                    Log($"could not attach the virtual device {port.Name}");
                    return 5;
                }
                var p = port;
                conn.MessageReceived += (_, e) => FromApp(p, e.GetMessagePacket().GetAllWords());
                if (!conn.Open()) {
                    Log($"could not open the virtual device {port.Name}");
                    return 5;
                }
                port.Conn = conn;
                port.Device = device;
                Log($"port up: {port.Name}");
            }
            new Thread(BrokerLoop) { IsBackground = true }.Start();
            quit.WaitOne(); // vtimidiports --quit
            Log("quit requested, closing the ports");
            lock (_pipeLock) _pipe?.Dispose();
            foreach (var port in Ports) {
                // detach the virtual device first: without this the service keeps the device registered and hangs
                // on the next CreateVirtualDevice (the author's E090)
                if (port.Conn != null && port.Device != null)
                    port.Conn.RemoveMessageProcessingPlugin(port.Device.PluginId);
                if (port.Conn != null)
                    session.DisconnectEndpointConnection(port.Conn.ConnectionId);
                port.Conn = null;
                port.Device = null;
            }
            Log("ports closed");
            // Disposing the session after the disconnects hung the process on 26H2 (the ports were already gone).
            // Nothing is left to clean up, so leave without it.
            Environment.Exit(0);
            return 0;
        } catch (Exception ex) {
            Log("fatal: " + ex);
            return 1;
        }
    }

    static MidiVirtualDeviceCreationConfig DefineDevice(Port port)
    {
        var info = new MidiDeclaredEndpointInfo {
            Name = port.Name,
            ProductInstanceId = port.ProductInstanceId,
            SpecificationVersionMajor = 1,
            SpecificationVersionMinor = 1,
            SupportsMidi10Protocol = true,
            SupportsMidi20Protocol = false,
            SupportsReceivingJitterReductionTimestamps = false,
            SupportsSendingJitterReductionTimestamps = false,
            HasStaticFunctionBlocks = true,
        };
        var identity = new MidiDeclaredDeviceIdentity(0x00, 0x20, 0x33, // Access Music manufacturer id
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
        var user = new MidiEndpointUserSuppliedInfo { Name = port.Name, Description = "Access Virus TI through TI Revive" };
        var config = new MidiVirtualDeviceCreationConfig(port.Name, "Access Virus TI through TI Revive", "TI Revive",
            info, identity, user);
        config.FunctionBlocks.Add(new MidiFunctionBlock {
            Number = 0,
            Name = port.Name,
            IsActive = true,
            UIHint = MidiFunctionBlockUIHint.Bidirectional,
            FirstGroup = new MidiGroup(0),
            GroupCount = 1,
            Direction = MidiFunctionBlockDirection.Bidirectional,
            RepresentsMidi10Connection = MidiFunctionBlockRepresentsMidi10Connection.YesBandwidthUnrestricted,
            MaxSystemExclusive8Streams = 0,
            MidiCIMessageVersionFormat = 0,
        });
        return config;
    }

    // ---- broker side ------------------------------------------------------------------------------------------------

    static void BrokerLoop()
    {
        for (;;) {
            try {
                using var pipe = new NamedPipeClientStream(".", "vtibroker", PipeDirection.InOut, PipeOptions.Asynchronous);
                // Asynchronous = FILE_FLAG_OVERLAPPED: without it Windows serialises I/O on the handle, so the reader
                // thread's pending Read blocks every Write (nothing ever reached the Virus; TI Revive E047)
                pipe.Connect(2000);
                lock (_pipeLock) _pipe = pipe;
                Send(MSG_HELLO, BitConverter.GetBytes(PROTO));
                Log("connected to the broker");
                var hdr = new byte[4];
                var buf = new byte[4096];
                for (;;) {
                    ReadExact(pipe, hdr, 4);
                    int type = hdr[0] | hdr[1] << 8, len = hdr[2] | hdr[3] << 8;
                    ReadExact(pipe, buf, len);
                    if (type == MSG_STATE && len >= 4)
                        Log($"broker: device {(buf[0] != 0 ? "connected" : "disconnected")}");
                    else if (type == MSG_RX && len >= 1 && buf[0] == EP_MI03_IN)
                        FromSynth(buf, 1, len - 1);
                }
            } catch (TimeoutException) {
                // broker not running: it normally starts on demand with the plug-in; start it so the ports also work
                // without the plug-in (as the author's prototype did, E090)
                StartBroker();
            } catch (Exception ex) {
                Log("broker connection lost: " + ex.Message);
            }
            lock (_pipeLock) _pipe = null;
            Thread.Sleep(2000);
        }
    }

    static DateTime _lastBrokerStart = DateTime.MinValue;

    static void StartBroker()
    {
        if (DateTime.Now - _lastBrokerStart < TimeSpan.FromSeconds(30))
            return;
        _lastBrokerStart = DateTime.Now;
        var dir = Microsoft.Win32.Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\TI Revive", "InstallDir", null) as string;
        var exe = dir == null ? null : Path.Combine(dir, "vtibroker.exe");
        if (exe == null || !File.Exists(exe)) {
            Log("vtibroker.exe not found (TI Revive not installed?)");
            return;
        }
        try {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true });
            Log("started vtibroker");
        } catch (Exception ex) {
            Log("could not start vtibroker: " + ex.Message);
        }
    }

    static void ReadExact(Stream s, byte[] b, int n)
    {
        for (int o = 0; o < n;) {
            int r = s.Read(b, o, n - o);
            if (r <= 0)
                throw new EndOfStreamException("broker closed the pipe");
            o += r;
        }
    }

    static void Send(ushort type, byte[] payload)
    {
        var m = new byte[4 + payload.Length];
        m[0] = (byte)type; m[1] = (byte)(type >> 8);
        m[2] = (byte)payload.Length; m[3] = (byte)(payload.Length >> 8);
        payload.CopyTo(m, 4);
        lock (_pipeLock) {
            if (_pipe == null)
                return;
            _pipe.Write(m, 0, m.Length);
            _pipe.Flush();
        }
    }

    // ---- synth -> PC ------------------------------------------------------------------------------------------------

    static void FromSynth(byte[] b, int off, int len)
    {
        for (int i = off; i + 3 < off + len; i += 4) {
            int cable = b[i] >> 4, cin = b[i] & 0x0F;
            byte d0 = b[i + 1], d1 = b[i + 2], d2 = b[i + 3];
            var port = Array.Find(Ports, p => p.Cable == cable);
            if (port == null || (b[i] == 0 && d0 == 0))
                continue;
            switch (cin) {
            case 0x8: case 0x9: case 0xA: case 0xB: case 0xE: // 3-byte channel voice
                SendUmp(port, 0x20000000u | (uint)d0 << 16 | (uint)d1 << 8 | d2);
                break;
            case 0xC: case 0xD: // 2-byte channel voice
                SendUmp(port, 0x20000000u | (uint)d0 << 16 | (uint)d1 << 8);
                break;
            case 0x4: // SysEx start or continue, 3 bytes
                SysexBytes(port, d0, d1, d2);
                break;
            case 0x5: case 0x6: case 0x7: // SysEx ends with 1/2/3 bytes, or a 1-byte system common message (CIN 5)
                if (cin == 0x5 && d0 != 0xF7 && !port.SysexInStarted) {
                    SystemMessage(port, d0, 0, 0);
                    break;
                }
                SysexBytes(port, cin == 5 ? new[] { d0 } : cin == 6 ? new[] { d0, d1 } : new[] { d0, d1, d2 });
                break;
            case 0x2: case 0x3: // 2/3-byte system common
                SystemMessage(port, d0, d1, cin == 3 ? d2 : (byte)0);
                break;
            case 0xF: // single byte (real time)
                if (d0 != 0xFE) // Active Sensing stays between the broker and the synth
                    SystemMessage(port, d0, 0, 0);
                break;
            }
        }
    }

    static void SystemMessage(Port port, byte s, byte a, byte b) =>
        SendUmp(port, 0x10000000u | (uint)s << 16 | (uint)a << 8 | b);

    static void SysexBytes(Port port, params byte[] bytes)
    {
        foreach (byte x in bytes) {
            if (x == 0xF0) {
                port.SysexIn.Clear();
                port.SysexInStarted = true;
            } else if (x == 0xF7) {
                if (port.SysexInStarted)
                    SendSysex7(port, port.SysexIn);
                port.SysexIn.Clear();
                port.SysexInStarted = false;
            } else if (port.SysexInStarted) {
                port.SysexIn.Add(x);
            }
        }
    }

    // UMP type 3 (7-bit SysEx), up to 6 data bytes per 64-bit packet, F0/F7 not included.
    static void SendSysex7(Port port, List<byte> data)
    {
        int n = data.Count, pos = 0;
        do {
            int count = Math.Min(6, n - pos);
            int status = n <= 6 ? 0 : pos == 0 ? 1 : pos + count >= n ? 3 : 2;
            var p = new byte[8];
            p[0] = 0x30;
            p[1] = (byte)(status << 4 | count);
            for (int k = 0; k < count; k++)
                p[2 + k] = data[pos + k];
            uint w0 = (uint)(p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]);
            uint w1 = (uint)(p[4] << 24 | p[5] << 16 | p[6] << 8 | p[7]);
            port.Conn?.SendSingleMessageWords(MidiClock.TimestampConstantSendImmediately, w0, w1);
            pos += count;
        } while (pos < n);
    }

    static void SendUmp(Port port, uint w0) =>
        port.Conn?.SendSingleMessageWords(MidiClock.TimestampConstantSendImmediately, w0);

    // ---- PC -> synth ------------------------------------------------------------------------------------------------

    static void FromApp(Port port, IList<uint> words)
    {
        if (words.Count == 0)
            return;
        uint w0 = words[0];
        int mt = (int)(w0 >> 28);
        byte cable = port.Cable;
        byte s = (byte)(w0 >> 16), a = (byte)(w0 >> 8), b = (byte)w0;
        var outp = new List<byte>();
        switch (mt) {
        case 0x2: { // MIDI 1.0 channel voice
            int cin = s >> 4;
            outp.AddRange(new[] { (byte)(cable << 4 | cin), s, a, (cin == 0xC || cin == 0xD) ? (byte)0 : b });
            break;
        }
        case 0x1: { // system common / real time
            int cin = s switch { 0xF2 => 0x3, 0xF1 or 0xF3 => 0x2, 0xF6 => 0x5, _ => 0xF };
            outp.AddRange(new[] { (byte)(cable << 4 | cin), s, cin == 0x2 || cin == 0x3 ? a : (byte)0, cin == 0x3 ? b : (byte)0 });
            break;
        }
        case 0x3: { // 7-bit SysEx
            if (words.Count < 2)
                return;
            int status = (int)(w0 >> 20) & 0x0F, count = (int)(w0 >> 16) & 0x0F;
            uint w1 = words[1];
            byte[] d = { a, b, (byte)(w1 >> 24), (byte)(w1 >> 16), (byte)(w1 >> 8), (byte)w1 };
            var acc = port.SysexOut;
            if (status == 0 || status == 1) {
                acc.Clear();
                acc.Add(0xF0);
            }
            for (int k = 0; k < Math.Min(count, 6); k++)
                acc.Add(d[k]);
            if (status == 0 || status == 3) {
                acc.Add(0xF7);
                PackSysex(cable, acc, outp);
                acc.Clear();
            }
            break;
        }
        default: // MIDI 2.0 and others: the Virus speaks MIDI 1.0 only
            return;
        }
        if (outp.Count > 0)
            WriteToSynth(outp);
    }

    static void PackSysex(byte cable, List<byte> m, List<byte> outp)
    {
        int i = 0;
        while (m.Count - i > 3) {
            outp.AddRange(new[] { (byte)(cable << 4 | 0x4), m[i], m[i + 1], m[i + 2] });
            i += 3;
        }
        int rest = m.Count - i; // 1..3, the last one is F7
        outp.Add((byte)(cable << 4 | (0x4 + rest)));
        for (int k = 0; k < 3; k++)
            outp.Add(k < rest ? m[i + k] : (byte)0);
    }

    static void WriteToSynth(List<byte> packets)
    {
        for (int i = 0; i < packets.Count; i += 64 * 4) { // keep writes small
            int n = Math.Min(64 * 4, packets.Count - i);
            var payload = new byte[1 + n];
            payload[0] = EP_MI03_OUT;
            packets.CopyTo(i, payload, 1, n);
            Send(MSG_WRITE, payload);
        }
    }
}
