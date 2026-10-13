// vtimidiports - Windows MIDI ports for the Virus TI (design-midi-ports.md, option A).
//
// Creates a Windows MIDI Services virtual device "Virus TI" with two MIDI 1.0 function blocks and relays them to the
// Virus through the TI Revive broker (it is just another pipe client, vtiproto.h):
//   group 0 "Virus TI Synth" <-> USB-MIDI cable 1 on MI_03 (the synth engine: keys, knobs, notes in)
//   group 1 "Virus TI MIDI"  <-> USB-MIDI cable 0 on MI_03 (the Virus' MIDI In/Out DIN sockets)
// Synth -> PC: EP 0x85 packets are split by cable and sent as UMP. PC -> synth: UMP is packed into USB-MIDI packets
// and written to EP 0x05. The plug-in's own channel (MI_04, cables 2/3) is not touched.
//
// Needs the Windows MIDI Services runtime (winget Microsoft.MIDI.SDK). Log: %TEMP%\vtimidiports.log.

using System.IO.Pipes;
using Windows.Devices.Midi2;
using Windows.Devices.Midi2.Enumeration;
using Windows.Devices.Midi2.Transports.Virtual;

namespace TiRevive.MidiPorts;

static class Program
{
    const ushort MSG_HELLO = 1, MSG_WRITE = 2, MSG_RX = 0x81, MSG_STATE = 0x84;
    const byte EP_MI03_OUT = 0x05, EP_MI03_IN = 0x85;
    const int PROTO = 3;

    static readonly string[] BlockNames = { "Virus TI Synth", "Virus TI MIDI" };
    static readonly byte[] GroupToCable = { 1, 0 };

    static StreamWriter? _log;
    static NamedPipeClientStream? _pipe;
    static readonly object _pipeLock = new();
    static MidiEndpointConnection? _conn;
    static readonly SysexIn[] _sysexIn = { new(), new() };   // per cable 0/1, synth -> PC
    static readonly List<byte>[] _sysexOut = { new(), new() }; // per group 0/1, PC -> synth

    static void Log(string s)
    {
        lock (_pipeLock) {
            _log?.WriteLine($"{DateTime.Now:HH:mm:ss.fff} {s}");
            _log?.Flush();
        }
    }

    static int Main(string[] args)
    {
        _log = new StreamWriter(Path.Combine(Path.GetTempPath(), "vtimidiports.log"), append: true);
        using var single = new Mutex(true, @"Local\TiReviveMidiPorts", out bool first);
        if (!first) {
            Log("already running");
            return 0;
        }
        try {
            if (!MidiApi.EnsureServiceAvailable()) {
                Log("Windows MIDI Service not available (needs Windows 11 25H2 or newer)");
                return 3;
            }
            using var session = MidiSession.Create("TI Revive MIDI ports");
            var device = MidiVirtualDeviceManager.CreateVirtualDevice(DefineDevice());
            if (device == null) {
                Log("could not create the virtual device");
                return 4;
            }
            device.SuppressHandledMessages = true;
            _conn = session.CreateEndpointConnection(device.DeviceEndpointDeviceId);
            if (_conn.AddMessageProcessingPlugin(device) != MidiMessageProcessingPluginAddResult.Succeeded) {
                Log("could not attach the virtual device to the connection");
                return 5;
            }
            _conn.MessageReceived += (_, e) => FromApp(e.GetMessagePacket().GetAllWords());
            if (!_conn.Open()) {
                Log("could not open the virtual device connection");
                return 5;
            }
            Log($"virtual device up: {device.DeviceEndpointDeviceId}");
            BrokerLoop(); // runs until the process is ended
            return 0;
        } catch (Exception ex) {
            Log("fatal: " + ex);
            return 1;
        }
    }

    static MidiVirtualDeviceCreationConfig DefineDevice()
    {
        var info = new MidiDeclaredEndpointInfo {
            Name = "Virus TI",
            ProductInstanceId = "TIREVIVE_VIRUS_TI",
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
        var user = new MidiEndpointUserSuppliedInfo { Name = "Virus TI", Description = "Access Virus TI through TI Revive" };
        var config = new MidiVirtualDeviceCreationConfig("Virus TI", "Access Virus TI through TI Revive", "TI Revive",
            info, identity, user);
        for (int g = 0; g < BlockNames.Length; g++) {
            config.FunctionBlocks.Add(new MidiFunctionBlock {
                Number = (byte)g,
                Name = BlockNames[g],
                IsActive = true,
                UIHint = MidiFunctionBlockUIHint.Bidirectional,
                FirstGroup = new MidiGroup((byte)g),
                GroupCount = 1,
                Direction = MidiFunctionBlockDirection.Bidirectional,
                RepresentsMidi10Connection = MidiFunctionBlockRepresentsMidi10Connection.YesBandwidthRestricted,
                MaxSystemExclusive8Streams = 0,
                MidiCIMessageVersionFormat = 0,
            });
        }
        return config;
    }

    // ---- broker side ------------------------------------------------------------------------------------------------

    static void BrokerLoop()
    {
        for (;;) {
            try {
                using var pipe = new NamedPipeClientStream(".", "vtibroker", PipeDirection.InOut);
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
                // broker not running yet: it starts on demand; keep trying
            } catch (Exception ex) {
                Log("broker connection lost: " + ex.Message);
            }
            lock (_pipeLock) _pipe = null;
            Thread.Sleep(2000);
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

    sealed class SysexIn { public readonly List<byte> Data = new(); public bool Started; }

    static void FromSynth(byte[] b, int off, int len)
    {
        for (int i = off; i + 3 < off + len; i += 4) {
            int cable = b[i] >> 4, cin = b[i] & 0x0F;
            byte d0 = b[i + 1], d1 = b[i + 2], d2 = b[i + 3];
            if (cable > 1 || (b[i] == 0 && d0 == 0))
                continue;
            int group = Array.IndexOf(GroupToCable, (byte)cable);
            switch (cin) {
            case 0x8: case 0x9: case 0xA: case 0xB: case 0xE: // 3-byte channel voice
                SendUmp(0x20000000u | (uint)group << 24 | (uint)d0 << 16 | (uint)d1 << 8 | d2);
                break;
            case 0xC: case 0xD: // 2-byte channel voice
                SendUmp(0x20000000u | (uint)group << 24 | (uint)d0 << 16 | (uint)d1 << 8);
                break;
            case 0x4: // SysEx start or continue, 3 bytes
                SysexBytes(cable, group, d0, d1, d2);
                break;
            case 0x5: case 0x6: case 0x7: // SysEx ends with 1/2/3 bytes, or a 1-byte system common message (CIN 5)
                if (cin == 0x5 && d0 != 0xF7 && !_sysexIn[cable].Started) {
                    SystemMessage(group, d0, 0, 0);
                    break;
                }
                SysexBytes(cable, group, cin == 5 ? new[] { d0 } : cin == 6 ? new[] { d0, d1 } : new[] { d0, d1, d2 });
                break;
            case 0x2: case 0x3: // 2/3-byte system common
                SystemMessage(group, d0, d1, cin == 3 ? d2 : (byte)0);
                break;
            case 0xF: // single byte (real time)
                if (d0 != 0xFE) // Active Sensing stays between the broker and the synth
                    SystemMessage(group, d0, 0, 0);
                break;
            }
        }
    }

    static void SystemMessage(int group, byte s, byte a, byte b) =>
        SendUmp(0x10000000u | (uint)group << 24 | (uint)s << 16 | (uint)a << 8 | b);

    static void SysexBytes(int cable, int group, params byte[] bytes)
    {
        var st = _sysexIn[cable];
        foreach (byte x in bytes) {
            if (x == 0xF0) {
                st.Data.Clear();
                st.Started = true;
            } else if (x == 0xF7) {
                if (st.Started)
                    SendSysex7(group, st.Data);
                st.Data.Clear();
                st.Started = false;
            } else if (st.Started) {
                st.Data.Add(x);
            }
        }
    }

    // UMP type 3 (7-bit SysEx), up to 6 data bytes per 64-bit packet, F0/F7 not included.
    static void SendSysex7(int group, List<byte> data)
    {
        int n = data.Count, pos = 0;
        do {
            int count = Math.Min(6, n - pos);
            int status = n <= 6 ? 0 : pos == 0 ? 1 : pos + count >= n ? 3 : 2;
            var p = new byte[8];
            p[0] = (byte)(0x30 | group);
            p[1] = (byte)(status << 4 | count);
            for (int k = 0; k < count; k++)
                p[2 + k] = data[pos + k];
            uint w0 = (uint)(p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]);
            uint w1 = (uint)(p[4] << 24 | p[5] << 16 | p[6] << 8 | p[7]);
            _conn?.SendSingleMessageWords(MidiClock.TimestampConstantSendImmediately, w0, w1);
            pos += count;
        } while (pos < n);
    }

    static void SendUmp(uint w0) => _conn?.SendSingleMessageWords(MidiClock.TimestampConstantSendImmediately, w0);

    // ---- PC -> synth ------------------------------------------------------------------------------------------------

    static void FromApp(IList<uint> words)
    {
        if (words.Count == 0)
            return;
        uint w0 = words[0];
        int mt = (int)(w0 >> 28), group = (int)(w0 >> 24) & 0x0F;
        if (group >= GroupToCable.Length)
            return;
        byte cable = GroupToCable[group];
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
            var acc = _sysexOut[group];
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
