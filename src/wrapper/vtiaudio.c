// vtiaudio.c - plugin-integrated audio for the IOCTL emulation (milestone M4, findings E051-E055, spec §11.3/11.4).
//
// With VirusUSB.sys the plugin gets the Virus audio from a driver-filled "AudioSM" region that the driver maps
// into the process (IOCTL 0x220010), and its audio thread is clocked by a buffer-switch event (0x2200E4,
// "threaded" variant). Without the Access driver the audio interfaces are driven by Windows' inbox USB audio
// class driver (E045), so here:
//   - 0x220010 returns a region we allocate with the driver's layout,
//   - a capture thread reads the "Virus TI" recording endpoint with WASAPI (shared mode, all endpoint channels,
//     Windows converts to 44.1 kHz / 16-bit) and writes them as int16 << 16 in device order, advancing the counter,
//   - after every packet it consumes the plugin's output ring (+0x810BC = +0x81028) and signals the plugin's
//     buffer-switch event (the driver did this in its isochronous completion).
// If no Virus recording endpoint exists, a 5 ms timer provides the clock with silence.
// A second thread keeps the Virus playback endpoint streaming (silence), as the driver did (E072).
// Preferred over all of this: the broker streams the USB audio endpoints on WinUSB (vtiusbaudio.c, E075) into a
// shared ring (vtiaudioshm.h) that this process follows; with an older broker the plug-in process streams them
// itself (same code).
#include <windows.h>
#include <mmsystem.h>
#include <initguid.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <functiondiscoverykeys_devpkey.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>
#include "vtiusbaudio.h"
#include "../broker/vticore.h"
#include "../broker/vtiaudioshm.h"
#include <stdio.h>

void vtiemu_log(const char *fmt, ...); // vtiemu.c

#define SM_SAMPLES 0x20000
#define IN_REGION 0x810C0
#define IN_CHANNELS 6
#define RATE 44100

static uint8_t *g_in;               // input region B (spec §11.4)
static volatile uint8_t *g_out_sm;  // plugin's output AudioSM (0x220030 buffer)
static volatile HANDLE g_bs_event;  // plugin's buffer-switch event (0x2200E4, threaded)
static volatile LONG g_running;
static HANDLE g_thread, g_render_thread;

#define S(p) ((p) + 8) // AudioSM struct inside the input region
#define U32(p, off) (*(volatile uint32_t *)((p) + (off)))

static void init_region(uint8_t *b)
{
    memset(b, 0, IN_REGION);
    *(uint64_t *)b = 0x001FFDD8; // magic, = IOCTL 0x22004C value (E055)
    uint8_t *s = S(b);
    U32(s, 0x80000) = IN_CHANNELS;
    U32(s, 0x80004) = SM_SAMPLES / IN_CHANNELS;
    U32(s, 0x81030) = RATE;
    U32(s, 0x810B0) = RATE / 4;
    U32(s, 0x810B4) = 1;
    // B+0x81020 owner = 0 and B+0x81028 exclusive = 0: every plugin instance outputs the audio
}

// Append n frames of `ch` interleaved int16 channels (or silence if pcm == NULL) in device channel order and
// run the clock for the plugin. The Virus sends 6 channels (USB1-3 L/R); the plugin's "USB1" is device channel
// pair 2/3 (E056), so all channels are copied 1:1 like the driver did.
#ifdef VTIAUDIO_FORWARD_OUTPUT
// ASIO build (vtiasio.c): what the original ASIO driver wrote into its output AudioSM since the last delivery goes
// to the broker's output ring (vtiaudioshm.h) and from there to the synth. The plug-in's output ring (side chain,
// "2 Outs / No Input") is not forwarded.
static vti_audio_shm *g_out_shm; // writable view, set by broker_audio()

static int16_t to16(int32_t s24)
{
    int32_t v = s24 >> 8;
    return (int16_t)(v > 32767 ? 32767 : v < -32768 ? -32768 : v);
}

static void forward_output(volatile uint8_t *o)
{
    static uint32_t pos;
    static int valid;
    vti_audio_shm *shm = g_out_shm;
    uint32_t ch = U32(o, 0x80000), maxf = U32(o, 0x80004), wr = U32(o, 0x81028);
    if (!shm || !ch || ch > 32 || !maxf)
        return;
    uint32_t n = wr - pos;
    if (!valid || n > maxf) { // first sight or out of step: start at the writer
        pos = wr;
        valid = 1;
        return;
    }
    const int32_t *ring = (const int32_t *)o;
    int64_t w = shm->out_write;
    for (uint32_t i = 0; i < n; i++) {
        const int32_t *f = ring + ((pos + i) % maxf) * ch;
        int16_t *d = &shm->out[((w + i) & (VTI_AUDIO_RING - 1)) * VTI_AUDIO_OUT_CH];
        // the ASIO driver stores 24-bit samples in its output AudioSM (int32 >> 8; a -12 dBFS test tone arrived 256x
        // too quiet with >> 16, E083); the input direction is int16 << 16
        d[0] = to16(f[0]);
        d[1] = to16(ch > 1 ? f[1] : f[0]);
    }
    InterlockedExchange64((volatile LONG64 *)&shm->out_write, w + n); // publishes the frames written above
    pos = wr;
}
#endif

static void push_frames(const int16_t *pcm, uint32_t ch, uint32_t n)
{
    uint8_t *s = S(g_in);
    uint32_t maxf = U32(s, 0x80004), wr = U32(s, 0x81028);
    int32_t *ring = (int32_t *)s;
    for (uint32_t i = 0; i < n; i++) {
        int32_t *f = ring + ((wr + i) % maxf) * IN_CHANNELS;
        for (uint32_t c = 0; c < IN_CHANNELS; c++)
            f[c] = pcm && c < ch ? (int32_t)pcm[ch * i + c] << 16 : 0;
    }
    U32(s, 0x81028) = wr + n;
    // Buffer switch like VirusUSB.sys (FUN_f1025370, E051): once per +0x810B8 frames of device time (the plugin's
    // buffer size: 64..2048), not once per capture packet; the first one stamps +0x810C8 with the QPC time
    // ("mTriggerTime", which the plugin's AudioSM code checks).
    volatile uint8_t *o = g_out_sm;
    HANDLE ev = g_bs_event;
    uint32_t thr = o ? U32(o, 0x810B8) : 0;
#ifndef VTIAUDIO_BS_PER_BUFFER // fix1 experiment (E069): per-buffer switching + trigger time made timing worse
    thr = 0;
#endif
    if (!thr || thr > 0x8000) { // no output ring (yet): one switch per packet
#ifdef VTIAUDIO_FORWARD_OUTPUT
        if (o)
            forward_output(o);
#endif
        if (o)
            U32(o, 0x810BC) = U32(o, 0x81028);
        if (ev)
            SetEvent(ev);
        return;
    }
    static uint32_t since;
    for (since += n; since >= thr; since -= thr) {
        U32(o, 0x810BC) = U32(o, 0x81028); // the device "consumed" what the plugin produced towards it
        if (!*(volatile uint64_t *)(o + 0x810C8)) {
            LARGE_INTEGER q;
            QueryPerformanceCounter(&q);
            *(volatile uint64_t *)(o + 0x810C8) = (uint64_t)q.QuadPart;
        }
        if (ev)
            SetEvent(ev);
    }
}

// Diagnostics (E074): the synth's sync reports, the offset of the plugin's F5 timestamps (14-bit sample time) to our
// input frame counter (= synth position as the plugin sees it), and the output ring counters, logged every 10 s.
extern volatile LONG g_sync_reports; // vtiemu.c
static volatile LONG g_f5_min = 0x7FFFFFFF, g_f5_max = -0x7FFFFFFF, g_f5_n;

void vtiaudio_f5(uint32_t ts14)
{
    if (!g_in)
        return;
    int32_t d = (int32_t)((ts14 - U32(S(g_in), 0x81028)) & 0x3FFF);
    if (d >= 0x2000)
        d -= 0x4000;
    if (d < g_f5_min)
        g_f5_min = d;
    if (d > g_f5_max)
        g_f5_max = d;
    g_f5_n++;
}

static void diag(void)
{
    static LONG last_reports;
    LONG r = g_sync_reports;
    volatile uint8_t *o = g_out_sm;
    vtiemu_log("diag: in %u, sync reports +%ld (total %ld), F5 n %ld offset %ld..%ld, out wr %u rd %u thr %u",
               U32(S(g_in), 0x81028), r - last_reports, r, g_f5_n, g_f5_n ? g_f5_min : 0, g_f5_n ? g_f5_max : 0,
               o ? U32(o, 0x81028) : 0, o ? U32(o, 0x810BC) : 0, o ? U32(o, 0x810B8) : 0);
    last_reports = r;
    g_f5_min = 0x7FFFFFFF;
    g_f5_max = -0x7FFFFFFF;
    g_f5_n = 0;
}

// GUIDs spelled out: mingw headers declare but do not always define them.
static const CLSID CLSID_MMDevEnum = {0xBCDE0395, 0xE52F, 0x467C, {0x8E, 0x3D, 0xC4, 0x57, 0x92, 0x91, 0x69, 0x2E}};
static const IID IID_MMDevEnum = {0xA95664D2, 0x9614, 0x4F35, {0xA7, 0x46, 0xDE, 0x8D, 0xB6, 0x36, 0x17, 0xE6}};
static const IID IID_AudioClient = {0x1CB9AD4C, 0xDBFA, 0x4C32, {0xB1, 0x78, 0xC2, 0xF5, 0x68, 0xA7, 0x03, 0xB2}};
static const IID IID_AudioCapture = {0xC8ADBD64, 0xE71E, 0x48A0, {0xA4, 0xDE, 0x18, 0x5C, 0x39, 0x5C, 0xD3, 0x17}};
static const IID IID_AudioRender = {0xF294ACFC, 0x3146, 0x4483, {0xA7, 0xBF, 0xAD, 0xDC, 0xA7, 0xC2, 0x60, 0xE2}};

// First active endpoint of the given direction (eCapture / eRender) whose friendly name contains "Virus TI".
static IMMDevice *find_virus(EDataFlow flow)
{
    IMMDeviceEnumerator *en = NULL;
    IMMDeviceCollection *col = NULL;
    IMMDevice *found = NULL;
    if (FAILED(CoCreateInstance(&CLSID_MMDevEnum, NULL, CLSCTX_ALL, &IID_MMDevEnum, (void **)&en)))
        return NULL;
    if (SUCCEEDED(en->lpVtbl->EnumAudioEndpoints(en, flow, DEVICE_STATE_ACTIVE, &col))) {
        UINT n = 0;
        col->lpVtbl->GetCount(col, &n);
        for (UINT i = 0; i < n && !found; i++) {
            IMMDevice *d = NULL;
            IPropertyStore *ps = NULL;
            if (FAILED(col->lpVtbl->Item(col, i, &d)))
                continue;
            if (SUCCEEDED(d->lpVtbl->OpenPropertyStore(d, STGM_READ, &ps))) {
                PROPVARIANT v;
                PropVariantInit(&v);
                if (SUCCEEDED(ps->lpVtbl->GetValue(ps, &PKEY_Device_FriendlyName, &v)) && v.vt == VT_LPWSTR &&
                    wcsstr(v.pwszVal, L"Virus TI")) {
                    char name[256];
                    WideCharToMultiByte(CP_UTF8, 0, v.pwszVal, -1, name, sizeof name, NULL, NULL);
                    vtiemu_log("audio: %s endpoint \"%s\"", flow == eRender ? "render" : "capture", name);
                    found = d;
                    d = NULL;
                }
                PropVariantClear(&v);
                ps->lpVtbl->Release(ps);
            }
            if (d)
                d->lpVtbl->Release(d);
        }
        col->lpVtbl->Release(col);
    }
    en->lpVtbl->Release(en);
    return found;
}

static void silence_clock(void)
{
    while (g_running) { // ~5 ms periods
        push_frames(NULL, 0, 221);
        Sleep(5);
    }
}

static DWORD WINAPI render_thread(LPVOID unused);

// Callback timing of the USB path (diag): largest gap between two deliveries and frames per delivery.
static double g_gap_max;
static uint32_t g_calls, g_fmax;

static void usb_in(const int16_t *pcm, uint32_t frames, void *user)
{
    (void)user;
    static LARGE_INTEGER f, last;
    static uint64_t total, next_diag = RATE * 10;
    LARGE_INTEGER t;
    if (!f.QuadPart)
        QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t);
    if (last.QuadPart) {
        double gap = (double)(t.QuadPart - last.QuadPart) * 1000.0 / f.QuadPart;
        if (gap > g_gap_max)
            g_gap_max = gap;
        if (gap > 15) { // late delivery: with wall-clock time, to correlate with the broker log (E128)
            SYSTEMTIME st;
            GetLocalTime(&st);
            vtiemu_log("audio: delivery late, %.1f ms after the previous one (%02u:%02u:%02u.%03u)", gap, st.wHour,
                       st.wMinute, st.wSecond, st.wMilliseconds);
        }
    }
    last = t;
    g_calls++;
    if (frames > g_fmax)
        g_fmax = frames;
    push_frames(pcm, IN_CHANNELS, frames);
    if ((total += frames) >= next_diag) {
        vtiemu_log("diag: usb %u calls, max gap %.1f ms, max %u frames/call", g_calls, g_gap_max, g_fmax);
        g_gap_max = 0;
        g_calls = g_fmax = 0;
        diag();
        next_diag += RATE * 10;
    }
}

vti *vtiemu_dev(void); // vtiemu.c: the broker connection (reconnects / starts the broker if needed)

// Follow the broker's shared input ring (vtiaudioshm.h). Returns 1 after a normal stop, 0 if the broker has no
// WinUSB audio function, -1 if broker audio is not available (no broker connection, broker older than protocol 2).
static int broker_audio(void)
{
    char name[64];
    snprintf(name, sizeof name, "Local\\vtiaudio_%lu_%lu", GetCurrentProcessId(), GetTickCount());
    HANDLE ev = CreateEventA(NULL, FALSE, FALSE, name);
    vti *v = vtiemu_dev();
    int r = v && ev ? vti_audio(v, 1, name) : -1;
#ifdef VTIAUDIO_FORWARD_OUTPUT
    DWORD access = FILE_MAP_READ | FILE_MAP_WRITE; // the ASIO copy also writes the output ring
#else
    DWORD access = FILE_MAP_READ;
#endif
    HANDLE map = r == 1 ? OpenFileMappingA(access, FALSE, VTI_AUDIO_SHM_NAME) : NULL;
    const vti_audio_shm *shm = map ? MapViewOfFile(map, access, 0, 0, sizeof(vti_audio_shm)) : NULL;
    if (!shm || shm->magic != VTI_AUDIO_MAGIC || shm->version != VTI_AUDIO_VERSION ||
        shm->ring_frames != VTI_AUDIO_RING || shm->in_ch != IN_CHANNELS) {
        vtiemu_log("audio: no broker audio (%d)", r);
        if (r == 1)
            vti_audio(v, 0, NULL);
        if (shm)
            UnmapViewOfFile(shm);
        if (map)
            CloseHandle(map);
        if (ev)
            CloseHandle(ev);
        return r == 0 ? 0 : -1;
    }
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
#ifdef VTIAUDIO_FORWARD_OUTPUT
    g_out_shm = (vti_audio_shm *)shm;
#endif
    vtiemu_log("audio: following the broker's WinUSB stream (shared ring, %u ch)", shm->in_ch);
    static int16_t buf[4096 * IN_CHANNELS];
    int64_t pos = shm->in_frames;
    int idle = 0;
#ifdef VTIEMU_VIRTUAL_DEVICE
    // Wine (Linux): the broker's tick arrives over a socket and is turned into SetEvent - both go through wineserver,
    // which occasionally delays the wake-up by 20-30 ms; the plug-in then re-anchors its time stamps and the synth
    // reports a sync error (E128). Instead, poll the shared ring every millisecond (Sleep is handled without
    // wineserver); the event stays as a fallback for the "stream stalled" check.
    timeBeginPeriod(1);
#endif
    while (g_running) {
#ifdef VTIEMU_VIRTUAL_DEVICE
        DWORD w = WAIT_TIMEOUT;
        for (int ms = 0; ms < 200; ms++) {
            if (*(volatile const int64_t *)&shm->in_frames != pos) {
                w = WAIT_OBJECT_0;
                break;
            }
            Sleep(1);
        }
#else
        DWORD w = WaitForSingleObject(ev, 200);
#endif
        // plain aligned 64-bit read (atomic on x64); no interlocked op: the mapping is read-only (lock cmpxchg
        // writes and faults there). The broker publishes in_frames after the data, x64 keeps the load order.
        int64_t wr = *(volatile const int64_t *)&shm->in_frames;
        // Only while the plug-in's stream runs (output ring and buffer-switch event registered), and at most once per
        // second: while a Live set loads, the plug-in is still setting up and closes/reopens its stream several times
        // (2026-10-14: Live crashed inside Virus Control.dll during a set load right after the first version of this
        // re-registered at once; not proven to be the cause, but the plug-in should be left alone until it is ready).
        static DWORD last_rereg;
        if (w == WAIT_TIMEOUT && wr != pos && g_out_sm && g_bs_event && GetTickCount() - last_rereg > 1000) {
            last_rereg = GetTickCount();
            // Frames arrived but our event was not signalled: the broker dropped our registration because the broker
            // connection it belonged to was closed (the plug-in closed its device handles, e.g. a Live set was closed,
            // and reopened them on a new connection). The stream itself kept running for another client (the TI
            // Revive ASIO driver), so the "stalled" check below never fires and the plug-in would be clocked by this
            // 200 ms timeout in 4096-frame lumps: random F5 timestamps, continuous sync errors, messy playback
            // (seen 2026-10-14 on Windows 11, Ableton Live 12: 15 deliveries/s, max gap 215 ms). Register again.
            v = vtiemu_dev();
            int rr = v ? vti_audio(v, 1, name) : -1;
            vtiemu_log("audio: broker stopped signalling while the stream runs, re-registered (%d)", rr);
        }
        if (wr == pos) {
            if (w == WAIT_TIMEOUT && ++idle >= 5) { // 1 s without audio: broker restarted or stream stopped
                idle = 0;
                v = vtiemu_dev();
                int rr = v ? vti_audio(v, 1, name) : -1;
                vtiemu_log("audio: broker stream stalled, re-registered (%d)", rr);
                pos = shm->in_frames;
            }
            continue;
        }
        idle = 0;
        int64_t avail = wr - pos;
        if (avail < 0 || avail > VTI_AUDIO_RING - 4096) { // fell behind by most of the ring (or the ring restarted)
            vtiemu_log("audio: broker ring overrun (%lld frames), resynchronising", (long long)avail);
            pos = wr - 441;
            avail = 441;
        }
        while (avail > 0) { // one contiguous block per delivery (small blocks upset the plugin's clock, E077)
            uint32_t k = avail > 4096 ? 4096 : (uint32_t)avail;
            for (uint32_t i = 0; i < k; i++)
                memcpy(buf + i * IN_CHANNELS, &shm->in[((pos + i) & (VTI_AUDIO_RING - 1)) * IN_CHANNELS],
                       IN_CHANNELS * sizeof(int16_t));
            usb_in(buf, k, NULL);
            pos += k;
            avail -= k;
        }
    }
#ifdef VTIEMU_VIRTUAL_DEVICE
    timeEndPeriod(1);
#endif
#ifdef VTIAUDIO_FORWARD_OUTPUT
    g_out_shm = NULL;
#endif
    v = vtiemu_dev();
    if (v)
        vti_audio(v, 0, NULL);
    UnmapViewOfFile(shm);
    CloseHandle(map);
    CloseHandle(ev);
    return 1;
}

static DWORD WINAPI capture_thread(LPVOID unused)
{
    (void)unused;
    // Preferred: the broker streams the Virus audio on WinUSB like VirusUSB.sys (frame counter = the synth's real
    // frames, OUT pattern mirrored; E075) and this process follows its shared ring. With an older broker, stream
    // it here directly. Falls through to WASAPI when the audio function is not on WinUSB.
    int b = broker_audio();
    if (b > 0)
        return 0;
    if (b < 0 && vua_run(&g_running, usb_in, NULL, vtiemu_log) >= 0)
        return 0;
    vtiemu_log("audio: no WinUSB audio function (MI_00): using Windows audio (WASAPI)");
    g_render_thread = CreateThread(NULL, 0, render_thread, NULL, 0, NULL);
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    IMMDevice *dev = find_virus(eCapture);
    IAudioClient *ac = NULL;
    IAudioCaptureClient *cc = NULL;
    HANDLE ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    // Same channel count and mask as the endpoint (so Windows does not remix), 16-bit PCM at 44.1 kHz
    // (Windows resamples from the device rate, 48 kHz with the inbox driver, E056).
    WAVEFORMATEXTENSIBLE fx = {0};
    WAVEFORMATEX *fmt = &fx.Format, *mix = NULL;
    HRESULT hr = E_FAIL;
    uint32_t ch = 2;
    if (dev && SUCCEEDED(hr = dev->lpVtbl->Activate(dev, &IID_AudioClient, CLSCTX_ALL, NULL, (void **)&ac)) &&
        SUCCEEDED(hr = ac->lpVtbl->GetMixFormat(ac, &mix))) {
        ch = mix->nChannels ? mix->nChannels : 2;
        DWORD mask = mix->wFormatTag == WAVE_FORMAT_EXTENSIBLE ? ((WAVEFORMATEXTENSIBLE *)mix)->dwChannelMask : 0;
        vtiemu_log("audio: endpoint mix format %u ch, %lu Hz, %u bit, mask 0x%lx", ch, (unsigned long)mix->nSamplesPerSec,
                   mix->wBitsPerSample, (unsigned long)mask);
        CoTaskMemFree(mix);
        fx.Format.wFormatTag = WAVE_FORMAT_EXTENSIBLE;
        fx.Format.nChannels = (WORD)ch;
        fx.Format.nSamplesPerSec = RATE;
        fx.Format.wBitsPerSample = 16;
        fx.Format.nBlockAlign = (WORD)(2 * ch);
        fx.Format.nAvgBytesPerSec = RATE * 2 * ch;
        fx.Format.cbSize = sizeof fx - sizeof fx.Format;
        fx.Samples.wValidBitsPerSample = 16;
        fx.dwChannelMask = mask;
        fx.SubFormat = (GUID){0x00000001, 0x0000, 0x0010, {0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71}}; // PCM
    }
    // Exclusive mode first: the device itself then runs at 44.1 kHz like with the Access driver (the inbox driver
    // picks 48 kHz in shared mode, and the 48k->44.1k conversion plus the 48 kHz device clock made tempo sync and
    // audio timing drift, E067); no resampling and a short, device-clocked period. Shared mode is the fallback.
    int exclusive = 0;
    if (SUCCEEDED(hr) && ac->lpVtbl->IsFormatSupported(ac, AUDCLNT_SHAREMODE_EXCLUSIVE, fmt, NULL) == S_OK) {
        REFERENCE_TIME def = 0, min = 0;
        ac->lpVtbl->GetDevicePeriod(ac, &def, &min);
        HRESULT ex = ac->lpVtbl->Initialize(ac, AUDCLNT_SHAREMODE_EXCLUSIVE, AUDCLNT_STREAMFLAGS_EVENTCALLBACK, def,
                                            def, fmt, NULL);
        if (ex == AUDCLNT_E_BUFFER_SIZE_NOT_ALIGNED) { // retry with the aligned buffer size
            UINT32 frames = 0;
            ac->lpVtbl->GetBufferSize(ac, &frames);
            ac->lpVtbl->Release(ac);
            ac = NULL;
            def = (REFERENCE_TIME)(10000.0 * 1000 / RATE * frames + 0.5);
            if (SUCCEEDED(dev->lpVtbl->Activate(dev, &IID_AudioClient, CLSCTX_ALL, NULL, (void **)&ac)))
                ex = ac->lpVtbl->Initialize(ac, AUDCLNT_SHAREMODE_EXCLUSIVE, AUDCLNT_STREAMFLAGS_EVENTCALLBACK, def,
                                            def, fmt, NULL);
        }
        if (SUCCEEDED(ex)) {
            exclusive = 1;
            vtiemu_log("audio: exclusive mode, period %.2f ms", def / 10000.0);
        } else {
            vtiemu_log("audio: exclusive mode failed (hr=0x%08lx): shared mode", (unsigned long)ex);
            if (ac)
                ac->lpVtbl->Release(ac);
            ac = NULL;
            hr = dev->lpVtbl->Activate(dev, &IID_AudioClient, CLSCTX_ALL, NULL, (void **)&ac);
        }
    } else if (SUCCEEDED(hr)) {
        vtiemu_log("audio: 44.1 kHz %u ch not available in exclusive mode: shared mode (resampled)", ch);
    }
    if (SUCCEEDED(hr) && !exclusive)
        hr = ac->lpVtbl->Initialize(ac, AUDCLNT_SHAREMODE_SHARED,
                                    AUDCLNT_STREAMFLAGS_EVENTCALLBACK | AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM |
                                        AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY,
                                    100000 /* 10 ms */, 0, fmt, NULL);
    if (SUCCEEDED(hr))
        hr = ac->lpVtbl->SetEventHandle(ac, ev);
    if (SUCCEEDED(hr))
        hr = ac->lpVtbl->GetService(ac, &IID_AudioCapture, (void **)&cc);
    if (SUCCEEDED(hr))
        hr = ac->lpVtbl->Start(ac);
    if (FAILED(hr)) {
        vtiemu_log("audio: no Virus TI capture stream (hr=0x%08lx, endpoint %s): silence clock", (unsigned long)hr,
                   dev ? "found" : "missing");
        silence_clock();
    } else {
        vtiemu_log("audio: capturing 44.1 kHz 16-bit %u ch from the Virus TI endpoint (%s)", ch, exclusive ? "exclusive" : "shared");
        uint64_t total = 0;
        while (g_running) {
            if (WaitForSingleObject(ev, 200) != WAIT_OBJECT_0)
                continue;
            BYTE *data;
            UINT32 n;
            DWORD flags;
            while (SUCCEEDED(cc->lpVtbl->GetBuffer(cc, &data, &n, &flags, NULL, NULL)) && n) {
                push_frames((flags & AUDCLNT_BUFFERFLAGS_SILENT) ? NULL : (const int16_t *)data, ch, n);
                total += n;
                cc->lpVtbl->ReleaseBuffer(cc, n);
            }
            static uint64_t next_diag = RATE * 10;
            if (total >= next_diag) { // every 10 s of device time
                diag();
                next_diag += RATE * 10;
            }
        }
        ac->lpVtbl->Stop(ac);
    }
    if (cc)
        cc->lpVtbl->Release(cc);
    if (ac)
        ac->lpVtbl->Release(ac);
    if (dev)
        dev->lpVtbl->Release(dev);
    CloseHandle(ev);
    CoUninitialize();
    return 0;
}

// The Access driver streams audio TO the Virus (iso EP 0x01) all the time, alongside the input stream; without
// it the synth reports "Sync Information Event" (global 0x54 = 1) ~10x per second and the plug-in shows "A sync
// error occurred" on play (findings E072). So keep the "Virus TI" render endpoint running in exclusive mode at
// 44.1 kHz (the device rate the capture side set). Silence for now: audio to the Virus is not supported yet.
// No shared-mode fallback: that would run the endpoint at the shared-mode rate (48 kHz) instead.
static DWORD WINAPI render_thread(LPVOID unused)
{
    (void)unused;
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    IMMDevice *dev = find_virus(eRender);
    IAudioClient *ac = NULL;
    IAudioRenderClient *rc = NULL;
    HANDLE ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    WAVEFORMATEXTENSIBLE fx = {0};
    WAVEFORMATEX *mix = NULL;
    HRESULT hr = E_FAIL;
    REFERENCE_TIME def = 0, min = 0;
    UINT32 frames = 0;
    if (dev && SUCCEEDED(hr = dev->lpVtbl->Activate(dev, &IID_AudioClient, CLSCTX_ALL, NULL, (void **)&ac)) &&
        SUCCEEDED(hr = ac->lpVtbl->GetMixFormat(ac, &mix))) {
        WORD ch = mix->nChannels ? mix->nChannels : 2;
        fx.Format.wFormatTag = WAVE_FORMAT_EXTENSIBLE;
        fx.Format.nChannels = ch;
        fx.Format.nSamplesPerSec = RATE;
        fx.Format.wBitsPerSample = 16;
        fx.Format.nBlockAlign = (WORD)(2 * ch);
        fx.Format.nAvgBytesPerSec = RATE * 2 * ch;
        fx.Format.cbSize = sizeof fx - sizeof fx.Format;
        fx.Samples.wValidBitsPerSample = 16;
        fx.dwChannelMask = mix->wFormatTag == WAVE_FORMAT_EXTENSIBLE ? ((WAVEFORMATEXTENSIBLE *)mix)->dwChannelMask : 0;
        fx.SubFormat = (GUID){0x00000001, 0x0000, 0x0010, {0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71}}; // PCM
        CoTaskMemFree(mix);
        ac->lpVtbl->GetDevicePeriod(ac, &def, &min);
        hr = ac->lpVtbl->Initialize(ac, AUDCLNT_SHAREMODE_EXCLUSIVE, AUDCLNT_STREAMFLAGS_EVENTCALLBACK, def, def,
                                    &fx.Format, NULL);
        if (hr == AUDCLNT_E_BUFFER_SIZE_NOT_ALIGNED) { // retry with the aligned buffer size
            ac->lpVtbl->GetBufferSize(ac, &frames);
            ac->lpVtbl->Release(ac);
            ac = NULL;
            def = (REFERENCE_TIME)(10000.0 * 1000 / RATE * frames + 0.5);
            if (SUCCEEDED(hr = dev->lpVtbl->Activate(dev, &IID_AudioClient, CLSCTX_ALL, NULL, (void **)&ac)))
                hr = ac->lpVtbl->Initialize(ac, AUDCLNT_SHAREMODE_EXCLUSIVE, AUDCLNT_STREAMFLAGS_EVENTCALLBACK, def,
                                            def, &fx.Format, NULL);
        }
    }
    if (SUCCEEDED(hr))
        hr = ac->lpVtbl->SetEventHandle(ac, ev);
    if (SUCCEEDED(hr))
        hr = ac->lpVtbl->GetBufferSize(ac, &frames);
    if (SUCCEEDED(hr))
        hr = ac->lpVtbl->GetService(ac, &IID_AudioRender, (void **)&rc);
    BYTE *data;
    if (SUCCEEDED(hr) && SUCCEEDED(hr = rc->lpVtbl->GetBuffer(rc, frames, &data))) // pre-fill before Start
        hr = rc->lpVtbl->ReleaseBuffer(rc, frames, AUDCLNT_BUFFERFLAGS_SILENT);
    if (SUCCEEDED(hr))
        hr = ac->lpVtbl->Start(ac);
    if (FAILED(hr)) {
        vtiemu_log("audio: no Virus TI render stream (hr=0x%08lx, endpoint %s): the synth may report sync errors",
                   (unsigned long)hr, dev ? "found" : "missing");
    } else {
        vtiemu_log("audio: rendering silence to the Virus TI endpoint (exclusive 44.1 kHz %u ch, period %.2f ms)",
                   fx.Format.nChannels, def / 10000.0);
        while (g_running) {
            if (WaitForSingleObject(ev, 200) != WAIT_OBJECT_0)
                continue;
            if (SUCCEEDED(rc->lpVtbl->GetBuffer(rc, frames, &data))) // exclusive event mode: one whole buffer each
                rc->lpVtbl->ReleaseBuffer(rc, frames, AUDCLNT_BUFFERFLAGS_SILENT);
        }
        ac->lpVtbl->Stop(ac);
    }
    if (rc)
        rc->lpVtbl->Release(rc);
    if (ac)
        ac->lpVtbl->Release(ac);
    if (dev)
        dev->lpVtbl->Release(dev);
    CloseHandle(ev);
    CoUninitialize();
    return 0;
}

static void ensure_running(void)
{
    if (!InterlockedExchange(&g_running, 1)) {
        g_thread = CreateThread(NULL, 0, capture_thread, NULL, 0, NULL); // starts render_thread for WASAPI
    }
}

// IOCTL 0x220010: map the input region (allocated once per process).
void *vtiaudio_input_region(void)
{
    if (!g_in) {
        g_in = VirtualAlloc(NULL, IN_REGION, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (g_in)
            init_region(g_in);
        vtiemu_log("audio: input region %p", (void *)g_in);
    }
    return g_in;
}

// IOCTL 0x220030 {u8 start, pad, void *buf}: the plugin's output AudioSM (towards the device).
void vtiaudio_output_ring(int start, void *buf)
{
    g_out_sm = start ? buf : NULL;
    vtiemu_log("audio: plugin stream %s (ring %p)", start ? "start" : "stop", buf);
    if (start && g_in)
        ensure_running();
}

// IOCTL 0x2200E4 {routine, thread, event}: the threaded buffer-switch registration (all zero = unregister).
void vtiaudio_buffer_switch(const uint64_t reg[3])
{
    if (!reg[0] && reg[1] && reg[2]) {
        g_bs_event = (HANDLE)(uintptr_t)reg[2];
        vtiemu_log("audio: buffer-switch event %p", g_bs_event);
    } else if (!reg[0] && !reg[1] && !reg[2]) {
        g_bs_event = NULL;
    } else {
        vtiemu_log("audio: APC buffer-switch registration (routine %p) not supported", (void *)(uintptr_t)reg[0]);
    }
}
