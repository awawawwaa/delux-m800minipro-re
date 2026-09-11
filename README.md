# DeluxRE — Delux M800 Mini Pro protocol reverse engineering

Reverse engineering of the USB HID protocol used by the **Delux M800 Mini Pro**
gaming mouse (2.4GHz wireless dongle, "competitive" firmware) to control DPI,
performance settings and read battery status without the vendor's official
software.

This document is the protocol reference. If you want to reimplement this in
another tool (a driver, a CLI, an OpenRazer-style daemon, etc.), everything
you need is below. Inspired by [lx862's mouse reverse engineering
writeup](https://blog.lx862.com/blog/2024-05-13-reverse-engineering-a-mouse/)
and the [hyperx_pulsefire_dart_reverse_engineering
project](https://github.com/santeri3700/hyperx_pulsefire_dart_reverse_engineering).

## Status

Validated against real hardware, multiple independent samples per field
(see "Confidence" column per report below). DPI, debounce, polling rate,
ripple control, motion sync, angle snapping, LOD, sensor frame rate/mode and
battery/charging are all confirmed working, writable, and (mostly) documented
byte-for-byte. A working reference implementation (Windows-only) lives in
this repo — see [Reference implementation](#reference-implementation).

## Device identification

| | |
|---|---|
| Vendor ID | `0x1D57` (Weltrend Semiconductor — a generic OEM controller chip vendor used by many rebranded peripherals, not Delux-specific) |
| Product ID | `0xFA60` |
| Product string | `2.4G Wireless Device` |
| Connection | 2.4GHz RF dongle (not Bluetooth). All findings below were captured through the dongle. |
| Firmware | Delux's "competitive" firmware variant — required for the Sensor Frame Rate / connection-mode setting to be present at all |

## Why you can't just use WebHID

Chromium (and any browser built on it) hard-blocks Feature/Input report
access for any HID top-level collection whose usage is Generic Desktop
Mouse/Keyboard/SystemControl/etc — this is a fixed security policy, not a
permission you can grant. On this device the vendor config report happens to
live behind exactly that kind of collection, so `navigator.hid` cannot reach
it, full stop, regardless of user consent.

The workaround is a small native process (a "bridge") talking directly to
`hid.dll` / `setupapi.dll` via `CreateFile` + `HidD_SetFeature` (Win32), which
isn't subject to the browser's blocklist. Any implementation on any OS needs
an equivalent native HID access layer (e.g. `hidraw` + `ioctl` on Linux,
`IOHIDDeviceSetReport` on macOS, or `hidapi`/`libusb` cross-platform).

## USB/HID topology

The dongle enumerates as a composite USB device with 4 HID interfaces. On
Windows each shows up as a separate device path; three of them are further
split into sub-collections:

| Interface | HID descriptor size | Windows class | Notes |
|---|---|---|---|
| 0 (`mi_00`) | 67 bytes | Keyboard | Exclusively claimed by the OS keyboard driver. Not reachable by user-mode code. |
| 1 (`mi_01`) | 73 bytes | **Mouse** | The actual cursor-movement collection. Exclusively claimed by the OS mouse driver — `CreateFile` fails with `ERROR_ACCESS_DENIED` (error 5) for **any** process, read or write, regardless of what software is running. This is an OS-level lock, independent of and stricter than the WebHID browser block. |
| 2 (`mi_02`) | 230 bytes | HID (split into 4 sub-collections, see below) | This is where all vendor config lives. |
| 3 (`mi_03`) | 27 bytes | Keyboard | Also exclusively claimed. Not reachable. |

Interface 2's sub-collections (each independently reachable via a normal
`CreateFile`/`HidD_*` handle — none of these are blocked):

| Collection | Usage Page | Usage | Carries |
|---|---|---|---|
| `mi_02&col01` | `0x01` (Generic Desktop) | `0x80` (System Control) | No reports observed in use |
| `mi_02&col02` | `0x0C` (Consumer) | `0x01` (Consumer Control) | Input report #2 (not reverse engineered) |
| `mi_02&col03` | `0x0A` (Ordinal) | `0x00` | **Report ID 3** — movement + battery/charging heartbeat, as async INPUT reports |
| `mi_02&col04` | `0x0B` (Telephony) | `0x00` | **Report IDs 4, 5, 6, 8, 12** — all vendor config, as FEATURE reports (`SET_REPORT`/`HidD_SetFeature`) |

Key implementation detail: a `SET_REPORT` (Feature) control transfer is
addressed by USB `wIndex` = **interface number** (2, in this case), not by
which specific sub-collection handle you opened. In practice this means
`HidD_SetFeature` succeeds through **any** of col01-col04's device handles
for **any** report ID that belongs to interface 2 — Windows' HID class driver
forwards the control transfer at the interface level and doesn't enforce
per-collection report-ID scoping the way it does for `HidD_GetInputReport`.
So pick whichever of the 4 collections is convenient to open (this project
uses col04, since it's the one with a non-zero declared Feature report
length).

## Writing config: HID SET_REPORT (Feature Report), control transfer

All writes below use the same control transfer shape:

```
bmRequestType : 0x21  (Host→Device, Class, Recipient=Interface)
bRequest      : 0x09  (SET_REPORT)
wValue        : (ReportID << 8) | 0x03   — 0x03 = Feature report type
wIndex        : 0x0002                   — interface number
wLength       : <report length, including the ReportID byte>
```

The data payload's first byte is always the Report ID, matching `wValue`'s
low byte. All multi-byte reports below are shown fully, byte 0 = Report ID.

### Report ID 4 — DPI + Performance, 56 bytes

`wValue = 0x0304`, `wLength = 56`. This single report bundles the DPI table
*and* five other performance toggles — the whole 56-byte struct is rewritten
on every save, there is no partial write.

| Offset | Field | Encoding | Confidence |
|---|---|---|---|
| 0 | Report ID | `0x04` | — |
| 1 | Report length | `0x38` (56) | — |
| 2 | unknown | always observed `0x01` | low (never varied) |
| 3 | flags | bit0 (`0x01`) = Ripple Control on/off; bit4 (`0x10`) = LOD (0=1mm, 1=2mm) | confirmed, 2 samples/bit |
| 4 | flags | bit0 (`0x01`) = Motion Sync on/off; bit4 (`0x10`) = Angle Snapping on/off | confirmed, 2 samples/bit |
| 5 | DPI stage enable bitmask | bit *i* = DPI slot *i+1* enabled | confirmed, several samples |
| 6 | Sensor Frame Rate / connection mode | `0x00`=HP (high performance), `0x01`=LP (power saving), `0x03`=Corded (wired). `0x02` never observed. | confirmed, 3 samples |
| 7 | unknown | always `0x00` | low |
| 8–13 | DPI table, 6 slots | `dpi = (byte + 1) * 50` per slot | confirmed, many samples incl. edited values |
| 14–23 | reserved | always `0x00` | — |
| 24 | active DPI stage | 1-based index into the 6-slot table above | confirmed |
| 25–50 | unidentified (26 bytes) | looks like an RGB/lighting color table; not reverse engineered | not investigated |
| 51 | checksum | `(sum(bytes[2,3,4,5,6,8,9,10,11,12,13,24]) + 0x34) mod 256` | confirmed, 7+ independent samples, zero mismatches |
| 52–55 | padding | `0x00 0x00 0x00 0x00` | — |

Example (all defaults: DPI 400/800/1200/1600/3200/5000, slots 2/4/5
enabled, slot 2 active, everything off, Corded mode):
```
04 38 01 00 00 1e 03 00 07 0f 17 1f 3f 63 00 00
00 00 00 00 00 00 00 00 02 ff 00 00 00 ff 00 00
00 ff ff 00 ff ff ff 00 ff ff ff ff 40 00 ff ff
ff 03 0f 48 00 00 00 00
```

### Report ID 5 — Debounce time, 15 bytes

`wValue = 0x0503`, `wLength = 15`.

| Offset | Field | Encoding | Confidence |
|---|---|---|---|
| 0 | Report ID | `0x05` | — |
| 1 | Report length | `0x0f` (15) | — |
| 2–9 | unidentified, fixed | always observed `01 70 03 a8 00 00 ff 02` | not investigated (may encode other settings on different firmware variants) |
| 10 | Debounce time | raw milliseconds, no scaling. Device accepted 1–15ms in testing. | confirmed, 3 independent samples (1/7/13ms) |
| 11 | unidentified, fixed | always `0x02` | low |
| 12 | checksum | `(byte[10] + 28) mod 256` | confirmed, 3/3 samples |
| 13–14 | padding | `0x00 0x00` | — |

Example (13ms): `05 0f 01 70 03 a8 00 00 ff 02 0d 02 29 00 00`

### Report ID 6 — Polling rate, 9 bytes

`wValue = 0x0603`, `wLength = 9`.

| Offset | Field | Encoding | Confidence |
|---|---|---|---|
| 0 | Report ID | `0x06` | — |
| 1 | Report length | `0x09` (9) | — |
| 2 | unidentified, fixed | always `0x01` | low |
| 3 | Polling rate enum | `1000Hz=0x74`, `500Hz=0x73`, `250Hz=0x72` | confirmed, 3/3 samples. `125Hz=0x71` is extrapolated from the pattern (each halving decrements this byte by 1) — **not confirmed on hardware**. |
| 4 | checksum | `(0xFF - byte[3]) mod 256` | confirmed, 3/3 samples |
| 5–8 | padding | `0x00 0x00 0x00 0x00` | — |

Example (1000Hz): `06 09 01 74 8b 00 00 00 00`

### Report ID 8 — button/macro mapping (not reverse engineered)

59 bytes, `wValue = 0x0803`. Observed once; byte pattern looks like
`[keycode, 0x00, 0x00]` triplets, consistent with a per-button remapping
table (~14 buttons). Out of scope for this writeup — flagged here so it
isn't mistaken for noise if you're inspecting your own captures.

### Report ID 12 — startup sync/handshake (not reverse engineered)

10 bytes, `wValue = 0x0C03`. Sent once by the official software on startup,
before any other write. Purpose unclear (possibly a "wake up"/capability
query the software issues once); not required to replicate any of the
writes documented here — none of our tooling sends it and everything still
works.

## Reading config back: doesn't work

There is no reliable way to read current DPI/debounce/polling/etc settings
back from the device:

- `HidD_GetInputReport` for any report ID on any of col01/02/03/04 returns
  failure immediately (Windows rejects it locally — the report ID isn't
  declared as a valid *Input* report for that collection's cached
  capabilities, it's a client-side validation failure, not a device
  response).
- `HidD_GetFeature` (control-transfer `GET_REPORT`, Feature type) *does*
  return data without erroring, but it's not meaningful — requesting Report
  ID 4 (and most other IDs) returns a cached UTF-16LE product-name string
  buffer (`"2.4G Wireless Device"`) regardless of which report ID you ask
  for. This firmware does not implement Feature report reads correctly; it
  just echoes back some internal buffer.
- The vendor's own official software was confirmed (via `Get-PnpDevice`) to
  use the exact same stock Microsoft HID class drivers as any other
  process — it holds no special driver-level access. Empirically it also
  never issues `GET_REPORT` (checked via USB capture). It appears the
  official software just remembers its last-written state locally (in its
  own UI) rather than reading the mouse.

**Practical consequence for anyone reimplementing this**: you cannot detect
or reconcile with the mouse's actual current settings. Any UI you build
should either (a) treat itself as the sole source of truth and never assume
a starting value, or (b) require the user to explicitly set a value for
every field before writing, rather than guessing — this repo's webapp does
the latter for exactly this reason.

## Battery and charging status

Confirmed exception to the "reads don't work" rule above — but it's not a
Feature Report, and it's not requested on demand. The mouse pushes a
5-byte **Input** report on **Report ID 3**, periodically (observed roughly
every 2–4 seconds while idle), over collection `mi_02&col03`.

| Offset | Field | Encoding |
|---|---|---|
| 0 | Report ID | `0x03` |
| 1 | unidentified, fixed | always `0x29` (41) |
| 2 | unidentified | `0x40` observed at steady state; `0x50` observed during bursts of config writes — meaning not fully pinned down, don't rely on it |
| 3 | Charging flag | `0x01` = on battery, `0x03` = charging |
| 4 | Battery percentage | raw decimal, 0–100 |

To read this, do **not** use `HidD_GetInputReport` (it fails the same way
described above — this report isn't declared as synchronously queryable).
Instead, open col03 with `FILE_FLAG_OVERLAPPED` and issue an async
`ReadFile`, then wait (with a timeout — a few seconds is enough given the
observed cadence) for the next unsolicited push. Example bytes while on
battery at 33%, not charging: `03 29 40 01 21`.

Note that col03 is a *different* collection than the ones used for config
writes (col04) — you need a handle to col03 specifically for battery, and a
handle to any of col01–col04 for config writes.

## RF link reliability

There is no delivery acknowledgment for `SET_REPORT` writes over the
2.4GHz link — the control transfer to the dongle completes and reports
success from Windows' perspective the moment the dongle accepts it over
USB, which says nothing about whether the dongle successfully relayed it
to the mouse. In testing, firing multiple `SET_REPORT` writes back-to-back
with no delay (e.g. saving DPI + debounce + polling rate together)
sometimes resulted in one of them not actually taking effect on the mouse.
Spacing consecutive writes by roughly 500–800ms resolved this reliably in
testing. If you're writing multiple reports in one user action, don't fire
them concurrently — queue them with a short delay between each.

## TODO

- **Verify the Product ID with the mouse connected via USB cable.** Every
  finding in this document — including the `0xFA60` PID — was captured
  with the mouse connected through the 2.4GHz dongle. It's not confirmed
  whether wired mode enumerates with the same PID, the same VID:PID pair
  at all, or a different interface/report layout. Don't assume wired mode
  matches this document until someone checks.
- **Sleep timer setting is not implemented.** The official software exposes
  a sleep/auto-off timer; this hasn't been captured or reverse engineered
  yet. Needs a capture of that setting being changed (see "Capturing your
  own data" below) before it can be added to the protocol reference and to
  the bridge/webapp.

## Reference implementation

This repo contains a working Windows implementation you can read directly
instead of reimplementing from scratch:

| File | What it is |
|---|---|
| `scripts/HidBridge.cs` | The P/Invoke layer (`hid.dll`/`setupapi.dll`): enumeration, `SetFeatureReport`, `ReadFileWithTimeout` (battery), etc. |
| `scripts/Start-DpiBridge.ps1` | A local HTTP server wrapping `HidBridge.cs`, with the exact byte-building logic (`Build-DpiPayload`, `Build-DebouncePayload`, `Build-PollingRatePayload`) for every report above, including the checksum formulas |
| `webapp/index.html` | A browser UI talking to the bridge over HTTP — shows the full field set (DPI, debounce, polling rate, ripple control, motion sync, angle snapping, LOD, sensor frame rate) end to end |
| `Iniciar-Bridge.bat` | Double-click shortcut that launches `Start-DpiBridge.ps1` |

## Capturing your own data (e.g. to extend this to RGB/macros)

The findings above were derived from USB captures (Wireshark + USBPcap) of
the official software, not shipped in this repo. To redo that yourself:

1. Install [Wireshark](https://www.wireshark.org/) with the USBPcap
   extcap enabled (included in the Windows installer).
2. Start a capture on the USB root hub your dongle is attached to, *before*
   plugging the dongle in or opening the official Delux software — this
   captures the full enumeration and any startup handshake.
3. Change exactly one setting in the official software, wait a moment,
   then stop the capture.
4. In Wireshark, filter for `usbhid.setup.bRequest == 9` to isolate
   `SET_REPORT` writes, and inspect the `usb.data_fragment` field of each
   match — that's the full Feature report payload (Report ID + data).
5. Diff the payload against a baseline (same steps, without the setting
   change) to isolate exactly which byte(s) moved.

## Disclaimer

Independent reverse engineering for interoperability purposes. Not
affiliated with, endorsed by, or based on confidential information from
Delux. All findings here were derived from observing USB traffic between
the official software and the device.
