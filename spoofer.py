#!/usr/bin/env python3

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
import webbrowser
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Iterator, Sequence

for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

ROOT = Path(__file__).resolve().parent
DEX_FILE = ROOT.parent / "data" / "pokedex.json"
STATE_FILE = ROOT / "session.json"
LEGACY_FILES = (ROOT / "pokedex_state.json", ROOT / "science_state.json")

ME_URL = "https://discord.com/api/v9/users/@me?with_analytics_token=true"
SCIENCE_URL = "https://discord.com/api/v9/science"
PROPERTIES_URL = "https://cordapi.dolfi.es/api/v2/properties/windows"
DEX_CDN_URL = "https://cdn.discordapp.com/detectables/games.json"
SUBSCRIBE_URL = "https://www.youtube.com/@moufid-en-short?sub_confirmation=1"
LEAGUE_LABEL = "discord.gg/7XVTEeEKC8"
LEAGUE_URL = "https://discord.gg/7XVTEeEKC8"
GATE_WAIT = 10

BATCH_SIZE = 50
BATCH_DELAY = 1
AUTH_MAX_AGE = 12 * 3600
DEBUG = False

CLIENT_VERSION = "1.0.9253"
CLIENT_BUILD_NUMBER = 594031
NATIVE_BUILD_NUMBER = 88414
OS_VERSION = "10.0.26200"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) discord/1.0.9253 Chrome/148.0.7778.280 "
    "Electron/42.7.1 Safari/537.36"
)

R = "\x1b[0m"
SNOW = "\x1b[38;5;255m"
S55 = "\x1b[38;5;246m"
S35 = "\x1b[38;5;243m"
S25 = "\x1b[38;5;240m"
BORDER = "\x1b[38;5;238m"
BORDER_HI = "\x1b[38;5;245m"
DIM = "\x1b[38;5;238m"
SIGNAL = "\x1b[38;5;255m"
WARN = "\x1b[38;5;179m"
BAD = "\x1b[38;5;203m"

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _vlen(value: str) -> int:
    return len(_ANSI.sub("", value))


def _cut(value: str, width: int) -> str:
    out, n, i = [], 0, 0
    while i < len(value) and n < width:
        if value[i] == "\x1b":
            j = value.find("m", i)
            if j == -1:
                break
            out.append(value[i:j + 1])
            i = j + 1
            continue
        out.append(value[i])
        i += 1
        n += 1
    return "".join(out) + R if n else ""


def _pad(value: str, width: int, align: str = "left") -> str:
    gap = max(0, width - _vlen(value))
    if align == "right":
        return " " * gap + value
    if align == "center":
        left = gap // 2
        return " " * left + value + " " * (gap - left)
    return value + " " * gap


def _user_id_from_token(token: str) -> str:
    try:
        first = token.split(".", 1)[0]
        pad = "=" * (-len(first) % 4)
        return base64.b64decode(first + pad).decode("utf-8")
    except Exception:
        return ""


def _mask(value: str) -> str:
    return value[:6] + "…" + value[-4:] if len(value) > 12 else value


def _dot(on: bool) -> str:
    return f"{SIGNAL}●{R}" if on else f"{S25}○{R}"


_FINGERPRINT_PS1 = r'''
param(
  [int]$ProcessId = 0,
  [string]$Path,
  [Parameter(Mandatory = $true)][string]$UserId
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class CertPubKeyHash {
  const uint X509_ASN_ENCODING = 0x00000001;
  const uint PKCS_7_ASN_ENCODING = 0x00010000;
  const uint CALG_SHA_256 = 0x0000800C;

  [StructLayout(LayoutKind.Sequential)] struct Blob { public uint cbData; public IntPtr pbData; }
  [StructLayout(LayoutKind.Sequential)] struct AlgId { public IntPtr pszObjId; public Blob Parameters; }
  [StructLayout(LayoutKind.Sequential)] struct BitBlob { public uint cbData; public IntPtr pbData; public uint cUnusedBits; }
  [StructLayout(LayoutKind.Sequential)] struct PubKeyInfo { public AlgId Algorithm; public BitBlob PublicKey; }
  [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low; public uint High; }
  [StructLayout(LayoutKind.Sequential)]
  struct CertInfo {
    public uint Version; public Blob SerialNumber; public AlgId SignatureAlgorithm; public Blob Issuer;
    public FileTime NotBefore; public FileTime NotAfter; public Blob Subject;
    public PubKeyInfo SubjectPublicKeyInfo; public BitBlob IssuerUniqueId; public BitBlob SubjectUniqueId;
    public uint ExtensionCount; public IntPtr Extensions;
  }
  [StructLayout(LayoutKind.Sequential)]
  struct CertContext {
    public uint EncodingType; public IntPtr Encoded; public uint EncodedSize;
    public IntPtr CertInfo; public IntPtr Store;
  }

  [DllImport("crypt32.dll", SetLastError = true)]
  static extern bool CryptHashPublicKeyInfo(
    IntPtr provider, uint algid, uint flags, uint encoding, ref PubKeyInfo info, byte[] hash, ref uint hashSize);

  public static byte[] Hash(IntPtr certContext) {
    var ctx = Marshal.PtrToStructure<CertContext>(certContext);
    var info = Marshal.PtrToStructure<CertInfo>(ctx.CertInfo);
    var hash = new byte[32];
    uint hashSize = 32;
    if (!CryptHashPublicKeyInfo(IntPtr.Zero, CALG_SHA_256, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, ref info.SubjectPublicKeyInfo, hash, ref hashSize) || hashSize != 32)
      throw new InvalidOperationException("CryptHashPublicKeyInfo failed");
    return hash;
  }
}
"@

if (!$Path) {
  if (!$ProcessId) { throw "Pass -Path <exe> or -ProcessId <pid>." }
  $Path = (Get-Process -Id $ProcessId).Path
}
if (!$Path) { throw "Could not resolve executable path." }

$fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
try {
  $fileSize = [UInt64]$fs.Length
  $readSize = [int][Math]::Min($fs.Length, 0x10000)
  $buf = [byte[]]::new($readSize)
  $read = $fs.Read($buf, 0, $readSize)
  if ($read -lt 0x40) { throw "File prefix is too small." }
  if ($read -ne $readSize) { [Array]::Resize([ref]$buf, $read) }
} finally {
  $fs.Dispose()
}

if ([BitConverter]::ToUInt16($buf, 0) -ne 0x5A4D) { throw "Not an MZ executable." }
$pe = [BitConverter]::ToInt32($buf, 0x3C)
if ($pe -lt 0 -or [BitConverter]::ToUInt32($buf, $pe) -ne 0x4550) { throw "Not a PE executable." }

$fh = $pe + 4
$sections = [BitConverter]::ToUInt16($buf, $fh + 2)
$timestamp = [BitConverter]::ToUInt32($buf, $fh + 4)
$optSize = [BitConverter]::ToUInt16($buf, $fh + 16)
$opt = $fh + 20
$isPe32Plus = [BitConverter]::ToUInt16($buf, $opt) -eq 0x20B
if (!$isPe32Plus) { throw "Discord only fingerprints PE32+." }
$sizeOfImage = [BitConverter]::ToUInt32($buf, $opt + 56)

$sectionTable = $opt + $optSize
$sha256 = [Security.Cryptography.SHA256]::Create()
$headerHash = $sha256.ComputeHash([byte[]]$buf[0..($sectionTable - 1)])
$sectionHash = $sha256.ComputeHash([byte[]]$buf[$sectionTable..($sectionTable + $sections * 40 - 1)])

$machineGuid = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid).MachineGuid
$machineUserHash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($machineGuid + $UserId))

$sig = Get-AuthenticodeSignature -LiteralPath $Path
$signed = $sig.Status -eq "Valid" -and $sig.SignerCertificate
if ($signed) {
  $name = $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
  $certHash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($name) + [CertPubKeyHash]::Hash($sig.SignerCertificate.Handle))
} else {
  $certHash = [byte[]]::new(32)
}

$flags = 0
if ($signed) { $flags += 1 }
if ($isPe32Plus) { $flags += 2 }

$out = [byte[]](@(1, [byte]$flags) +
  [BitConverter]::GetBytes($fileSize) +
  [BitConverter]::GetBytes($timestamp) +
  [BitConverter]::GetBytes($sizeOfImage) +
  $headerHash + $machineUserHash + $sectionHash + $certHash)

$key = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($UserId + "https://discord.com/careers"))
for ($i = 1; $i -lt $out.Length; $i++) {
  $out[$i] = $out[$i] -bxor $key[($i - 1) -band 31]
}

[Convert]::ToBase64String($out)
'''


def generate_fingerprint(user_id: str, path: str = "", pid: int = 0) -> str:
    if os.name != "nt":
        raise RuntimeError("windows uniquement")
    script = Path(tempfile.gettempdir()) / f"dex_{uuid.uuid4().hex}.ps1"
    script.write_text(_FINGERPRINT_PS1, encoding="utf-8")
    try:
        args = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(script), "-UserId", user_id]
        args += (["-ProcessId", str(pid)] if pid else ["-Path", path])
        result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    finally:
        try:
            script.unlink()
        except OSError:
            pass
    if result.returncode != 0:
        lines = (result.stderr or result.stdout or "").strip().splitlines()
        raise RuntimeError(lines[-1] if lines else "powershell a echoue")
    out = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not out:
        raise RuntimeError("aucune sortie")
    return out[-1]


class UI:
    W = 58
    INNER = 56

    def __init__(self) -> None:
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
        if sys.platform == "win32":
            self._ansi()

    @staticmethod
    def _ansi() -> None:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)

    def _w(self, content: str = "") -> str:
        body = _cut(content, self.INNER).replace(R, R + BORDER)
        return f"  {BORDER}│{R}{_pad(body, self.INNER)}{BORDER}│{R}"

    def _top(self, label: str = "", right: str = "") -> None:
        if not label and not right:
            print(f"  {BORDER}╭{'─' * self.INNER}╮{R}")
            return
        gap = max(1, self.INNER - _vlen(label) - _vlen(right) - 3)
        tail = max(0, self.INNER - _vlen(label) - _vlen(right) - gap - 4)
        print(f"  {BORDER}╭─{R} {S35}{label}{R}{' ' * gap}{S35}{right}{R} "
              f"{BORDER}{'─' * tail}╮{R}")

    def _bottom(self) -> None:
        print(f"  {BORDER}╰{'─' * self.INNER}╯{R}")

    def card(self, label: str = "", right: str = "", rows: Sequence[str] = (),
             footer: str = "") -> None:
        self._top(label, right)
        for row in rows:
            print(self._w(row))
        if footer:
            print(self._w(""))
            print(self._w(f" {S35}{footer}"))
        self._bottom()

    def rule(self) -> None:
        print(f"  {BORDER}{'─' * self.W}{R}")

    def blank(self) -> None:
        print()

    def clear(self) -> None:
        print("\x1b[2J\x1b[3J\x1b[H", end="")

    def section(self, num: str, label: str) -> None:
        self.blank()
        print(f"  {S35}{num} / {label}{R}")

    def header(self, sub: str = "") -> None:
        left = f"{SNOW}POKEDOX{R}  {S35}{sub}{R}" if sub else f"{SNOW}POKEDOX{R}"
        print()
        print("  " + _pad(left, self.W - 4) + f"{S35}core{R}")
        self.rule()

    def prompt(self, label: str = "") -> str:
        if label:
            print(f"  {S35}{label}{R}")
        return input(f"  {SNOW}›{R} ").strip()

    def _stamp(self) -> str:
        return f"{DIM}{time.strftime('%H:%M:%S')}{R}"

    def _log(self, glyph: str, color: str, text: str, detail: str = "") -> None:
        tail = f"  {DIM}·{R}  {color}{detail}{R}" if detail else ""
        print(f"  {self._stamp()}  {color}{glyph}{R}  {S55}{text}{R}{tail}")

    def info(self, text: str, detail: str = "") -> None:
        self._log("→", S35, text, detail)

    def ok(self, text: str, detail: str = "") -> None:
        self._log("✓", SNOW, text, detail)

    def warn(self, text: str, detail: str = "") -> None:
        self._log("!", WARN, text, detail)

    def err(self, text: str, detail: str = "") -> None:
        self._log("×", BAD, text, detail)

    def spinner(self, label: str) -> None:
        for frame in ("⠂", "⠒", "⠲", "⠴", "⠦", "⠖"):
            print(f"\r  {S35}{frame}{R}  {S55}{label}{R}   ", end="", flush=True)
            time.sleep(0.08)
        print("\r" + " " * 70 + "\r", end="")

    def boot(self) -> None:
        self.clear()
        self.header("science")
        self.blank()
        self.card("Live frame", "04 signaux", [
            f" {S25}01{R}  token                              {_dot(False)}",
            f" {S25}02{R}  cf_clearance                       {_dot(False)}",
            f" {S25}03{R}  fingerprint                        {_dot(False)}",
            f" {S25}04{R}  analytics                          {_dot(False)}",
        ], "Initialisation · session locale")


@dataclass
class State:
    token: str = ""
    cookie: str = ""
    fingerprint: str = ""
    analytics_token: str = ""
    fetched_at: int = 0
    injected: list[str] = field(default_factory=list)
    pushed: int = 0
    hours: float = 0.0
    hall_of_fame: bool = False
    league: bool = False

    @classmethod
    def load(cls) -> "State":
        if STATE_FILE.exists():
            try:
                data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
                return cls(**{k: data.get(k, v) for k, v in cls().__dict__.items()})
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
        for legacy in LEGACY_FILES:
            if not legacy.exists():
                continue
            try:
                old = json.loads(legacy.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            return cls(
                token=old.get("token", ""),
                cookie=old.get("cookie", ""),
                fingerprint=old.get("fingerprint", ""),
                analytics_token=old.get("analytics_token", ""),
                fetched_at=int(old.get("fetched_at", 0) or 0),
                injected=old.get("injected") or old.get("caught") or old.get("used_games") or [],
                pushed=int(old.get("pushed") or old.get("total_caught")
                           or old.get("total_games_claimed") or 0),
                hours=float(old.get("hours") or old.get("total_hours")
                            or old.get("total_hours_claimed") or 0.0),
                hall_of_fame=bool(old.get("hall_of_fame") or old.get("subscribed")),
                league=bool(old.get("league") or old.get("joined_discord")),
            )
        return cls()

    def save(self) -> None:
        try:
            STATE_FILE.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        except OSError:
            pass

    @property
    def is_stale(self) -> bool:
        return not self.analytics_token or (time.time() - self.fetched_at) > AUTH_MAX_AGE

    @property
    def has_cookie(self) -> bool:
        return bool(self.cookie.strip())

    @property
    def has_token(self) -> bool:
        return bool(self.token.strip())

    @property
    def signals(self) -> int:
        return sum((self.has_token, self.has_cookie, bool(self.fingerprint),
                    bool(self.analytics_token)))


def _local_props() -> dict:
    return {
        "os": "Windows",
        "browser": "Discord Client",
        "release_channel": "stable",
        "client_version": CLIENT_VERSION,
        "os_version": OS_VERSION,
        "os_arch": "x64",
        "app_arch": "x64",
        "system_locale": "en-GB",
        "has_client_mods": False,
        "browser_user_agent": USER_AGENT,
        "browser_version": "42.7.1",
        "os_sdk_version": "26200",
        "client_build_number": CLIENT_BUILD_NUMBER,
        "native_build_number": NATIVE_BUILD_NUMBER,
        "client_event_source": None,
        "client_app_state": "focused",
    }


def build_super_props(launch_signature: str, heartbeat_session: str) -> str:
    try:
        req = urllib.request.Request(PROPERTIES_URL, method="POST", data=b"{}",
                                     headers={"content-type": "application/json",
                                              "user-agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=10) as response:
            props = json.loads(response.read().decode("utf-8"))["properties"]
    except Exception:
        props = _local_props()
    props["client_launch_id"] = str(uuid.uuid4())
    props["launch_signature"] = launch_signature
    props["client_heartbeat_session_id"] = heartbeat_session
    raw = json.dumps(props, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _read_analytics_token(auth_token: str, super_props: str) -> str:
    req = urllib.request.Request(ME_URL, headers={
        "authorization": auth_token,
        "user-agent": USER_AGENT,
        "x-super-properties": super_props,
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"token rejete ({exc.code})") from exc
    except Exception as exc:
        raise RuntimeError("reseau indisponible") from exc
    token = data.get("analytics_token")
    if not token:
        raise RuntimeError("analytics_token absent")
    return token


def ensure_token(state: State, super_props: str) -> None:
    if not state.is_stale:
        return
    state.analytics_token = _read_analytics_token(state.token, super_props)
    state.fetched_at = int(time.time())
    state.save()


@dataclass(frozen=True)
class Session:
    heartbeat_session: str
    launch_signature: str
    super_props: str

    @classmethod
    def new(cls) -> "Session":
        hb = str(uuid.uuid4())
        sig = str(uuid.uuid4())
        return cls(hb, sig, build_super_props(sig, hb))


@dataclass(frozen=True)
class Target:
    no: int
    id: str
    name: str
    exe: str

    @property
    def tag(self) -> str:
        return f"{self.no:04d}"


def _win_exe(entry: dict) -> str:
    for item in entry.get("executables", []):
        if item.get("os") == "win32" and item.get("name"):
            return item["name"]
    return "game.exe"


def _download_dex() -> str:
    request = urllib.request.Request(DEX_CDN_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read().decode("utf-8")
    try:
        DEX_FILE.parent.mkdir(parents=True, exist_ok=True)
        DEX_FILE.write_text(raw, encoding="utf-8")
    except OSError:
        pass
    return raw


def _parse_dex(raw: str) -> list[Target]:
    data = json.loads(raw)
    targets: list[Target] = []
    seen: set[str] = set()
    no = 0
    for entry in data:
        gid = str(entry.get("id", ""))
        if not gid.isdigit() or gid in seen:
            continue
        if not any(e.get("os") == "win32" and e.get("name") for e in entry.get("executables", [])):
            continue
        seen.add(gid)
        no += 1
        targets.append(Target(no, gid, entry.get("name", "Inconnu"), _win_exe(entry)))
    return targets


def load_dex() -> list[Target]:
    raw = ""
    if DEX_FILE.exists():
        try:
            raw = DEX_FILE.read_text(encoding="utf-8").strip()
        except OSError:
            raw = ""
    if raw:
        try:
            targets = _parse_dex(raw)
            if targets:
                return targets
        except (json.JSONDecodeError, ValueError):
            pass
    try:
        return _parse_dex(_download_dex())
    except Exception:
        return []


class Client:
    def __init__(self, state: State, session: Session) -> None:
        self.state = state
        self.session = session
        self._seq = 0

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def build_launch(self, target: Target) -> dict:
        now = int(time.time() * 1000)
        props = {
            "client_track_timestamp": now,
            "client_heartbeat_session_id": self.session.heartbeat_session,
            "event_sequence_number": self._next_seq(),
            "game": target.name,
            "game_id": target.id,
            "verified": True,
            "elevated": False,
            "is_launcher": False,
            "game_platform": "desktop",
            "detection_method": "verified_game",
            "is_overlay_enabled": False,
            "is_overlay_game_enabled": True,
            "is_overlay_game_source": "OOP_DEFAULT_DATABASE",
            "fullscreen_type": "UNKNOWN",
            "hardware_display_count": 1,
            "overlay_method": "Disabled",
            "activity_status_enabled": True,
            "activity_status_shared_guilds": [],
            "current_user_status": "online",
            "game_detection_enabled": True,
            "executable_path": target.exe,
            "voice_channel_id": None,
            "voice_channel_type": None,
            "voice_channel_bitrate": None,
            "voice_channel_guild_id": None,
            "hidden_by_distributor": False,
            "game_metadata": None,
            "executable_fingerprint": self.state.fingerprint,
            "client_performance_cpu": None,
            "client_performance_memory": None,
            "cpu_core_count": None,
            "accessibility_features": 0,
            "rendered_locale": "en-GB",
            "launch_signature": self.session.launch_signature,
            "client_rtc_state": None,
            "client_app_state": "focused",
            "client_send_timestamp": now,
        }
        if not self.state.fingerprint:
            del props["executable_fingerprint"]
        return {"type": "launch_game", "properties": props}

    def build_heartbeat(self, target: Target, duration_ms: int, session_id: str,
                        initial: bool, final: bool, ts: int | None = None) -> dict:
        ts = int(time.time() * 1000) if ts is None else ts
        return {
            "type": "running_game_heartbeat",
            "properties": {
                "client_track_timestamp": ts,
                "client_heartbeat_session_id": self.session.heartbeat_session,
                "event_sequence_number": self._next_seq(),
                "game_id": target.id,
                "game_name": target.name,
                "game_metadata": None,
                "game_executable": target.exe,
                "game_detection_enabled": True,
                "initial_heartbeat": initial,
                "final_heartbeat": final,
                "game_session_id": session_id,
                "duration_tracked_ms": duration_ms,
                "rtc_connection_id": None,
                "media_session_id": None,
                "launch_signature": self.session.launch_signature,
                "client_app_state": "focused",
                "client_send_timestamp": ts,
            },
        }

    def build_session(self, target: Target, duration_ms: int) -> list[dict]:
        sid = str(uuid.uuid4())
        now = int(time.time() * 1000)
        start = now - duration_ms
        if start < 0:
            start = now
        return [
            self.build_heartbeat(target, 0, sid, initial=True, final=False, ts=start),
            self.build_launch(target),
            self.build_heartbeat(target, duration_ms, sid, initial=False, final=True, ts=now),
        ]

    def post(self, events: Sequence[dict]) -> int:
        payload = {"token": self.state.analytics_token, "events": list(events)}
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "accept": "*/*",
            "accept-language": "en-GB",
            "authorization": self.state.token,
            "content-type": "application/json",
            "cookie": self.state.cookie,
            "origin": "https://discord.com",
            "referer": "https://discord.com/channels/@me",
            "user-agent": USER_AGENT,
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": "en-GB",
            "x-discord-timezone": "Europe/Oslo",
            "x-super-properties": self.session.super_props,
        }
        if DEBUG:
            print("\n" + "=" * 72)
            print(f"POST {SCIENCE_URL} ({len(payload['events'])} events)")
            print("headers:", json.dumps(headers, indent=2))
            print("body:", json.dumps(payload, indent=2))
            print("=" * 72)
        request = urllib.request.Request(SCIENCE_URL, data=body, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except Exception:
            return 0


def _chunked(items: Sequence[Target], size: int) -> Iterator[Sequence[Target]]:
    for start in range(0, len(items), size):
        yield items[start:start + size]


class Runner:
    def __init__(self, client: Client, ui: UI) -> None:
        self.client = client
        self.ui = ui

    def run(self, targets: Sequence[Target], build_events) -> int:
        total = len(targets)
        sent = 0
        for request_no, chunk in enumerate(_chunked(targets, BATCH_SIZE), start=1):
            events = []
            for target in chunk:
                events.extend(build_events(target))
            status = self.client.post(events)
            if status == 204:
                sent += len(chunk)
                self.ui.ok(f"lot {request_no:02d}", f"{sent}/{total}")
            elif status in (401, 403):
                self.ui.err(f"lot {request_no:02d}", f"[{status}] token rejete · option 02")
                return sent
            else:
                self.ui.warn(f"lot {request_no:02d}", f"[{status}]")
            time.sleep(BATCH_DELAY)
        return sent


class App:
    def __init__(self, ui: UI | None = None) -> None:
        self.ui = ui or UI()
        self.state = State.load()
        self.session: Session | None = None
        self.client: Client | None = None
        self.targets: list[Target] = []

    def _flush(self) -> None:
        try:
            if sys.platform == "win32":
                import msvcrt
                while msvcrt.kbhit():
                    msvcrt.getwch()
            else:
                import termios
                termios.tcflush(sys.stdin, termios.TCIFLUSH)
        except Exception:
            pass

    def _new_session(self) -> None:
        self.session = Session.new()
        self.client = Client(self.state, self.session)

    def _gate_step(self, step: int, total: int, action: str, label: str,
                   url: str, done: str) -> None:
        ui = self.ui
        ui.clear()
        ui.header("acces")
        ui.section("00", "Acces")
        ui.blank()
        print(f"  {S55}Un compte ouvre la recherche. Deux formalites.{R}")
        ui.blank()
        print(f"  {S35}Etape {step} / {total}{R}")
        print(f"  {SNOW}{action}{R}")
        print(f"  {S25}{label}{R}")
        ui.blank()
        print(f"  {S35}ouverture navigateur…{R}")
        webbrowser.open(url)
        for left in range(GATE_WAIT, 0, -1):
            print(f"\r  {S25}disponible dans {left}s{R}   ", end="", flush=True)
            time.sleep(1)
        print("\r" + " " * 34 + "\r", end="")
        self._flush()
        ui.prompt(f"entree quand tu as {done}")
        ui.blank()

    def _gate(self) -> None:
        steps = [
            ("hall_of_fame", "s'abonner a la chaine", "youtube.com/@moufid-en-short",
             SUBSCRIBE_URL, "fini"),
            ("league", "rejoindre le discord", LEAGUE_LABEL, LEAGUE_URL, "fini"),
        ]
        for i, (flag, action, label, url, done) in enumerate(steps, 1):
            if getattr(self.state, flag):
                continue
            self._gate_step(i, len(steps), action, label, url, done)
            setattr(self.state, flag, True)
            self.state.save()

    def start(self) -> None:
        ui = self.ui
        ui.boot()
        time.sleep(0.7)

        if not (self.state.hall_of_fame and self.state.league):
            self._gate()

        if not self.state.has_token:
            ui.clear()
            ui.header("acces")
            ui.section("01", "Signal")
            ui.blank()
            print(f"  {S55}Colle le token du compte.{R}")
            ui.blank()
            entered = ui.prompt("token")
            if entered:
                self.state.token = entered
                self.state.save()
                ui.ok("token", "enregistre")
        else:
            ui.ok("token", "charge")
        if not self.state.has_token:
            ui.err("token", "obligatoire")
            ui.prompt("entree pour fermer")
            return
        time.sleep(0.3)

        if not self.state.has_cookie:
            ui.clear()
            ui.header("acces")
            ui.section("02", "Signal")
            ui.blank()
            print(f"  {S55}Colle l'en-tete cookie.{R}")
            ui.blank()
            entered = ui.prompt("cf_clearance")
            if entered:
                self.state.cookie = entered
                self.state.save()
                ui.ok("cf_clearance", "enregistre")
        else:
            ui.ok("cf_clearance", "charge")
        if not self.state.has_cookie:
            ui.err("cf_clearance", "obligatoire")
            ui.prompt("entree pour fermer")
            return
        time.sleep(0.3)

        ui.clear()
        ui.header("index")
        ui.section("03", "Index")
        ui.blank()
        ui.spinner("lecture du dex")
        self.targets = load_dex()
        if not self.targets:
            ui.err("index", "echec du chargement")
            ui.info("source", DEX_CDN_URL)
            ui.prompt("entree pour fermer")
            return
        ui.ok("index", f"{len(self.targets)} cibles")
        time.sleep(0.3)

        if not self.state.fingerprint:
            ui.warn("fingerprint", "non calibre · badge incertain")

        ui.blank()
        ui.spinner("verification du token")
        self._new_session()
        try:
            ensure_token(self.state, self.session.super_props)
        except Exception as exc:
            ui.err("token", str(exc))
            ui.prompt("entree pour fermer")
            return
        ui.ok("token", "valide")
        time.sleep(0.4)
        self.menu()

    def menu(self) -> None:
        ui = self.ui
        while True:
            ui.clear()
            ui.header("science")
            ui.section("01", "Signal")
            ui.card("Live frame", f"{self.state.signals:02d} signaux", [
                f" {S25}01{R}  token                              {_dot(self.state.has_token)}",
                f" {S25}02{R}  cf_clearance                       {_dot(self.state.has_cookie)}",
                f" {S25}03{R}  fingerprint                        {_dot(bool(self.state.fingerprint))}",
                f" {S25}04{R}  analytics                          {_dot(bool(self.state.analytics_token))}",
            ], "Pret · session locale")

            ui.section("02", "Couverture")
            ui.card("Index", f"{len(self.state.injected)} / {len(self.targets)}", [
                f" {S25}cibles{R}     {SNOW}{len(self.targets):,}{R} {S55}indexees{R}",
                f" {S25}injectees{R}  {SNOW}{len(self.state.injected):,}{R} "
                f"{S55}· {self.state.hours:,.0f}h cumulees{R}",
            ])

            ui.section("03", "Actions")
            ui.card(rows=[
                f" {S25}01{R}  injecter du temps de jeu",
                f" {S25}02{R}  rafraichir la session",
                f" {S25}03{R}  calibrer le fingerprint",
                f" {S25}04{R}  fiche session",
                f" {S25}05{R}  quitter",
            ])

            ui.rule()
            choice = ui.prompt()
            ui.blank()
            if choice == "1":
                self.inject()
            elif choice == "2":
                self.refresh()
            elif choice == "3":
                self.calibrate()
            elif choice == "4":
                self.sheet()
            elif choice in ("5", ""):
                break
            else:
                ui.warn("entree", "option inconnue")
                time.sleep(0.9)

    def refresh(self) -> None:
        ui = self.ui
        ui.clear()
        ui.header("session")
        ui.section("01", "Session")
        ui.blank()
        if ui.prompt("nouveau cf_clearance ? [y/n]").lower() in ("y", "yes"):
            entered = ui.prompt("cf_clearance")
            if entered:
                self.state.cookie = entered
                ui.ok("cf_clearance", "remplace")
            else:
                ui.info("cf_clearance", "inchange")
        ui.spinner("refetch du token")
        try:
            self.state.fetched_at = 0
            ensure_token(self.state, self.session.super_props)
        except Exception as exc:
            ui.err("token", str(exc))
            ui.prompt("entree pour revenir")
            return
        self._new_session()
        self.state.save()
        ui.clear()
        ui.header("session")
        ui.section("01", "Session")
        ui.card("Resultat", "soignee", [
            f" {S25}token{R}      {_dot(True)}  {S55}rafraichi{R}",
            f" {S25}clearance{R}  {_dot(self.state.has_cookie)}  "
            f"{S55}{'ok' if self.state.has_cookie else 'vide'}{R}",
        ], "pret · session locale")
        time.sleep(1.2)

    def _ready(self) -> bool:
        if not self.state.has_cookie:
            self.ui.err("cf_clearance", "absent · option 02")
            return False
        if self.state.is_stale:
            try:
                ensure_token(self.state, self.session.super_props)
            except Exception as exc:
                self.ui.err("token", str(exc))
                return False
            self._new_session()
        return bool(self.state.analytics_token)

    def inject(self) -> None:
        ui = self.ui
        ui.clear()
        ui.header("injection")
        if not self._ready():
            ui.blank()
            ui.prompt("entree pour revenir")
            return
        ui.section("01", "Requete")
        ui.blank()
        raw_count = ui.prompt(f"cibles [tout · {len(self.targets)}]")
        try:
            count = int(raw_count) if raw_count else len(self.targets)
        except ValueError:
            ui.err("entree", "nombre invalide")
            time.sleep(1.2)
            return
        count = min(count, len(self.targets))

        raw_hours = ui.prompt("heures par cible [1]")
        try:
            hours = float(raw_hours) if raw_hours else 1.0
        except ValueError:
            ui.err("entree", "heures invalides")
            time.sleep(1.2)
            return

        picked = self._pick(count)
        if not picked:
            ui.err("cibles", "aucune selection")
            time.sleep(1.2)
            return

        duration_ms = int(hours * 3600 * 1000)
        total_hours = len(picked) * hours
        preview = [f" {S25}{t.tag}{R}  {S55}{t.name}{R}" for t in picked[:6]]
        if len(picked) > 6:
            preview.append(f" {S25}… {len(picked) - 6} de plus{R}")

        ui.clear()
        ui.header("injection")
        ui.section("01", "Execution")
        ui.card("Cibles", f"{len(picked)}", [
            f" {S55}{hours:g}h par cible · {total_hours:,.0f}h au total{R}",
            "",
            *preview,
        ], "envoi par lots de 50")
        ui.blank()

        sent = Runner(self.client, ui).run(picked, lambda t: self.client.build_session(t, duration_ms))

        self.state.pushed += sent
        self.state.hours += sent * hours
        self.state.save()

        ui.clear()
        ui.header("rapport")
        ui.section("01", "Rapport")
        ui.card("Resultat", f"{sent}/{len(picked)}", [
            f" {SNOW}{sent:,}{R} {S55}cibles injectees{R}",
            f" {SNOW}{sent * hours:,.0f}h{R} {S55}creditees{R}",
            "",
            f" {S25}cumul{R}  {self.state.pushed:,} cibles · {self.state.hours:,.0f}h",
            f" {S25}index{R}  {len(self.state.injected):,} / {len(self.targets):,}",
        ], "entree pour revenir")
        ui.prompt()

    def _pick(self, count: int) -> list[Target]:
        known = {t.id for t in self.targets}
        fresh = [t.id for t in self.targets if t.id not in self.state.injected]
        old = [tid for tid in self.state.injected if tid in known]

        if len(fresh) >= count:
            chosen = fresh[:count]
        else:
            chosen = list(fresh)
            if old:
                remaining = count - len(chosen)
                rotated = old[remaining:] + old[:remaining]
                chosen.extend(rotated[:remaining])

        self.state.injected = [tid for tid in self.state.injected if tid not in chosen] + chosen
        index = {t.id: t for t in self.targets}
        return [index[tid] for tid in chosen if tid in index]

    def calibrate(self) -> None:
        ui = self.ui
        ui.clear()
        ui.header("fingerprint")
        uid = _user_id_from_token(self.state.token)
        if not uid:
            ui.err("fingerprint", "token absent")
            ui.prompt("entree pour revenir")
            return
        if os.name != "nt":
            ui.err("fingerprint", "windows uniquement")
            ui.prompt("entree pour revenir")
            return
        ui.section("01", "Signal")
        ui.blank()
        print(f"  {S55}Genere un executable_fingerprint lie au compte et a la machine.{R}")
        print(f"  {S25}compte {uid}{R}")
        ui.blank()
        entered = ui.prompt("chemin .exe ou pid").strip('"')
        if not entered:
            ui.info("fingerprint", "annule")
            time.sleep(1)
            return
        pid = int(entered) if entered.isdigit() else 0
        path = "" if pid else entered
        if path and not Path(path).exists():
            ui.err("fingerprint", f"introuvable: {path}")
            time.sleep(1.5)
            return
        ui.spinner("lecture des metadonnees PE")
        try:
            fp = generate_fingerprint(uid, path=path, pid=pid)
        except Exception as exc:
            ui.err("fingerprint", str(exc))
            ui.prompt("entree pour revenir")
            return
        self.state.fingerprint = fp
        self.state.save()
        ui.clear()
        ui.header("fingerprint")
        ui.section("01", "Signal")
        ui.card("Resultat", "calibre", [
            f" {S25}print{R}     {_dot(True)}  {S55}{len(fp)} car.{R}",
            f" {S25}compte{R}    {S55}{uid}{R}",
        ], "pret · session locale")
        time.sleep(1.2)

    def sheet(self) -> None:
        ui = self.ui
        ui.clear()
        ui.header("fiche")
        uid = _user_id_from_token(self.state.token)
        ui.section("01", "Identite")
        ui.card("Identite", "locale", [
            f" {S25}id{R}         {SNOW}{uid or '—'}{R}",
            f" {S25}token{R}      {S55}{_mask(self.state.token) or '—'}{R}",
            f" {S25}clearance{R}  {_dot(self.state.has_cookie)}  "
            f"{S55}{'ok' if self.state.has_cookie else 'vide'}{R}",
            f" {S25}print{R}      {_dot(bool(self.state.fingerprint))}  "
            f"{S55}{'calibre' if self.state.fingerprint else 'non calibre'}{R}",
        ])
        ui.section("02", "Volume")
        ui.card("Volume", "cumul", [
            f" {S25}cibles{R}    {SNOW}{len(self.state.injected):,}{R} {S55}/ {len(self.targets):,}{R}",
            f" {S25}poussees{R}  {SNOW}{self.state.pushed:,}{R}",
            f" {S25}heures{R}    {SNOW}{self.state.hours:,.0f}{R}",
        ], "usage interne")
        ui.rule()
        ui.prompt()


def main() -> None:
    ui = UI()
    try:
        App(ui).start()
    except KeyboardInterrupt:
        ui.warn("sortie", "interrompu")
    except Exception as exc:
        ui.err("crash", repr(exc))
        raise
    finally:
        print()
        try:
            input(f"  {S25}entree pour fermer{R} ")
        except (EOFError, KeyboardInterrupt):
            pass


if __name__ == "__main__":
    main()
