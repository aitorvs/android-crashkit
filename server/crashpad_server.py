#!/usr/bin/env python3
"""
Local Crashpad minidump ingestion server.

Accepts multipart POST uploads from Crashpad, saves .dmp files to ./dumps/,
and returns a CrashID so Crashpad marks the report as completed.

No third-party dependencies — stdlib only, works on Python 3.8+.

Usage:
    python3 crashpad_server.py             # default: port 8080
    python3 crashpad_server.py --port 9000
    python3 crashpad_server.py --dumps /tmp/dumps --port 8080

Upload endpoint:  POST /upload
Health check:     GET  /
Dump list:        GET  /dumps             (JSON)
Crash UI:         GET  /crashes           (HTML)
Crash detail:     GET  /crash/<filename>  (HTML)
Download dump:    GET  /crash/<filename>/download
"""

import argparse
import gzip
import html
import json
import os
import shutil
import socket
import struct
import subprocess
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional


def parse_args():
    p = argparse.ArgumentParser(description="Local Crashpad minidump server")
    p.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    p.add_argument("--dumps", default="dumps", help="Directory to save minidumps (default: ./dumps)")
    p.add_argument("--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
    return p.parse_args()


DUMPS_DIR = "dumps"  # overridden by args at startup

# ── Minidump parsing ──────────────────────────────────────────────────────────

_MDMP_SIGNATURE = b"MDMP"
_STREAM_THREAD_LIST   = 3
_STREAM_MODULE_LIST   = 4
_STREAM_EXCEPTION     = 6
_STREAM_SYSTEM_INFO   = 7
_STREAM_CRASHPAD_INFO = 0x43500001

# crashpad::Annotation::Type
# Upstream Crashpad uses kString=2; Chromium's fork (used by WebView) uses kString=1.
_ANN_TYPE_STRING = (1, 2)

_EXCEPTION_CODES = {
    0xC0000005: "EXCEPTION_ACCESS_VIOLATION (SIGSEGV)",
    0xC000001D: "EXCEPTION_ILLEGAL_INSTRUCTION (SIGILL)",
    0x80000003: "EXCEPTION_BREAKPOINT (SIGTRAP)",
    0xC0000025: "EXCEPTION_NONCONTINUABLE_EXCEPTION",
    0xC0000094: "EXCEPTION_INT_DIVIDE_BY_ZERO (SIGFPE)",
    0xC0000096: "EXCEPTION_PRIVILEGED_INSTRUCTION (SIGBUS)",
    0x80000004: "EXCEPTION_SINGLE_STEP",
    0xC000008C: "EXCEPTION_ARRAY_BOUNDS_EXCEEDED",
    0xC00000FD: "EXCEPTION_STACK_OVERFLOW",
    # Android / Bionic signals mapped by Crashpad
    0x00000006: "SIGABRT",
    0x00000007: "SIGBUS",
    0x00000008: "SIGFPE",
    0x00000004: "SIGILL",
    0x0000000B: "SIGSEGV",
    0x0000000D: "SIGPIPE",
}

_PROCESSOR_ARCH = {
    0: "x86", 6: "IA64", 9: "x86_64", 12: "arm", 0xFFFF: "unknown",
    0x8003: "arm64",
}


def parse_minidump(path: str) -> dict:
    """
    Parse a minidump and return a dict with crash metadata.
    Keys present when available:
      exception_code, exception_code_str, exception_address,
      crash_thread_id, num_threads, processor_arch, modules
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return {}

    if len(data) < 32 or data[:4] != _MDMP_SIGNATURE:
        return {}

    # MINIDUMP_HEADER layout (offset 0):
    #   0  Signature          4
    #   4  Version            4
    #   8  NumberOfStreams     4
    #  12  StreamDirectoryRva 4
    #  16  CheckSum           4
    #  20  TimeDateStamp      4
    #  24  Flags              8
    num_streams, stream_dir_rva = struct.unpack_from("<II", data, 8)

    # Stream directory: array of (StreamType:4, DataSize:4, Rva:4)
    streams = {}
    for i in range(num_streams):
        off = stream_dir_rva + i * 12
        if off + 12 > len(data):
            break
        stype, dsize, rva = struct.unpack_from("<III", data, off)
        streams[stype] = (rva, dsize)

    result = {}

    # ExceptionStream (type 6)
    # MINIDUMP_EXCEPTION_STREAM:
    #   ThreadId        4
    #   __alignment     4
    # MINIDUMP_EXCEPTION:
    #   ExceptionCode   4
    #   ExceptionFlags  4
    #   ExceptionRecord 8  (ptr)
    #   ExceptionAddress 8
    if _STREAM_EXCEPTION in streams:
        rva, size = streams[_STREAM_EXCEPTION]
        if rva + 28 <= len(data):
            thread_id, _, exc_code, exc_flags = struct.unpack_from("<IIII", data, rva)
            exc_addr, = struct.unpack_from("<Q", data, rva + 16)
            result["crash_thread_id"] = thread_id
            result["exception_code"] = exc_code
            result["exception_code_str"] = _EXCEPTION_CODES.get(exc_code, f"0x{exc_code:08X}")
            result["exception_address"] = exc_addr

    # ThreadListStream (type 3) — just count
    if _STREAM_THREAD_LIST in streams:
        rva, _ = streams[_STREAM_THREAD_LIST]
        if rva + 4 <= len(data):
            result["num_threads"], = struct.unpack_from("<I", data, rva)

    # SystemInfoStream (type 7)
    # ProcessorArchitecture: 2 bytes at offset 0
    if _STREAM_SYSTEM_INFO in streams:
        rva, size = streams[_STREAM_SYSTEM_INFO]
        if rva + 2 <= len(data):
            arch, = struct.unpack_from("<H", data, rva)
            result["processor_arch"] = _PROCESSOR_ARCH.get(arch, f"arch_{arch}")

    # ModuleListStream (type 4) — name + base address
    if _STREAM_MODULE_LIST in streams:
        rva, size = streams[_STREAM_MODULE_LIST]
        if rva + 4 <= len(data):
            num_mods, = struct.unpack_from("<I", data, rva)
            modules = []
            # MINIDUMP_MODULE size = 108 bytes
            for i in range(min(num_mods, 256)):
                moff = rva + 4 + i * 108
                if moff + 108 > len(data):
                    break
                base_addr, = struct.unpack_from("<Q", data, moff)
                mod_size, = struct.unpack_from("<I", data, moff + 8)
                name_rva, = struct.unpack_from("<I", data, moff + 28)
                mod_name = _read_minidump_string(data, name_rva)
                modules.append({
                    "name": os.path.basename(mod_name) if mod_name else "?",
                    "base": base_addr,
                    "size": mod_size,
                })
            result["modules"] = modules

    # CrashpadInfoStream — our annotations + WebView-injected typed annotations
    cp = _parse_crashpad_annotations(data, streams)
    result["dmp_simple_annotations"] = cp["simple"]
    result["dmp_typed_annotations"]  = cp["typed"]

    return result


def _read_minidump_string(data: bytes, rva: int) -> str:
    """Read a MINIDUMP_STRING (4-byte length in bytes + UTF-16LE chars)."""
    if rva == 0 or rva + 4 > len(data):
        return ""
    length, = struct.unpack_from("<I", data, rva)
    start = rva + 4
    if start + length > len(data):
        return ""
    return data[start:start + length].decode("utf-16-le", errors="replace")


def _read_utf8_string(data: bytes, rva: int) -> str:
    """Read a MinidumpUTF8String (4-byte length + UTF-8 bytes, no null terminator)."""
    if rva == 0 or rva + 4 > len(data):
        return ""
    length, = struct.unpack_from("<I", data, rva)
    start = rva + 4
    if start + length > len(data):
        return ""
    return data[start:start + length].decode("utf-8", errors="replace")


def _parse_crashpad_annotations(data: bytes, streams: dict) -> dict:
    """
    Parse annotations from CrashpadInfoStream (0x43500001).

    Returns a dict with:
      "simple"  – dict[str, str]  from SimpleStringDictionary (our StartHandler annotations)
      "typed"   – list[(name, value)]  from per-module AnnotationList (WebView-injected)

    Binary layout reference:
      MinidumpCrashpadInfo (52 bytes):
        version             uint32   @ 0
        report_id           UUID(16) @ 4
        client_id           UUID(16) @ 20
        simple_annotations  LOCATION_DESCRIPTOR(8) @ 36  → MinidumpSimpleStringDictionary
        module_list         LOCATION_DESCRIPTOR(8) @ 44  → MinidumpModuleCrashpadInfoList

      MinidumpSimpleStringDictionary:
        count uint32; entries[]: { key_rva(4), val_rva(4) } → MINIDUMP_STRING (UTF-16)

      MinidumpModuleCrashpadInfoList:
        count uint32; children[]: { module_index(4), loc_size(4), loc_rva(4) }

      MinidumpModuleCrashpadInfo (28 bytes):
        version(4), list_annotations LOCATION(8), simple_annotations LOCATION(8),
        annotation_objects LOCATION(8) → MinidumpAnnotationList

      MinidumpAnnotationList:
        count uint32; objects[]: { name_rva(4), type(2), reserved(2), value_rva(4) }
        name/value are MinidumpUTF8String (uint32 len + UTF-8 bytes)
    """
    result = {"simple": {}, "typed": []}

    if _STREAM_CRASHPAD_INFO not in streams:
        return result

    rva, size = streams[_STREAM_CRASHPAD_INFO]

    if rva + 52 > len(data):
        return result

    version, = struct.unpack_from("<I", data, rva)

    # simple_annotations LOCATION_DESCRIPTOR @ offset 36
    sa_size, sa_rva = struct.unpack_from("<II", data, rva + 36)

    # module_list LOCATION_DESCRIPTOR @ offset 44
    ml_size, ml_rva = struct.unpack_from("<II", data, rva + 44)

    # ── SimpleStringDictionary ──
    # Keys and values are MinidumpUTF8String (uint32 length + UTF-8 bytes), not MINIDUMP_STRING.
    if sa_rva and sa_rva + 4 <= len(data):
        count, = struct.unpack_from("<I", data, sa_rva)
        for i in range(min(count, 512)):
            eoff = sa_rva + 4 + i * 8
            if eoff + 8 > len(data):
                break
            key_rva, val_rva = struct.unpack_from("<II", data, eoff)
            key = _read_utf8_string(data, key_rva)
            val = _read_utf8_string(data, val_rva)
            if key:
                result["simple"][key] = val

    # ── Per-module AnnotationList (typed / WebView annotations) ──
    if ml_rva and ml_rva + 4 <= len(data):
        mod_count, = struct.unpack_from("<I", data, ml_rva)
        for i in range(min(mod_count, 256)):
            # MinidumpModuleCrashpadInfoLink: module_index(4) + DataSize(4) + RVA(4)
            link_off = ml_rva + 4 + i * 12
            if link_off + 12 > len(data):
                break
            _mod_idx, _loc_size, loc_rva = struct.unpack_from("<III", data, link_off)

            # MinidumpModuleCrashpadInfo: version(4) + list_ann(8) + simple_ann(8) + ann_objects(8)
            if loc_rva + 28 > len(data):
                continue

            ms_size, ms_rva = struct.unpack_from("<II", data, loc_rva + 12)
            ao_size, ao_rva = struct.unpack_from("<II", data, loc_rva + 20)

            # Per-module simple_annotations (MinidumpSimpleStringDictionary, UTF-8)
            if ms_rva and ms_rva + 4 <= len(data):
                ms_count, = struct.unpack_from("<I", data, ms_rva)
                for j in range(min(ms_count, 512)):
                    eoff = ms_rva + 4 + j * 8
                    if eoff + 8 > len(data):
                        break
                    key_rva, val_rva = struct.unpack_from("<II", data, eoff)
                    key = _read_utf8_string(data, key_rva)
                    val = _read_utf8_string(data, val_rva)
                    if key:
                        result["typed"].append((key, val))

            # Per-module annotation_objects (MinidumpAnnotationList, typed)
            if not ao_rva or ao_rva + 4 > len(data):
                continue
            ann_count, = struct.unpack_from("<I", data, ao_rva)
            for j in range(min(ann_count, 512)):
                # MinidumpAnnotation: name_rva(4) + type(2) + reserved(2) + value_rva(4)
                aoff = ao_rva + 4 + j * 12
                if aoff + 12 > len(data):
                    break
                name_rva, ann_type, _reserved, val_rva = struct.unpack_from("<IHHI", data, aoff)
                if ann_type not in _ANN_TYPE_STRING:
                    continue
                name = _read_utf8_string(data, name_rva)
                val  = _read_utf8_string(data, val_rva)
                if name:
                    result["typed"].append((name, val))

    return result


# ── minidump_stackwalk ────────────────────────────────────────────────────────

def _find_stackwalk() -> Optional[str]:
    for name in ("minidump_stackwalk", "minidump-stackwalk"):
        path = shutil.which(name)
        if path:
            return path
    return None


def run_stackwalk(dump_path: str) -> Optional[str]:
    """Run minidump_stackwalk and return its output, or None if unavailable."""
    tool = _find_stackwalk()
    if not tool:
        return None
    try:
        result = subprocess.run(
            [tool, dump_path],
            capture_output=True, text=True, timeout=30,
        )
        return (result.stdout or "") + (result.stderr or "")
    except Exception as e:
        return f"(minidump_stackwalk failed: {e})"


# ── Multipart parser ──────────────────────────────────────────────────────────

def parse_multipart(content_type: str, body: bytes) -> dict:
    boundary = None
    for token in content_type.split(";"):
        token = token.strip()
        if token.lower().startswith("boundary="):
            boundary = token[9:].strip().strip('"')
            break
    if not boundary:
        return {}

    delimiter = f"--{boundary}".encode()
    fields = {}

    for part in body.split(delimiter):
        if part in (b"", b"--", b"--\r\n", b"\r\n") or part.startswith(b"--"):
            continue
        if part.startswith(b"\r\n"):
            part = part[2:]
        if part.endswith(b"\r\n"):
            part = part[:-2]

        sep_idx = part.find(b"\r\n\r\n")
        if sep_idx == -1:
            continue
        headers_raw = part[:sep_idx].decode("utf-8", errors="replace")
        body_bytes = part[sep_idx + 4:]

        name = None
        for line in headers_raw.splitlines():
            if line.lower().startswith("content-disposition:"):
                for token in line.split(";"):
                    token = token.strip()
                    if token.lower().startswith("name="):
                        name = token[5:].strip().strip('"')
                        break
            if name:
                break

        if name is not None:
            fields[name] = body_bytes

    return fields


# ── HTML helpers ──────────────────────────────────────────────────────────────

_CSS = """
body { font-family: system-ui, sans-serif; margin: 0; background: #f5f5f5; color: #222; }
.nav { background: #1a1a2e; color: #eee; padding: 12px 20px; display: flex; align-items: center; gap: 16px; }
.nav a { color: #7eb8f7; text-decoration: none; font-size: 0.9em; }
.nav h1 { margin: 0; font-size: 1.2em; color: #fff; flex: 1; }
.container { max-width: 1100px; margin: 24px auto; padding: 0 16px; }
.card { background: #fff; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,.12); margin-bottom: 16px; overflow: hidden; }
.card-header { padding: 12px 16px; border-bottom: 1px solid #eee; display: flex; align-items: center; gap: 12px; }
.card-header h2 { margin: 0; font-size: 1em; flex: 1; }
.card-body { padding: 16px; }
.badge { background: #e53e3e; color: #fff; border-radius: 4px; padding: 2px 8px; font-size: 0.8em; font-weight: bold; }
.badge.ok { background: #38a169; }
.badge.warn { background: #d69e2e; }
.badge.muted { background: #718096; }
details > summary { cursor: pointer; list-style: none; padding: 12px 16px; font-weight: 600; font-size: 1em; }
details > summary::-webkit-details-marker { display: none; }
details > summary::before { content: "▶ "; font-size: 0.75em; color: #888; }
details[open] > summary::before { content: "▼ "; }
details > .card-body { border-top: 1px solid #eee; }
table { border-collapse: collapse; width: 100%; font-size: 0.9em; }
th { text-align: left; background: #f0f0f0; padding: 6px 10px; font-weight: 600; white-space: nowrap; }
td { padding: 6px 10px; border-top: 1px solid #eee; vertical-align: top; }
td:first-child { color: #555; white-space: nowrap; }
td:nth-child(2) { font-family: monospace; width: 100%; overflow-wrap: break-word; word-break: break-word; }
td:last-child { white-space: nowrap; color: #888; }
pre { background: #1e1e2e; color: #cdd6f4; padding: 16px; border-radius: 6px; overflow-x: auto; font-size: 0.82em; line-height: 1.5; margin: 0; white-space: pre-wrap; word-break: break-all; }
.btn { display: inline-block; padding: 6px 14px; border-radius: 4px; text-decoration: none; font-size: 0.85em; cursor: pointer; border: none; }
.seg { display: inline-flex; border: 1px solid #cbd5e0; border-radius: 4px; overflow: hidden; font-size: 0.82em; }
.seg button { background: #fff; border: none; padding: 3px 10px; cursor: pointer; color: #444; }
.seg button.active { background: #3182ce; color: #fff; }
.seg button:not(:last-child) { border-right: 1px solid #cbd5e0; }
.btn-primary { background: #3182ce; color: #fff; }
.btn-secondary { background: #718096; color: #fff; }
.meta { color: #666; font-size: 0.85em; }
.empty { color: #888; font-style: italic; text-align: center; padding: 32px; }
tr.filtered td { background: #fff5f5; color: #c53030; text-decoration: line-through; opacity: .7; }
tr.filtered td:first-child::after { content: " 🚫"; text-decoration: none; display: inline; }
"""


def _page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="nav">
  <h1>💥 Crashpad Local Server</h1>
  <a href="/crashes">Crashes</a>
  <a href="/">API</a>
</div>
<div class="container">{body}</div>
</body></html>"""


def _crashes_page(entries: list) -> str:
    auto_refresh = """
<script>
(function() {
  var count = document.querySelectorAll('.card').length;
  setInterval(function() {
    fetch('/crashes', {headers: {'X-Check': '1'}})
      .then(function(r) { return r.text(); })
      .then(function(html) {
        var tmp = document.createElement('div');
        tmp.innerHTML = html;
        var newCount = tmp.querySelectorAll('.card').length;
        if (newCount !== count) { location.reload(); }
      }).catch(function(){});
  }, 5000);
})();
</script>"""

    if not entries:
        return _page("Crashes", '<div class="empty">No crashes received yet.</div>' + auto_refresh)

    rows = ""
    for e in reversed(entries):  # newest first
        fname = html.escape(e["file"])
        ts = html.escape(e.get("received", "")[:19].replace("T", " "))
        size = e.get("size_kb", "?")
        ann = e.get("annotations", {})
        version = html.escape(ann.get("version", ""))
        platform = html.escape(ann.get("platform", ""))
        process = html.escape(ann.get("process", ""))
        exc = html.escape(e.get("exc_str", ""))
        exc_badge = f'<span class="badge">{exc}</span>' if exc else ""
        rows += f"""
<div class="card">
  <div class="card-header">
    <div>
      <strong>{fname}</strong> {exc_badge}<br>
      <span class="meta">{ts} &nbsp;·&nbsp; {size} KB &nbsp;·&nbsp; {platform} {version} &nbsp;·&nbsp; {process}</span>
    </div>
    <a class="btn btn-primary" href="/crash/{fname}">View</a>
    <a class="btn btn-secondary" href="/crash/{fname}/download">⬇ .dmp</a>
  </div>
</div>"""

    return _page("Crashes", rows + auto_refresh)


def _detail_page(filename: str, meta: dict, crash_info: dict, stack: Optional[str]) -> str:
    http_ann = meta.get("annotations", {})  # what was sent over HTTP (filtered)
    received = meta.get("received", "")[:19].replace("T", " ")
    size_kb = round(meta.get("size_bytes", 0) / 1024, 1)

    # ── Crash info table ──
    info_items = []
    if "processor_arch" in crash_info:
        info_items.append(("Architecture", crash_info["processor_arch"]))
    if "num_threads" in crash_info:
        info_items.append(("Threads", str(crash_info["num_threads"])))
    if "crash_thread_id" in crash_info:
        info_items.append(("Crashing thread", f"0x{crash_info['crash_thread_id']:X}"))
    if "exception_code" in crash_info:
        info_items.append(("Exception", crash_info.get("exception_code_str", f"0x{crash_info['exception_code']:08X}")))
    if "exception_address" in crash_info:
        info_items.append(("Crash address", f"0x{crash_info['exception_address']:016X}"))

    info_rows = "".join(
        f"<tr><td>{html.escape(k)}</td><td><code>{html.escape(v)}</code></td></tr>"
        for k, v in info_items
    ) or '<tr><td colspan="2" class="empty">could not parse minidump</td></tr>'

    # ── HTTP form fields (what actually reached the server) ──
    http_rows = "".join(
        f"<tr><td>{html.escape(k)}</td><td>{html.escape(str(v))}</td></tr>"
        for k, v in sorted(http_ann.items())
    ) or '<tr><td colspan="2" class="empty">none</td></tr>'

    # ── DMP binary annotations ──
    # simple = our StartHandler annotations (SimpleStringDictionary)
    # typed  = WebView-injected (per-module AnnotationList, kString type)
    dmp_simple = crash_info.get("dmp_simple_annotations", {})
    dmp_typed  = crash_info.get("dmp_typed_annotations", [])

    # Build combined set from DMP, marking each row as allowed or filtered.
    # Deduplicate typed entries (module simple + annotation_objects may overlap).
    seen = set()
    dmp_rows = ""
    for k, v in sorted(dmp_simple.items()):
        seen.add(k)
        filtered = k not in http_ann
        cls = ' class="filtered"' if filtered else ""
        dmp_rows += f"<tr{cls}><td>{html.escape(k)}</td><td>{html.escape(str(v))}</td><td>process</td></tr>"
    for k, v in dmp_typed:
        if k in seen:
            continue
        seen.add(k)
        filtered = k not in http_ann
        cls = ' class="filtered"' if filtered else ""
        dmp_rows += f"<tr{cls}><td>{html.escape(k)}</td><td>{html.escape(str(v))}</td><td>module</td></tr>"

    if not dmp_rows:
        dmp_rows = '<tr><td colspan="3" class="empty">CrashpadInfoStream not found or empty</td></tr>'

    all_dmp_keys = set(dmp_simple.keys()) | {k for k, _ in dmp_typed}
    filtered_count = sum(1 for k in all_dmp_keys if k not in http_ann)
    sent_count = len(all_dmp_keys) - filtered_count
    filtered_badge = f'<span class="badge muted">{sent_count} sent</span> <span class="badge warn">{filtered_count} filtered</span>' if filtered_count else f'<span class="badge ok">{sent_count} sent</span>'

    # ── Modules table (top 20) ──
    modules = crash_info.get("modules", [])[:20]
    mod_rows = "".join(
        f"<tr><td>{html.escape(m['name'])}</td><td><code>0x{m['base']:016X}</code></td><td>{m['size'] // 1024} KB</td></tr>"
        for m in modules
    )
    mod_table = f"""<table>
  <thead><tr><th>Module</th><th>Base address</th><th>Size</th></tr></thead>
  <tbody>{mod_rows or '<tr><td colspan="3" class="empty">none</td></tr>'}</tbody>
</table>""" if modules else '<div class="empty">no module info</div>'

    # ── Stack trace ──
    if stack:
        stack_html = f"<pre>{html.escape(stack)}</pre>"
    else:
        tool = _find_stackwalk()
        if tool is None:
            stack_html = (
                '<div class="empty"><code>minidump_stackwalk</code> not found in PATH.<br><br>'
                'Install: <code>brew install minidump-stackwalk</code><br><br>'
                'Or symbolicate with ndk-stack:<br>'
                '<code>adb logcat | ndk-stack -sym &lt;app/build/intermediates/merged_native_libs/&gt;</code></div>'
            )
        else:
            stack_html = '<div class="empty">stack trace unavailable</div>'

    fname = html.escape(filename)
    body = f"""
<div style="margin-bottom:12px">
  <a href="/crashes">← All crashes</a>
  &nbsp;
  <a class="btn btn-secondary" href="/crash/{fname}/download">⬇ Download .dmp</a>
</div>
<div class="meta" style="margin-bottom:16px">{fname} &nbsp;·&nbsp; {received} &nbsp;·&nbsp; {size_kb} KB</div>

<div class="card">
  <div class="card-header"><h2>Crash Info</h2></div>
  <div class="card-body">
    <table><thead><tr><th>Field</th><th>Value</th></tr></thead>
    <tbody>{info_rows}</tbody></table>
  </div>
</div>

<div class="card">
  <div class="card-header">
    <h2>DMP Binary Annotations</h2> {filtered_badge}
    <div class="seg" style="margin-left:auto">
      <button class="active" onclick="dmpFilter(this,'all')">All</button>
      <button onclick="dmpFilter(this,'sent')">Sent</button>
      <button onclick="dmpFilter(this,'filtered')">Filtered</button>
    </div>
  </div>
  <div class="card-body">
    <table id="dmp-table"><thead><tr><th>Key</th><th>Value</th><th>Store</th></tr></thead>
    <tbody>{dmp_rows}</tbody></table>
  </div>
</div>
<script>
function dmpFilter(btn, mode) {{
  btn.parentElement.querySelectorAll('button').forEach(function(b) {{ b.classList.remove('active'); }});
  btn.classList.add('active');
  document.querySelectorAll('#dmp-table tbody tr').forEach(function(tr) {{
    var filtered = tr.classList.contains('filtered');
    tr.style.display = (mode === 'all' || (mode === 'sent' && !filtered) || (mode === 'filtered' && filtered)) ? '' : 'none';
  }});
}}
</script>

<div class="card">
  <div class="card-header"><h2>HTTP Form Fields (received by server)</h2></div>
  <div class="card-body">
    <p class="meta" style="margin:0 0 10px">Annotations that passed the allowlist and arrived as multipart form fields.</p>
    <table><thead><tr><th>Key</th><th>Value</th></tr></thead>
    <tbody>{http_rows}</tbody></table>
  </div>
</div>

<div class="card">
  <details>
    <summary>Stack Trace</summary>
    <div class="card-body">{stack_html}</div>
  </details>
</div>

<div class="card">
  <details>
    <summary>Loaded Modules</summary>
    <div class="card-body">{mod_table}</div>
  </details>
</div>

"""
    return _page(filename, body)


# ── HTTP handler ──────────────────────────────────────────────────────────────

class CrashpadHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {fmt % args}")

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/":
            self._health()
        elif path == "/dumps":
            self._list_dumps_json()
        elif path == "/crashes":
            self._list_crashes_html()
        elif path.startswith("/crash/"):
            rest = path[len("/crash/"):]
            if rest.endswith("/download"):
                self._download_dump(rest[:-len("/download")])
            else:
                self._crash_detail(rest)
        else:
            self._respond(404, "text/plain", b"Not found")

    def _health(self):
        dumps = self._dump_files()
        body = json.dumps({
            "status": "ok",
            "dumps_dir": os.path.abspath(DUMPS_DIR),
            "dump_count": len(dumps),
            "crashes_ui": f"http://localhost:{self.server.server_address[1]}/crashes",
        }, indent=2).encode()
        self._respond(200, "application/json", body)

    def _list_dumps_json(self):
        entries = self._load_entries()
        self._respond(200, "application/json", json.dumps(entries, indent=2).encode())

    def _list_crashes_html(self):
        entries = self._load_entries()
        body = _crashes_page(entries).encode()
        self._respond(200, "text/html; charset=utf-8", body)

    def _crash_detail(self, filename: str):
        filename = os.path.basename(filename)
        if not filename.endswith(".dmp"):
            self._respond(400, "text/plain", b"Invalid filename")
            return
        dump_path = os.path.join(DUMPS_DIR, filename)
        meta_path = dump_path.replace(".dmp", ".meta.json")
        if not os.path.exists(dump_path):
            self._respond(404, "text/plain", b"Dump not found")
            return

        meta = {}
        if os.path.exists(meta_path):
            with open(meta_path) as fh:
                meta = json.load(fh)

        crash_info = parse_minidump(dump_path)
        stack = run_stackwalk(dump_path)
        body = _detail_page(filename, meta, crash_info, stack).encode()
        self._respond(200, "text/html; charset=utf-8", body)

    def _download_dump(self, filename: str):
        filename = os.path.basename(filename)
        if not filename.endswith(".dmp"):
            self._respond(400, "text/plain", b"Invalid filename")
            return
        dump_path = os.path.join(DUMPS_DIR, filename)
        if not os.path.exists(dump_path):
            self._respond(404, "text/plain", b"Dump not found")
            return
        with open(dump_path, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ── POST /upload ──────────────────────────────────────────────────────────
    def do_POST(self):
        path = self.path.split("?")[0]
        if path != "/upload":
            self._respond(404, "text/plain", b"Not found")
            return

        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self._respond(400, "text/plain", b"Expected multipart/form-data")
            return

        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = self._read_chunked()
        else:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)

        if self.headers.get("Content-Encoding", "").lower() == "gzip":
            try:
                body = gzip.decompress(body)
            except Exception as e:
                print(f"  ERROR decompressing gzip body: {e}")
                self._respond(400, "text/plain", b"Failed to decompress body")
                return

        try:
            fields = parse_multipart(content_type, body)
        except Exception as e:
            print(f"  ERROR parsing multipart: {e}")
            self._respond(400, "text/plain", b"Failed to parse multipart body")
            return

        if "upload_file_minidump" not in fields:
            print("  ERROR: no 'upload_file_minidump' field in upload")
            self._respond(400, "text/plain", b"Missing upload_file_minidump field")
            return

        dump_data = fields["upload_file_minidump"]
        annotations = {
            k: v.decode("utf-8", errors="replace")
            for k, v in fields.items()
            if k != "upload_file_minidump"
        }

        crash_id = str(uuid.uuid4())
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{crash_id[:8]}.dmp"
        dump_path = os.path.join(DUMPS_DIR, filename)
        meta_path = dump_path.replace(".dmp", ".meta.json")

        os.makedirs(DUMPS_DIR, exist_ok=True)
        with open(dump_path, "wb") as f:
            f.write(dump_data)
        with open(meta_path, "w") as f:
            json.dump({
                "crash_id": crash_id,
                "received": datetime.now(tz=timezone.utc).isoformat(),
                "size_bytes": len(dump_data),
                "annotations": annotations,
            }, f, indent=2)

        port = self.server.server_address[1]
        print(f"  ✔ Saved {filename} ({len(dump_data) / 1024:.1f} KB)")
        print(f"    → http://localhost:{port}/crash/{filename}")
        for k, v in annotations.items():
            print(f"    {k}: {v}")

        self._respond(200, "text/plain", f"CrashID={crash_id}".encode())

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _read_chunked(self) -> bytes:
        chunks = []
        while True:
            size_line = self.rfile.readline().strip()
            chunk_size = int(size_line, 16)
            if chunk_size == 0:
                break
            chunks.append(self.rfile.read(chunk_size))
            self.rfile.read(2)
        return b"".join(chunks)

    def _respond(self, status: int, content_type: str, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _dump_files(self):
        if not os.path.isdir(DUMPS_DIR):
            return []
        return sorted(f for f in os.listdir(DUMPS_DIR) if f.endswith(".dmp"))

    def _load_entries(self):
        entries = []
        for f in self._dump_files():
            dump_path = os.path.join(DUMPS_DIR, f)
            stat = os.stat(dump_path)
            meta_path = dump_path.replace(".dmp", ".meta.json")
            meta = {}
            if os.path.exists(meta_path):
                with open(meta_path) as fh:
                    meta = json.load(fh)
            crash_info = parse_minidump(dump_path)
            exc_str = crash_info.get("exception_code_str", "")
            entries.append({
                "file": f,
                "size_kb": round(stat.st_size / 1024, 1),
                "received": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                "exc_str": exc_str,
                "annotations": meta.get("annotations", {}),
            })
        return entries


# ── Entry point ───────────────────────────────────────────────────────────────

def local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "localhost"


def main():
    global DUMPS_DIR
    args = parse_args()
    DUMPS_DIR = args.dumps
    os.makedirs(DUMPS_DIR, exist_ok=True)

    server = HTTPServer((args.host, args.port), CrashpadHandler)

    ip = local_ip()
    stackwalk = _find_stackwalk()
    print(f"Crashpad server listening on :{args.port}")
    print(f"  Dumps dir   : {os.path.abspath(DUMPS_DIR)}")
    print(f"  Upload URL  : http://{ip}:{args.port}/upload       ← real device")
    print(f"  Emulator URL: http://10.0.2.2:{args.port}/upload   ← Android emulator")
    print(f"  Crashes UI  : http://localhost:{args.port}/crashes")
    print(f"  Stackwalk   : {stackwalk or 'not found (install minidump_stackwalk for stack traces)'}")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
