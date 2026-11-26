"""Compare retained CRT, reopened CRT and retained Win32 reads after an append."""

import argparse
from contextlib import ExitStack, contextmanager
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import platform
import struct

MAGIC = bytes.fromhex("9feb4b9d")
XOR = bytes.fromhex("34e142735561d387")
PREALLOCATED = 16384


def obfuscate(data, offset):
    return bytes(value ^ XOR[(offset + index) % len(XOR)] for index, value in enumerate(data))


def record(version, nonce):
    framed = MAGIC + struct.pack("<I", 81)
    return framed + struct.pack("<I", version) + bytes(64) + struct.pack("<III", 0, 0, nonce) + b"\x00"


class Crt:
    def __init__(self, name):
        dll = ctypes.CDLL(str(Path(os.environ["SystemRoot"]) / "System32" / name), use_errno=True)
        stream = ctypes.c_void_p
        size = ctypes.c_size_t
        bindings = (
            ("fopen", stream, (ctypes.c_char_p, ctypes.c_char_p)),
            ("fclose", ctypes.c_int, (stream,)),
            ("setvbuf", ctypes.c_int, (stream, ctypes.c_char_p, ctypes.c_int, size)),
            ("fseek", ctypes.c_int, (stream, ctypes.c_long, ctypes.c_int)),
            ("ftell", ctypes.c_long, (stream,)),
            ("fwrite", size, (stream, size, size, stream)),
            ("fread", size, (stream, size, size, stream)),
            ("fflush", ctypes.c_int, (stream,)),
            ("_fileno", ctypes.c_int, (stream,)),
            ("_get_osfhandle", ctypes.c_ssize_t, (ctypes.c_int,)),
        )
        for name, result, parameters in bindings:
            function = getattr(dll, name)
            function.restype = result
            function.argtypes = parameters
            setattr(self, name, function)

    @contextmanager
    def open(self, path, mode):
        stream = self.fopen(os.fsencode(path), mode)
        if not stream:
            raise OSError(ctypes.get_errno(), f"fopen {mode!r}")
        try:
            yield stream
        finally:
            if self.fclose(stream):
                raise OSError(ctypes.get_errno(), "fclose")

    def seek(self, stream, offset, origin=0):
        if self.fseek(stream, offset, origin):
            raise OSError(ctypes.get_errno(), "fseek")

    def write(self, stream, offset, payload):
        self.seek(stream, offset)
        if self.fwrite(ctypes.create_string_buffer(payload), 1, len(payload), stream) != len(payload):
            raise OSError(ctypes.get_errno(), "short fwrite")
        if self.fflush(stream):
            raise OSError(ctypes.get_errno(), "fflush")

    def read(self, stream, amount):
        out = ctypes.create_string_buffer(amount)
        if self.fread(out, 1, amount, stream) != amount:
            raise OSError(ctypes.get_errno(), "short fread")
        return out.raw

    def read_record(self, stream, offset):
        self.seek(stream, offset)
        header = self.read(stream, 8)
        body = self.read(stream, 81)
        return obfuscate(header + body, offset)


class KernelReader:
    def __init__(self):
        kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        self.seek = kernel.SetFilePointerEx
        self.seek.argtypes = (wintypes.HANDLE, ctypes.c_longlong, ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD)
        self.seek.restype = wintypes.BOOL
        self.read = kernel.ReadFile
        self.read.argtypes = (wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                              ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p)
        self.read.restype = wintypes.BOOL

    def read_record(self, handle, offset):
        if not self.seek(handle, offset, None, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        parts = []
        for amount in (8, 81):
            out = ctypes.create_string_buffer(amount)
            count = wintypes.DWORD()
            if not self.read(handle, out, amount, ctypes.byref(count), None):
                raise ctypes.WinError(ctypes.get_last_error())
            if count.value != amount:
                raise OSError("short ReadFile")
            parts.append(out.raw)
        return obfuscate(b"".join(parts), offset)


def measure(path, dll):
    crt = Crt(dll)
    native = KernelReader()
    first, second = record(7, 0), record(8, 0x94265ECF)
    append_at = len(first)
    path.write_bytes(bytes(PREALLOCATED))
    with ExitStack() as resources:
        writer = resources.enter_context(crt.open(path, b"rb+"))
        crt.write(writer, 0, obfuscate(first, 0))
        retained = resources.enter_context(crt.open(path, b"rb"))
        repositioned = resources.enter_context(crt.open(path, b"rb"))
        native_stream = resources.enter_context(crt.open(path, b"rb"))
        for stream in (retained, repositioned):
            if crt.setvbuf(stream, None, 4, 512) or crt.ftell(stream) != 0:
                raise OSError(ctypes.get_errno(), "Unbuffered CRT setup failed")
            if crt.read_record(stream, 0) != first:
                raise RuntimeError("Retained CRT first-record control differs")
        descriptor = crt._fileno(native_stream)
        if descriptor < 0:
            raise OSError(ctypes.get_errno(), "_fileno")
        native_handle = crt._get_osfhandle(descriptor)
        if native_handle == -1:
            raise OSError(ctypes.get_errno(), "_get_osfhandle")
        if native.read_record(native_handle, 0) != first:
            raise RuntimeError("Retained Win32 first-record control differs")

        crt.write(writer, append_at, obfuscate(second, append_at))
        reused = crt.read_record(retained, append_at)
        with crt.open(path, b"rb") as fresh:
            reopened = crt.read_record(fresh, append_at)
        crt.seek(repositioned, 0, 2)
        after_forced_seek = crt.read_record(repositioned, append_at)
        kernel = native.read_record(native_handle, append_at)

    differences = [index for index, (actual, expected) in enumerate(zip(reused, second)) if actual != expected]
    controls_match = reopened == after_forced_seek == kernel == second
    if differences == [0] and reused[0] == XOR[append_at % len(XOR)] and controls_match:
        verdict = "retained_stream_used_preallocated_zero_for_first_byte"
    elif not differences and controls_match:
        verdict = "retained_stream_matched"
    else:
        verdict = "unexpected_control_result"
    return {
        "crt": dll,
        "append_offset": append_at,
        "file_size": path.stat().st_size,
        "expected_magic": second[:4].hex(),
        "retained_stdio_magic": reused[:4].hex(),
        "reopened_stdio_magic": reopened[:4].hex(),
        "retained_stdio_forced_seek_magic": after_forced_seek[:4].hex(),
        "retained_win32_magic": kernel[:4].hex(),
        "differing_bytes": differences,
        "controls_match_full_record": controls_match,
        "verdict": verdict,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New owned temporary directory")
    args = parser.parse_args()
    if platform.system() != "Windows" or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise SystemExit("Use native Windows x86-64")
    args.output.mkdir(parents=True, exist_ok=False)
    result = [measure(args.output / f"{name}.dat", f"{name}.dll") for name in ("ucrtbase", "msvcrt")]
    (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))
    return int(any(row["verdict"] == "unexpected_control_result" for row in result))


if __name__ == "__main__":
    raise SystemExit(main())
