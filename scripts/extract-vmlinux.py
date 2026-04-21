#!/usr/bin/env python3
import gzip
import io
import lzma
import subprocess
import sys


def find_all(data: bytes, magic: bytes):
    pos = 0
    while pos < len(data):
        idx = data.find(magic, pos)
        if idx == -1:
            break
        yield idx
        pos = idx + 1


def is_elf(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == b"\x7fELF"


def try_gzip(data: bytes, offset: int) -> bytes | None:
    try:
        gz = gzip.GzipFile(fileobj=io.BytesIO(data[offset:]))
        result = gz.read()
        if is_elf(result):
            return result
    except Exception:
        pass
    return None


def try_xz(data: bytes, offset: int) -> bytes | None:
    try:
        dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        result = dec.decompress(data[offset:], maxlen=512 * 1024 * 1024)
        if is_elf(result):
            return result
    except Exception:
        pass
    return None


def try_lzma(data: bytes, offset: int) -> bytes | None:
    try:
        dec = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        result = dec.decompress(data[offset:], maxlen=512 * 1024 * 1024)
        if is_elf(result):
            return result
    except Exception:
        pass
    return None


def try_shell(cmd: list[str], data: bytes, offset: int) -> bytes | None:
    try:
        proc = subprocess.run(
            cmd,
            input=data[offset:],
            capture_output=True,
            timeout=60,
        )
        if proc.returncode == 0 and is_elf(proc.stdout):
            return proc.stdout
    except Exception:
        pass
    return None


DECOMPRESSORS = [
    ("gzip", try_gzip),
    ("xz", try_xz),
    ("lzma", try_lzma),
    ("zstd", lambda d, o: try_shell(["zstd", "-dc", "-"], d, o)),
    ("lz4", lambda d, o: try_shell(["lz4", "-dc", "-"], d, o)),
]


FORMATS = [
    (b"\x1f\x8b\x08", "gzip", DECOMPRESSORS[0][1]),
    (b"\xfd\x37\x7a\x58\x5a\x00", "xz", DECOMPRESSORS[1][1]),
    (b"\x5d\x00\x00", "lzma", DECOMPRESSORS[2][1]),
    (b"\x28\xb5\x2f\xfd", "zstd", DECOMPRESSORS[3][1]),
    # Linux 内核常见的是 legacy lz4 魔术字节，保留 frame 魔术字节兼容其他镜像。
    (b"\x02\x21\x4c\x18", "lz4", DECOMPRESSORS[4][1]),
    (b"\x04\x22\x4d\x18", "lz4", DECOMPRESSORS[4][1]),
]


def try_bzimage_payload(data: bytes) -> tuple[str, bytes] | None:
    if len(data) < 0x250 or data[0x202:0x206] != b"HdrS":
        return None

    setup_sects = data[0x1F1] or 4
    setup_size = (setup_sects + 1) * 512
    payload_offset = int.from_bytes(data[0x248:0x24C], "little")
    payload_length = int.from_bytes(data[0x24C:0x250], "little")
    start = setup_size + payload_offset
    end = start + payload_length
    if payload_length == 0 or start >= len(data) or end > len(data):
        return None

    payload_data = data[start:end]
    print(f"[extract-vmlinux] 使用 bzImage 头部定位负载 @ 偏移 {start}")
    for name, decompress in DECOMPRESSORS:
        print(f"[extract-vmlinux] 尝试 {name} @ bzImage 负载")
        result = decompress(payload_data, 0)
        if result is not None:
            return name, result
    return None


def extract(input_path: str, output_path: str) -> bool:
    with open(input_path, "rb") as f:
        data = f.read()

    result = try_bzimage_payload(data)
    if result is not None:
        name, payload = result
        with open(output_path, "wb") as f:
            f.write(payload)
        print(f"[extract-vmlinux] bzImage 头部定位成功，{name} 解压成功，输出 {len(payload)} bytes")
        return True

    for magic, name, decompress in FORMATS:
        for pos in find_all(data, magic):
            print(f"[extract-vmlinux] 尝试 {name} @ 偏移 {pos}")
            result = decompress(data, pos)
            if result is not None:
                with open(output_path, "wb") as f:
                    f.write(result)
                print(f"[extract-vmlinux] {name} 解压成功，输出 {len(result)} bytes")
                return True

    return False


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"用法: {sys.argv[0]} <输入> <输出>", file=sys.stderr)
        sys.exit(1)
    ok = extract(sys.argv[1], sys.argv[2])
    sys.exit(0 if ok else 1)
