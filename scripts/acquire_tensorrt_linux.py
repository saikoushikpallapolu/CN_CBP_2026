"""Fetch official Linux TensorRT libraries for one GPU architecture.

Uses bounded ZIP ranges, per-member CRC and official wheel RECORD SHA-256.
The unmodified binaries are loaded by NVIDIA's Python bindings through the
standard library path. Other GPU architectures are intentionally not packaged.
"""
import argparse
import base64
import csv
import hashlib
import io
import json
import struct
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from scripts.cse_archive import RemoteArchive
from scripts.acquire_production_data import range_bytes

URL = "https://pypi.nvidia.com/tensorrt-cu13-libs/tensorrt_cu13_libs-11.4.0.106-py3-none-manylinux_2_28_x86_64.whl"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sm", choices=("75", "80", "86", "89", "90", "100", "120"), default="89")
    args = parser.parse_args()
    folder = Path("artifacts") / f"tensorrt-linux-sm{args.sm}"
    cache, libraries = folder / ".cache", folder / "lib"
    cache.mkdir(parents=True, exist_ok=True)
    libraries.mkdir(parents=True, exist_ok=True)
    (folder / ".dockerignore").write_text(".cache\n")
    remote = RemoteArchive(URL)
    with zipfile.ZipFile(remote) as archive:
        record_name = next(i.filename for i in archive.infolist() if i.filename.endswith(".dist-info/RECORD"))
        hashes = {name: digest for name, digest, size in csv.reader(io.StringIO(archive.read(record_name).decode()))}
        names = {"libnvinfer.so.11", "libnvinfer_plugin.so.11", "libnvonnxparser.so.11",
                 f"libnvinfer_builder_resource_sm{args.sm}.so.11.4.0"}
        selected = [i for i in archive.infolist() if Path(i.filename).name in names or i.filename.endswith("/licenses/LICENSE.txt")]
        if not names.issubset({Path(i.filename).name for i in selected}):
            raise ValueError("Requested NVIDIA GPU libraries are absent")
        evidence = dict(url=URL, compute_capability=args.sm, members=[])
        for info in selected:
            expected = hashes[info.filename]
            if not expected.startswith("sha256="):
                raise ValueError("Missing official RECORD SHA-256")
            output = libraries / Path(info.filename).name
            def signature(path):
                with path.open("rb") as stream:
                    return "sha256=" + base64.urlsafe_b64encode(hashlib.file_digest(stream, "sha256").digest()).decode().rstrip("=")
            if not output.exists() or signature(output) != expected:
                remote.seek(info.header_offset)
                header = remote.read(30)
                if header[:4] != b"PK\x03\x04" or struct.unpack_from("<H", header, 6)[0] & 1:
                    raise ValueError("Invalid or encrypted official wheel member")
                name_length, extra_length = struct.unpack_from("<HH", header, 26)
                first = info.header_offset + 30 + name_length + extra_length
                partial = cache / (output.name + ".compressed")
                received = partial.stat().st_size if partial.exists() else 0
                if received > info.compress_size:
                    raise ValueError("Oversized cached library")
                with partial.open("ab") as target, ThreadPoolExecutor(max_workers=8) as pool:
                    for batch in range(first + received, first + info.compress_size, 8 * 1024 ** 2):
                        chunks = [(offset, min(1024 ** 2, first + info.compress_size - offset)) for offset in range(batch, min(batch + 8 * 1024 ** 2, first + info.compress_size), 1024 ** 2)]
                        for payload, total in pool.map(lambda chunk: range_bytes(URL, *chunk), chunks):
                            if total != remote.size:
                                raise ValueError("Official wheel size changed")
                            target.write(payload)
                        print(output.name, target.tell(), "/", info.compress_size, flush=True)
                decoder = zlib.decompressobj(-15) if info.compress_type == zipfile.ZIP_DEFLATED else None
                if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise ValueError("Unsupported official wheel compression")
                crc, written = 0, 0
                with partial.open("rb") as source, output.with_suffix(".part").open("wb") as target:
                    while payload := source.read(1024 ** 2):
                        while payload:
                            raw = decoder.decompress(payload, 64 * 1024 ** 2) if decoder else payload
                            written += len(raw)
                            if written > info.file_size:
                                raise ValueError("Library exceeded expected size")
                            crc = zlib.crc32(raw, crc)
                            target.write(raw)
                            payload = decoder.unconsumed_tail if decoder else b""
                candidate = output.with_suffix(".part")
                if written != info.file_size or crc != info.CRC or (decoder and not decoder.eof) or signature(candidate) != expected:
                    raise ValueError("Official library size/CRC/SHA-256 verification failed")
                candidate.replace(output)
            evidence["members"].append(dict(filename=info.filename, bytes=info.file_size, record_sha256=expected))
            print("Verified", output, flush=True)
        (folder / "manifest.json").write_text(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
