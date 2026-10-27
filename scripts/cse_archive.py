"""Inspect a remote RAR by seeking over compressed members with HTTPS Range.

Optional extraction copies only a non-solid selected member into a standalone
archive and uses the installed bsdtar data decoder. It never executes content.
"""
import argparse
import io
import json
import subprocess
import sys
import struct
import zlib
import hashlib
import zipfile
from concurrent.futures import ThreadPoolExecutor
from collections import OrderedDict
from pathlib import Path
from urllib.parse import quote
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / ".runtime"))
from scripts.acquire_production_data import range_bytes


class RemoteArchive(io.RawIOBase):
    def __init__(self, url):
        self.url = url
        self.block_size = 4096
        initial, self.size = range_bytes(url, 0, self.block_size)
        self.cache, self.position = OrderedDict([(0, initial)]), 0
        self.downloaded_bytes = len(initial)

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        self.position = offset if whence == 0 else self.position + offset if whence == 1 else self.size + offset
        if self.position < 0:
            raise ValueError("Negative archive offset")
        return self.position

    def read(self, size=-1):
        if size < 0:
            raise ValueError("Unbounded remote archive read rejected")
        if size > 4 * 1024 ** 2:
            raise ValueError("Unexpected oversized RAR metadata block")
        size = min(size, self.size - self.position)
        output = bytearray()
        while len(output) < size:
            offset = self.position // self.block_size * self.block_size
            if offset not in self.cache:
                payload, _ = range_bytes(self.url, offset, min(self.block_size, self.size - offset))
                self.downloaded_bytes += len(payload)
                self.cache[offset] = payload
                if len(self.cache) > 16:
                    self.cache.popitem(last=False)
            payload = self.cache[offset]
            local = self.position - offset
            length = min(len(payload) - local, size - len(output))
            if length <= 0:
                break
            output.extend(payload[local:local + length])
            self.position += length
        return bytes(output)


def extract_cached(report, member, budget, folder):
    if report["solid"]:
        raise SystemExit("Solid archive requires preceding members")
    info = next(row for row in report["members"] if row["filename"] == member)
    if info["compressed_bytes"] > budget * 1024 ** 2:
        raise SystemExit("Selected member exceeds configured acquisition budget")
    url = report["url"]
    prefix, total = range_bytes(url, 0, report["members"][0]["header_offset"])
    if total != report["total_archive_bytes"]:
        raise ValueError("Archive changed since inventory")
    first, length = info["header_offset"], info["data_offset"] - info["header_offset"] + info["compressed_bytes"]
    mini = folder / "selected-member.rar"
    digest = hashlib.sha256()
    with mini.with_suffix(".rar.part").open("wb") as target, ThreadPoolExecutor(max_workers=4) as pool:
        target.write(prefix)
        digest.update(prefix)
        for batch in range(first, first + length, 4 * 1024 ** 2):
            chunks = [(offset, min(1024 ** 2, first + length - offset)) for offset in range(batch, min(batch + 4 * 1024 ** 2, first + length), 1024 ** 2)]
            for payload, archive_size in pool.map(lambda chunk: range_bytes(url, *chunk), chunks):
                if archive_size != total:
                    raise ValueError("Archive changed during extraction")
                target.write(payload)
                digest.update(payload)
            if (batch - first) // (4 * 1024 ** 2) % 16 == 0:
                print("Member bytes acquired", min(batch + 4 * 1024 ** 2 - first, length), "/", length, flush=True)
        if prefix.startswith(b"Rar!\x1a\x07\x01\x00"):
            trailer = b"\x03\x05\x00\x00"
            trailer = struct.pack("<I", zlib.crc32(trailer)) + trailer
        else:
            trailer = struct.pack("<BHH", 0x7b, 0, 7)
            trailer = struct.pack("<H", zlib.crc32(trailer) & 0xffff) + trailer
        target.write(trailer)
        digest.update(trailer)
    mini.with_suffix(".rar.part").replace(mini)
    output = folder / "member.pcap"
    with output.with_suffix(".pcap.part").open("wb") as capture:
        result = subprocess.run(["tar", "-xOf", str(mini), "--", member], stdout=capture, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise SystemExit("Archive decoder rejected member: " + result.stderr.decode(errors="replace"))
    if output.with_suffix(".pcap.part").stat().st_size != info["raw_bytes"]:
        raise ValueError("Extracted size does not match archive metadata")
    output.with_suffix(".pcap.part").replace(output)
    evidence = dict(url=url, member=info, standalone_archive_sha256=digest.hexdigest(), extracted_bytes=output.stat().st_size)
    (folder / "extraction.json").write_text(json.dumps(evidence, indent=2))
    print("Extracted", output, output.stat().st_size, flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--day", default="Tuesday-20-02-2018")
    parser.add_argument("--member", help="Exact member filename from the saved inventory")
    parser.add_argument("--find", default="172.31.69.25", help="Stop inventory at a matching host capture")
    parser.add_argument("--max-member-mib", type=int, default=512)
    parser.add_argument("--main-only", action="store_true")
    parser.add_argument("--folder", default="data/external/cse", help="Separate destination for each independent capture day")
    parser.add_argument("--archive", choices=("rar", "zip"), default="rar")
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()
    if not 1 <= args.workers <= 16:
        parser.error("workers must be between 1 and 16")
    import rarfile
    key = f"Original Network Traffic and Log data/{args.day}/pcap.{args.archive}"
    url = "https://cse-cic-ids2018.s3.amazonaws.com/" + quote(key)
    folder = (ROOT / args.folder).resolve()
    if not folder.is_relative_to((ROOT / "data/external").resolve()):
        raise ValueError("Archive destination must stay inside data/external")
    folder.mkdir(parents=True, exist_ok=True)
    if args.archive == "zip":
        extract_zip(url, args, folder)
        return
    cached_path = folder / "rar_members.json"
    if args.member and cached_path.exists():
        cached = json.loads(cached_path.read_text())
        if cached["url"] == url and any(row["filename"] == args.member for row in cached["members"]):
            extract_cached(cached, args.member, args.max_member_mib, folder)
            return
    remote = RemoteArchive(url)
    infos, solid = [], False
    class SelectedMemberFound(Exception):
        pass
    def observed(info):
        nonlocal solid
        if info.type == rarfile.RAR_BLOCK_MAIN:
            solid = bool(info.flags & rarfile.RAR_MAIN_SOLID)
            if args.main_only:
                report = dict(url=url, total_archive_bytes=remote.size, solid=solid)
                (folder / "rar_main.json").write_text(json.dumps(report, indent=2))
                print(json.dumps(report), flush=True)
                raise SelectedMemberFound()
        if info.type != rarfile.RAR_BLOCK_FILE:
            return
        infos.append(info)
        if len(infos) % 50 == 0 or args.find in info.filename:
            print("Indexed", len(infos), "members; latest", info.filename, "compressed", info.compress_size, flush=True)
        if (args.member and info.filename == args.member) or (not args.member and args.find and args.find in info.filename):
            raise SelectedMemberFound()
    try:
        with rarfile.RarFile(remote, info_callback=observed):
            pass
    except SelectedMemberFound:
        pass
    if infos:
        inventory = [dict(filename=i.filename, compressed_bytes=i.compress_size, raw_bytes=i.file_size,
                          header_offset=i.header_offset, data_offset=i.data_offset, method=i.compress_type, flags=i.flags) for i in infos]
        report = dict(url=url, total_archive_bytes=remote.size, solid=solid, metadata_bytes_transferred=remote.downloaded_bytes, members=inventory)
        (folder / "rar_members.json").write_text(json.dumps(report, indent=2))
        print(json.dumps({key: value for key, value in report.items() if key != "members"}), "members", len(inventory), flush=True)
        if not args.member:
            return
        extract_cached(report, args.member, args.max_member_mib, folder)
        return


def extract_zip(url, args, folder):
    """Read only the remote ZIP directory and selected deflated capture member."""
    remote = RemoteArchive(url)
    with zipfile.ZipFile(remote) as archive:
        rows = [dict(filename=i.filename, compressed_bytes=i.compress_size, raw_bytes=i.file_size,
                     header_offset=i.header_offset, method=i.compress_type, crc32=i.CRC)
                for i in archive.infolist()]
        report = dict(url=url, total_archive_bytes=remote.size, members=rows,
                      metadata_bytes_transferred=remote.downloaded_bytes)
        (folder / "zip_members.json").write_text(json.dumps(report, indent=2))
        matches = [row for row in rows if args.find in row["filename"]]
        print(json.dumps(matches, indent=2), flush=True)
        if not args.member:
            return
        info = next(row for row in rows if row["filename"] == args.member)
        if info["compressed_bytes"] > args.max_member_mib * 1024 ** 2:
            raise ValueError("Selected ZIP member exceeds acquisition budget")
        if info["method"] not in (zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED):
            raise ValueError("Unsupported ZIP compression method")
        remote.seek(info["header_offset"])
        header = remote.read(30)
        if header[:4] != b"PK\x03\x04" or struct.unpack_from("<H", header, 6)[0] & 1:
            raise ValueError("Encrypted or invalid ZIP member")
        name_length, extra_length = struct.unpack_from("<HH", header, 26)
        first = info["header_offset"] + 30 + name_length + extra_length
        compressed = folder / "selected-member.deflate.part"
        identity_path = folder / "selected-member.download.json"
        identity = dict(url=url, member=info, total_archive_bytes=remote.size)
        if compressed.exists():
            if not identity_path.exists() or json.loads(identity_path.read_text()) != identity:
                raise ValueError("Partial ZIP member identity mismatch")
        identity_path.write_text(json.dumps(identity, indent=2))
        received = compressed.stat().st_size if compressed.exists() else 0
        length = info["compressed_bytes"]
        if received > length:
            raise ValueError("Partial ZIP member is oversized")
        batch_size = args.workers * 1024 ** 2
        with compressed.open("ab") as target, ThreadPoolExecutor(max_workers=args.workers) as pool:
            for batch in range(first + received, first + length, batch_size):
                chunks = [(offset, min(1024 ** 2, first + length - offset)) for offset in range(batch, min(batch + batch_size, first + length), 1024 ** 2)]
                for payload, total in pool.map(lambda chunk: range_bytes(url, *chunk), chunks):
                    if total != remote.size:
                        raise ValueError("Remote ZIP changed during acquisition")
                    target.write(payload)
                print("ZIP cached compressed bytes", target.tell(), "/", length, flush=True)
        decoder = zlib.decompressobj(-15) if info["method"] == zipfile.ZIP_DEFLATED else None
        output, crc, written = folder / "member.pcap", 0, 0
        with output.with_suffix(".pcap.part").open("wb") as target, compressed.open("rb") as source:
            while payload := source.read(1024 ** 2):
                while payload:
                    raw = decoder.decompress(payload, 64 * 1024 ** 2) if decoder else payload
                    written += len(raw)
                    if written > info["raw_bytes"]:
                        raise ValueError("ZIP output exceeded declared size")
                    crc = zlib.crc32(raw, crc)
                    target.write(raw)
                    payload = decoder.unconsumed_tail if decoder else b""
        if written != info["raw_bytes"] or crc != info["crc32"] or (decoder and not decoder.eof):
            raise ValueError("ZIP member size/CRC verification failed")
        output.with_suffix(".pcap.part").replace(output)
        (folder / "extraction.json").write_text(json.dumps(dict(url=url, member=info, extracted_bytes=written, crc_verified=True), indent=2))
        print("Verified extracted capture", output, written, flush=True)


if __name__ == "__main__":
    main()
