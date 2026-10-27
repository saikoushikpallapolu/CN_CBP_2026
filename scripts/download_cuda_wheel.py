"""Hash-verified ranged fallback for the official CUDA wheel on slow links."""
import hashlib
import html
import re
import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import unquote, urlsplit, urljoin
from scripts.acquire_production_data import get, range_bytes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tensorrt", action="store_true")
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()
    if not 1 <= args.workers <= 16:
        parser.error("workers must be between 1 and 16")
    index = "https://pypi.nvidia.com/tensorrt-cu13-libs/" if args.tensorrt else "https://download.pytorch.org/whl/cu130/torch/"
    links = re.findall(r'href="([^"]+)"', get(index).text)
    pattern = re.compile(r"torch-2\.14\.1(?:%2B|\+)cu130-cp312-cp312-win_amd64\.whl", re.I)
    if args.tensorrt:
        pattern = re.compile(r"tensorrt_cu13_libs-11\.4\.0\.106-py3-none-win_amd64\.whl", re.I)
    link = urljoin(index, html.unescape(next(value for value in links if pattern.search(value))))
    expected = urlsplit(link).fragment.removeprefix("sha256=")
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Official wheel index did not provide a SHA-256 digest")
    url = link.split("#", 1)[0]
    _, size = range_bytes(url, 0, 1)
    out = Path("artifacts/gpu-wheels")
    out.mkdir(parents=True, exist_ok=True)
    path = out / unquote(urlsplit(url).path.rsplit("/", 1)[-1])
    if path.exists():
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() == expected:
                print("Verified existing wheel", path, flush=True)
                return
    checksum = hashlib.sha256()
    partial = path.with_suffix(".whl.part")
    offset = partial.stat().st_size if partial.exists() else 0
    if offset > size:
        raise ValueError("Partial wheel is larger than the official artifact")
    if offset:
        with partial.open("rb") as previous:
            while block := previous.read(8 * 1024 ** 2):
                checksum.update(block)
        print("Resuming verified-at-completion wheel at byte", offset, flush=True)
    batch_size = args.workers * 1024 ** 2
    with partial.open("ab") as target, ThreadPoolExecutor(max_workers=args.workers) as pool:
        for first in range(offset, size, batch_size):
            chunks = [(offset, min(1024 ** 2, size-offset)) for offset in range(first, min(first + batch_size, size), 1024 ** 2)]
            for payload, total in pool.map(lambda chunk: range_bytes(url, *chunk), chunks):
                if total != size:
                    raise ValueError("Wheel size changed during transfer")
                checksum.update(payload)
                target.write(payload)
            if (first - offset) % (64 * 1024 ** 2) == 0:
                print("GPU wheel bytes", min(first + batch_size, size), "/", size, flush=True)
    if checksum.hexdigest() != expected:
        raise ValueError("Official CUDA wheel SHA-256 verification failed")
    partial.replace(path)
    print("Verified", path, expected, flush=True)


if __name__ == "__main__":
    main()
