"""Build small real reference captures from acquired sources (no fake packets)."""
import itertools
import struct
from pathlib import Path
from data_processing.production import read_capture


def main():
    output = Path("data/production/samples")
    output.mkdir(parents=True, exist_ok=True)
    sources = {"monday": "data/raw/benign/Monday-WorkingHours_slice100MB.pcap",
               "ctu1": "data/external/ctu1/capture.pcap", "friday": "data/external/friday/capture.pcap",
               "cse": "data/external/cse/capture.pcap", "mawi": "data/external/mawi/capture.pcap"}
    for name, source in sources.items():
        if not Path(source).exists():
            continue
        with (output / f"{name}.pcap").open("wb") as capture:
            capture.write(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 262144, 1))
            for stamp, raw, link in itertools.islice(read_capture(source), 1024):
                if link != 1:
                    raise ValueError("Sample link type must be Ethernet")
                capture.write(struct.pack("<IIII", int(stamp), int((stamp % 1) * 1e6), len(raw), len(raw)) + raw)
        print(output / f"{name}.pcap")


if __name__ == "__main__":
    main()
