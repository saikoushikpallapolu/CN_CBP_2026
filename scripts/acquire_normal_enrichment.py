"""Acquire independent published controlled normal captures for training."""
from pathlib import Path
from scripts.acquire_production_data import capture_subset, save_source


def main():
    for name, directory, filename in [
        ("normal7", "CTU-Normal-7", "2013-12-17_capture1.pcap"),
    ]:
        url = f"https://mcfp.felk.cvut.cz/publicDatasets/{directory}/{filename}"
        folder = Path("data/external") / name
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / "capture.pcap"
        if path.exists():
            print("Existing capture preserved", path, flush=True)
            continue
        capture = capture_subset(url, path, 16, None)
        value = dict(status="controlled_normal_enrichment", source_id=directory, split="train", capture=capture,
                     reference=f"https://mcfp.felk.cvut.cz/publicDatasets/{directory}/",
                     label_policy="Publisher-designated controlled normal capture; no validation/test packets included",
                     limitation="Controlled lab normal traffic, not independently audited enterprise traffic")
        save_source(Path("data/external/acquisition.json"), name, value)
        print(name, capture, flush=True)


if __name__ == "__main__":
    main()
