"""Build and verify the Linux GPU image with fixed, bounded workspace mounts."""
import argparse
import re
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("image", "compile", "audit", "benchmark", "stability"))
    parser.add_argument("--model", default="flow_resnet")
    parser.add_argument("--data", default="data/production/dataset.npz")
    parser.add_argument("--sm", default="89", choices=("75", "80", "86", "89", "90", "100", "120"))
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_]+", args.model):
        parser.error("model must be a checkpoint basename")
    root = Path(__file__).resolve().parents[1]
    if args.action == "image":
        libraries = root / f"artifacts/tensorrt-linux-sm{args.sm}"
        if not (libraries / "manifest.json").exists():
            raise SystemExit("Acquire and verify target libraries first")
        subprocess.run(["docker", "build", "--build-context", f"trt-libs={libraries}", "-f", "deploy/Dockerfile.gpu",
                        "-t", "trafficscan:gpu", "."], cwd=root, check=True)
        return
    data = (root / args.data).resolve()
    if not data.is_relative_to((root / "data/production").resolve()):
        parser.error("data must be inside data/production")
    command = ["docker", "run", "--rm", "--gpus", "all", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
               "--memory=4g", "--cpus=4", "--read-only", "--tmpfs", "/tmp:rw,size=268435456,mode=1777"]
    for source, target, readonly in (("ml/checkpoints", "/app/ml/checkpoints", args.action not in ("compile", "audit")),
                                     ("data/production", "/app/data/production", True),
                                     ("artifacts", "/app/artifacts", False)):
        command.extend(["--mount", f"type=bind,source={root / source},target={target}" + (",readonly" if readonly else "")])
    prefix = "ml/checkpoints/" + args.model
    command.extend(["-e", "TRAFFICSCAN_CHECKPOINT=" + prefix + ".pth", "-e", "TRAFFICSCAN_TENSORRT=" + prefix + ".engine", "trafficscan:gpu", "python", "-m"])
    if args.action == "compile":
        command.extend(["ml.build_tensorrt", prefix + ".trt.int8.onnx", "--int8", "--output", prefix + ".engine"])
    elif args.action == "audit":
        command.extend(["ml.evaluate_tensorrt", "--cuda-python", "--checkpoint", prefix + ".pth", "--engine", prefix + ".engine",
                        "--data", data.relative_to(root).as_posix(), "--output", "artifacts/" + args.model + "-tensorrt-audit.json"])
    elif args.action == "benchmark":
        command.extend(["scripts.benchmark_production", "data/production/samples/monday.pcap", "--output", "artifacts/" + args.model + "-tensorrt-benchmark.json"])
    else:
        command.extend(["scripts.stability_audit", *["data/production/samples/" + name + ".pcap" for name in ("monday", "ctu1", "friday", "cse", "mawi")],
                        "--hours", "24", "--interval", "2", "--output", "artifacts/" + args.model + "-gpu-stability-24h.jsonl"])
    subprocess.run(command, cwd=root, check=True)


if __name__ == "__main__":
    main()
