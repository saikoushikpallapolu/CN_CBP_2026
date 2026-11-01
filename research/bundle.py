"""Local reproduction bundle with byte-exact source; raw data is opt-in."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile
from research.dataset import ROOT,digest
from research.run import write


def main():
    parser=argparse.ArgumentParser();parser.add_argument("run");parser.add_argument("--include-frozen-data",action="store_true");args=parser.parse_args()
    folder=ROOT/"artifacts/research/runs"/args.run;config=json.loads((folder/"frozen-config.json").read_text());lock=json.loads((folder/"locked-models.json").read_text())
    names=subprocess.check_output(["git","ls-files","--cached","--others","--exclude-standard"],cwd=ROOT,text=True).splitlines()
    allowed={"api","classification","data_processing","deploy","docs","frontend","ml","native","research","scripts","tests"}
    selected={name:ROOT/name for name in names if Path(name).parts[0] in allowed or name.startswith("requirements") or name in ("README.md","pytest.ini",".dockerignore")}
    for path in folder.rglob("*"):
        if path.is_file() and path.suffix not in (".part",):selected[path.relative_to(ROOT).as_posix()]=path
    if args.include_frozen_data:
        path=ROOT/"artifacts/research"/config["dataset_file"];selected[path.relative_to(ROOT).as_posix()]=path
    normalized={name:dict(raw_sha256=expected,lf_sha256=hashlib.sha256((ROOT/name).read_bytes().replace(b"\r\n",b"\n")).hexdigest()) for name,expected in lock["code"].items()}
    write(folder/"source-normalization.json",dict(scope="Use the exact ZIP source for raw-byte checks; Git checkout line-ending changes can instead be checked with these LF hashes",files=normalized))
    selected[(folder/"source-normalization.json").relative_to(ROOT).as_posix()]=folder/"source-normalization.json"
    output=ROOT/"artifacts/research"/(args.run+"-reproduction.zip")
    manifest=dict(run=args.run,raw_corpora_included=False,frozen_feature_data_included=args.include_frozen_data,
                  public_redistribution="Review original dataset terms before sharing feature arrays; this local bundle is not an independent reproduction",files={})
    with zipfile.ZipFile(output,"w",zipfile.ZIP_DEFLATED) as archive:
        for name,path in sorted(selected.items()):
            payload=path.read_bytes();archive.writestr(name,payload);manifest["files"][name]=dict(size=len(payload),sha256=hashlib.sha256(payload).hexdigest())
        archive.writestr("REPRODUCTION_MANIFEST.json",json.dumps(manifest,indent=2))
    output.with_suffix(".sha256").write_text(digest(output)+"  "+output.name+"\n")
    print(str(output),output.stat().st_size,flush=True)


if __name__=="__main__":main()
