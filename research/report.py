"""Export paper figures, seed summaries and an honest evidence scorecard."""
import argparse
import csv
import json
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from research.dataset import ROOT,digest
from research.run import write


def main():
    parser=argparse.ArgumentParser();parser.add_argument("run");args=parser.parse_args();folder=ROOT/"artifacts/research/runs"/args.run
    summary=json.loads((folder/"summary.json").read_text());config=json.loads((folder/"frozen-config.json").read_text())
    precision=json.loads((folder/"precision.json").read_text()) if (folder/"precision.json").exists() else {"results":[]}
    final=json.loads((folder/"final-evaluation.json").read_text()) if (folder/"final-evaluation.json").exists() else {"results":[]}
    items=list(summary.get("results",[]))+list(precision["results"])+list(final["results"])
    columns=["model","seed","split","model_sha256","dataset_sha256","policy","task","coverage","correct_accepted_fraction","macro_f1","macro_f1_present_classes",
             "benign_false_alert_rate","benign_review_rate","attack_accepted_benign_rate","attack_recognition_rate","mean_packets","mean_model_calls","context_wait_ms_p50","context_wait_ms_p95","brier","ece_15_bins","binary_attack_auroc","binary_attack_aupr","capture_cluster_intervals"]
    with (folder/"results.csv").open("w",newline="",encoding="utf-8") as file:
        writer=csv.DictWriter(file,fieldnames=columns);writer.writeheader()
        for item in items:
            base={key:item.get(key) for key in ("model","seed","split","model_sha256")};base["dataset_sha256"]=config["dataset"]["dataset_sha256"]
            for policy,metrics in item.get("metrics",{}).items():
                row={**base,"policy":policy,"task":"three-class selective classification"}
                row.update({key:metrics.get(key) for key in columns if key not in row});row["capture_cluster_intervals"]=json.dumps(metrics.get("confidence_intervals",{}));writer.writerow(row)
            if item.get("novelty"):
                writer.writerow({**base,"policy":"fixed16","task":"binary novelty; adapted KitNET18","benign_false_alert_rate":item["novelty"]["benign_false_alert_rate"],"binary_attack_auroc":item["novelty"].get("auroc"),"binary_attack_aupr":item["novelty"].get("aupr")})
    plotted=[item for item in summary.get("results",[]) if item["model"] in ("resnet1d_prefix","resnet1d_fixed16","resnet2d_prefix","hybrid_prefix","forest_behavior","logistic_behavior")]
    groups={name:[item for item in plotted if item["model"]==name] for name in sorted({item["model"] for item in plotted})}
    plt.rcParams.update({"font.size":9,"axes.spines.top":False,"axes.spines.right":False,"svg.fonttype":"none"})
    def save(name,fig):
        fig.tight_layout();fig.savefig(folder/(name+".svg"),bbox_inches="tight");fig.savefig(folder/(name+".png"),dpi=220,bbox_inches="tight");plt.close(fig)
    fig,axes=plt.subplots(1,2,figsize=(10,4))
    for name,entries in groups.items():
        policy="fixed16" if name=="resnet1d_fixed16" else "adaptive";metrics=[item["metrics"][policy] for item in entries]
        accuracy=np.array([m["correct_accepted_fraction"]*100 for m in metrics]);packets=np.array([m["mean_packets"] for m in metrics]);wait=np.array([m["context_wait_ms_p95"]/1000 for m in metrics])
        yrange=[[accuracy.mean()-accuracy.min()],[accuracy.max()-accuracy.mean()]]
        axes[0].errorbar(packets.mean(),accuracy.mean(),xerr=[[packets.mean()-packets.min()],[packets.max()-packets.mean()]],yerr=yrange,marker="o",capsize=3,label=name)
        axes[1].errorbar(wait.mean(),accuracy.mean(),xerr=[[wait.mean()-wait.min()],[wait.max()-wait.mean()]],yerr=yrange,marker="o",capsize=3,label=name)
    axes[0].set(xlabel="Observed packets to decision",ylabel="Correct accepted / all sessions (%)",title="Development · seed mean and min–max",ylim=(0,100))
    axes[1].set(xlabel="Context wait p95 (s; excludes computation)",ylabel="Correct accepted / all sessions (%)",xlim=(0,33),ylim=(0,100))
    axes[0].legend(fontsize=6);save("accuracy-delay",fig)
    fig,ax=plt.subplots(figsize=(6,4))
    for name,entries in groups.items():
        curves=[entry.get("risk_coverage",[]) for entry in entries]
        if not curves or not all(curves):continue
        # Shared thresholds are averaged, not reinterpreted as paired sessions.
        coverage=np.array([[row["coverage"] for row in curve] for curve in curves]);risk=np.array([[np.nan if row["risk"] is None else row["risk"] for row in curve] for curve in curves])
        valid=np.isfinite(risk).any(0)
        if valid.any():ax.plot(coverage[:,valid].mean(0)*100,np.nanmean(risk[:,valid],axis=0)*100,label=name)
    ax.set(xlabel="Accepted coverage (%)",ylabel="Error among accepted sessions (%)",title="Development risk–coverage · mean at shared thresholds");ax.legend(fontsize=6);save("risk-coverage",fig)
    fig,ax=plt.subplots(figsize=(9,4));names=list(groups);x=np.arange(len(names))
    false=[];review=[];errors=[]
    for name in names:
        metrics=[e["metrics"]["fixed16" if name=="resnet1d_fixed16" else "adaptive"] for e in groups[name]]
        values=[m["benign_false_alert_rate"]*100 for m in metrics];false.append(np.mean(values));errors.append(np.std(values));review.append(np.mean([m["benign_review_rate"]*100 for m in metrics]))
    ax.bar(x-.18,false,.36,yerr=errors,label="Benign false attack alert · seed SD");ax.bar(x+.18,review,.36,label="Benign review")
    ax.set_xticks(x,[name.replace("_","\n") for name in names],fontsize=7);ax.set(ylabel="Benign sessions (%)",title="False alerts and review are separate outcomes");ax.legend(fontsize=7);save("false-alerts",fig)
    if precision["results"]:
        fig,ax=plt.subplots(figsize=(6,4));labels=[];medians=[];p95=[]
        for kind in ("ort_fp32","ort_int8"):
            rows=[r for r in precision["results"] if r["model"].endswith(kind)]
            if rows:
                labels.append(kind);medians.append(np.mean([r["timings"]["batch64_context16_cpu_ms_p50"] for r in rows]));p95.append(np.mean([r["timings"]["batch64_context16_cpu_ms_p95"] for r in rows]))
        pos=np.arange(len(labels));ax.bar(pos-.18,medians,.36,label="Median");ax.bar(pos+.18,p95,.36,label="p95");ax.set_xticks(pos,labels);ax.set(ylabel="ms / 64 flow prefixes",title="Same CPU ONNX Runtime · 16-packet context");ax.legend();save("precision",fig)
    # The scorecard assesses evidence, not whether a desired number was requested.
    complete=summary.get("status")=="development_complete";has_final=bool(final["results"]);has_stream=(folder/"streaming.json").exists()
    measured_gain=False
    for item in final["results"]:
        if item["model"]!="resnet1d_prefix":continue
        a=item["metrics"]["adaptive"];b=item["metrics"]["fixed16"]
        measured_gain |= bool(a["mean_packets"]<b["mean_packets"] and a["correct_accepted_fraction"]>=b["correct_accepted_fraction"] and a["benign_false_alert_rate"]<=b["benign_false_alert_rate"])
    categories=[dict(category="Focused adaptive method",score=7 if measured_gain else 6,reason="Causal 4→8→16→32 implemented and compared; novelty review and robust Pareto gains still need independent confirmation"),
        dict(category="Frozen dataset strength",score=6,reason="Source/session audits and reserved novel families; limited independent capture clusters, small family counts and historical/public labels"),
        dict(category="Fair baselines",score=8 if complete else 5,reason="Three-seed matched-context 1D/2D, fixed16, statistical/RF and author KitNET18; original full Kitsune feature pipeline is not reproduced"),
        dict(category="Ablations",score=8 if complete and precision["results"] else 5,reason="Masking, modalities, stopping, rejection and same-CPU FP32/INT8 measured; budgets are a bounded pilot, not exhaustive tuning"),
        dict(category="False alerts and uncertainty",score=8,reason="Review-aware metrics, per-family results, risk–coverage, calibration and cluster intervals; low false-alert claims need stronger cohorts"),
        dict(category="Incremental systems evidence",score=7 if has_stream else 3,reason="Original-pacing isolated queue measurements and overload test; no real NIC/prevention or full production workload evidence"),
        dict(category="Statistical and independent verification",score=6 if has_final else 4,reason="Three seeds and capture-cluster bootstrap; independent human reproduction is pending and capture clusters remain few"),
        dict(category="Experiment workbench",score=9 if complete else 7,reason="Versioned runs, hashes, split/seed/policy comparison, downloadable tables and vector figures; browser visual review remains pending")]
    scorecard=dict(categories=categories,mean_score=float(np.mean([r["score"] for r in categories])),
        assessment="Evidence-based, not guaranteed publication readiness. Scores are reviewer judgment, not model accuracy or a venue decision.",
        independent_reproduction="pending_external_person",final_evaluated=has_final,measured_shared_threshold_pareto_example=measured_gain)
    write(folder/"scorecard.json",scorecard)
    write(folder/"reproduction-checklist.json",dict(status="pending_external_person",steps=["Use a separate machine and person; record OS, hardware and dependency versions", "Verify frozen dataset, protocol, model and code hashes", "Reproduce preprocessing and compare session IDs and partition membership", "Re-run all seeds without test-based tuning", "Check confidence intervals and latency measurement scope", "Record differences and a signed/date-stamped independent assessment"],
        warning="An automated replay on this same machine is not independent reproduction"))
    print(json.dumps(scorecard,indent=2),flush=True)


if __name__=="__main__":main()
