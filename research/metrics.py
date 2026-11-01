"""Metrics preserve rejected attacks and uncertainty instead of counting them correct."""
import numpy as np
from sklearn.metrics import precision_recall_fscore_support, accuracy_score, f1_score,roc_auc_score,average_precision_score


def summarize(y, decision, family=None):
    y = np.asarray(y); predicted = decision["prediction"]; raw = decision["raw_prediction"]
    accepted = predicted >= 0; benign = y == 0; attack = ~benign
    def rate(mask, group): return float(mask[group].mean()) if group.any() else None
    precision, recall, f1, support = precision_recall_fscore_support(y,predicted,labels=[0,1,2],zero_division=0)
    out = dict(n=len(y), accuracy_before_rejection=float(accuracy_score(y,raw)),
               correct_accepted_fraction=float(np.mean(predicted == y)), coverage=float(accepted.mean()),
               selective_error=rate(predicted != y,accepted), macro_f1=float(f1_score(y,predicted,labels=[0,1,2],average="macro",zero_division=0)),
               benign_false_alert_rate=rate((predicted > 0),benign), benign_review_rate=rate(~accepted,benign),
               attack_accepted_benign_rate=rate(predicted == 0,attack), attack_review_rate=rate(~accepted,attack),
               attack_recognition_rate=rate(predicted > 0,attack), mean_packets=float(np.mean(decision["packets"])),
               per_class=[dict(label=i,precision=float(precision[i]),recall=float(recall[i]),f1=float(f1[i]),support=int(support[i])) for i in range(3)])
    p = decision["probabilities"]; confidence=p.max(1); correct=p.argmax(1)==y
    out["evaluated_classes"]=sorted(map(int,np.unique(y)))
    out["macro_f1_present_classes"]=float(f1_score(y,predicted,labels=np.unique(y),average="macro",zero_division=0))
    out["macro_f1_scope"]="Fixed three-class macro includes absent classes with F1=0; present-class metric is separate"
    out["confusion_true_rows_prediction_columns_0_1_2_review"]=[[int(np.sum((y==c)&(predicted==guess))) for guess in (0,1,2,-1)] for c in (0,1,2)]
    out["binary_attack_auroc"]=float(roc_auc_score(attack,1-p[:,0])) if benign.any() and attack.any() else None
    out["binary_attack_aupr"]=float(average_precision_score(attack,1-p[:,0])) if benign.any() and attack.any() else None
    out["brier"] = float(np.mean(np.sum((p - np.eye(3)[y])**2,axis=1)))
    out["ece_15_bins"] = float(sum(np.mean(mask)*abs(float(correct[mask].mean())-float(confidence[mask].mean()))
        for low in np.linspace(0,1,16)[:-1] if (mask := (confidence >= low) & (confidence < low+1/15 if low < 14/15 else confidence <= 1)).any()))
    if family is not None:
        family=np.asarray(family)
        out["per_family"]={str(name):dict(n=int((family==name).sum()),correct_accepted_fraction=float(np.mean(predicted[family==name]==y[family==name])),
            review_rate=float(np.mean(predicted[family==name]<0)),accepted_benign_rate=float(np.mean(predicted[family==name]==0))) for name in sorted(set(family))}
    return out


def clustered_intervals(y, decision, groups, repeats=500, seed=42):
    """Resample independent captures, never treat packets as independent trials."""
    groups=np.asarray(groups); unique=np.unique(groups); rng=np.random.default_rng(seed)
    if len(unique)<2: return {"status":"insufficient_capture_clusters", "clusters":len(unique)}
    values={key:[] for key in ("correct_accepted_fraction","benign_false_alert_rate","benign_review_rate","attack_accepted_benign_rate","mean_packets")}
    for _ in range(repeats):
        indexes=np.concatenate([np.flatnonzero(groups==group) for group in rng.choice(unique,len(unique),replace=True)])
        truth=y[indexes];p=decision["prediction"][indexes];normal=truth==0;attack=~normal
        measured=dict(correct_accepted_fraction=float(np.mean(p==truth)),
            benign_false_alert_rate=float(np.mean(p[normal]>0)) if normal.any() else None,
            benign_review_rate=float(np.mean(p[normal]<0)) if normal.any() else None,
            attack_accepted_benign_rate=float(np.mean(p[attack]==0)) if attack.any() else None,
            mean_packets=float(np.mean(decision["packets"][indexes])))
        for key in values:
            if measured[key] is not None: values[key].append(measured[key])
    return dict(method="capture-cluster percentile bootstrap",repeats=repeats,clusters=len(unique),
                warning="Few source clusters can make intervals unstable; seeds are reported separately",
                intervals={key:np.quantile(value,[.025,.975]).tolist() if value else None for key,value in values.items()})
