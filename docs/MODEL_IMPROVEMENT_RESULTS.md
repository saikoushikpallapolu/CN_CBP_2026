# Improvement experiments and remaining model gaps

29 October 2026. The existing model remains deployed. Two retrained challengers and one decision-policy experiment were executed; none met the promotion criteria. Their weights and reports were saved separately. No higher-accuracy or lower-false-alert model is being claimed from this work.

## What was changed and tested

1. A challenger used source/class-balanced sampling, label-smoothed cross entropy and training-only shortened flow contexts. Epoch selection used mean source/class validation loss. Training was restricted to the training partition; the test partition was not evaluated for this rejected challenger.
2. A second challenger added a bounded independent publisher-designated normal capture, [CTU-Normal-7](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-7/), to the training partition and used focal loss. The publisher describes manually checked normal P2P/web/messaging traffic. The 16 MiB subset yielded only **67 independent flow bursts**, despite containing 20,287 packets. This is limited enrichment, not thousands of independent examples.
3. A class-specific threshold search used expanded validation data, minimizing benign review under a constraint on attack escalation. The frozen policy was then measured on the previously inspected regression set. The policy was rejected because attack escalation fell from 100% to **98.32%**, exceeding the allowed loss, despite reducing benign review from 2.98% to 0.236%. The active confidence/entropy policy was not changed.

The attempted CTU-Normal-20 download was excluded: its relative/invalid initial timestamp records did not pass the strict acquisition alignment check. No labels or timestamps were silently repaired. A missing normal companion file also returned 404 and was not used.

## Validation results for the two training challengers

These are **expanded-validation represented-packet rates**, not the original held-out test metrics. That validation corpus includes CTU-9 normal/bot flows and 17,175 CSE-21 attack flows, most from HOIC. Its composition differs sharply from the earlier test.

| Metric | Existing PyTorch model | Balanced/smoothed challenger | Normal-enriched focal challenger |
|---|---:|---:|---:|
| Macro F1 before rejection | 0.28885 | 0.26399 | 0.15380 |
| Benign attack-alert rate | 18.12% | 30.18% | 33.21% |
| Benign review/escalation rate | 75.52% | 87.94% | 73.85% |
| Attack escalation | 100% | 100% | 100% |

The enriched model reduced UNKNOWN enough to lower total review slightly, but increased accepted false attack alerts substantially and reduced macro F1. It was therefore rejected. The expanded-validation findings also show that the earlier 98.65% test accuracy must not be generalized to all traffic sources. HOIC remains poorly recognized, and benign review varies greatly by source.

The source-separated train/test arrays were not mixed with validation. Source identities and dataset SHA-256 are in each experiment report. HOIC had already been inspected in earlier research and is validation here; it is not a new untouched final test. Any future claimed improvement needs additional independent labeled traffic after the training/selection recipe is fixed.

## Delivered testing improvements

The app now has **Test & demo**, with real capture hashes, separately recorded ground truth, exact-class comparisons, UNKNOWN rates, false attack alerts, escalation rates, capture inspection and report export. Labels are never inputs to inference. The same captured bytes uploaded under a misleading benign filename produce the same verdicts and fingerprints.

See [the demo guide](DEMO_GUIDE.md) and `docs/validation/demo-report.json`. Experiment summaries are in `docs/validation/improvement-experiments.json`; full local candidate reports are in `ml/checkpoints/improved_flow_resnet.json` and `ml/checkpoints/enriched_flow_resnet.json`. Neither candidate replaced the deployed checkpoint.

Verification: **22 Linux tests passed** with the native parser; Windows passed 21 with the native-extension case skipped. GPU HTTP/demo checks and the renamed-upload parity test passed. Browser automation was disabled in Work settings during this update, so the new page was verified through its live HTTP behavior and source/syntax checks rather than a new automated visual review.

## What is needed next

The main limitation is source/attack coverage, not GPU availability or simply longer training. Prioritize more independently labeled normal browsing, DNS, P2P and application sessions, plus a separate HTTP-flood training source while keeping CSE-21 isolated. Evaluate timing/rate/length features with a versioned training-serving representation; a first-16-packet byte fingerprint alone can resemble benign HTTP sessions. Validate on each source and attack family separately, with class/source-specific missed-attack limits so a large HOIC subset cannot conceal losses on smaller botnet subsets.

The next policy-selection design should enforce missed-attack constraints per class and source, rather than only the aggregate. The current rejected policy is retained as an experiment only. Do not reduce review rates by accepting uncertain attacks as benign, and do not report UNKNOWN as successful attack-type recognition.
