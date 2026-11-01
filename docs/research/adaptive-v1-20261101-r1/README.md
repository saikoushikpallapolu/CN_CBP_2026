# Measured first-study results

Experiment: `adaptive-v1-20261101-r1`. Final set: 1,814 sessions, five capture groups, 1,750 normal and 64 novel-family botnet sessions. No final DDoS examples. All percentages below are means over three seeds; these are not production-model accuracy claims.

| Model / adaptive policy | Correct accepted / all | Coverage | Benign false alerts | Benign review | Attacks accepted benign | Mean packets |
|---|---:|---:|---:|---:|---:|---:|
| resnet1d_prefix / adaptive | 39.42% | 44.25% | 4.69% | 56.72% | 8.85% | 2.53 |
| resnet1d_fixed16 / fixed16 | 23.36% | 25.05% | 1.43% | 76.55% | 8.85% | 3.92 |
| resnet2d_prefix / adaptive | 12.73% | 14.81% | 2.15% | 86.44% | 0.00% | 3.76 |
| hybrid_prefix / adaptive | 50.06% | 50.62% | 0.13% | 49.50% | 12.50% | 2.40 |
| logistic_behavior / adaptive | 73.48% | 89.25% | 15.03% | 10.74% | 35.94% | 2.59 |
| forest_behavior / adaptive | 62.07% | 63.74% | 1.64% | 35.77% | 2.60% | 4.39 |

Correct accepted / all penalizes review; it is not accuracy conditional on accepted predictions. Rejected attacks are not counted as recognized attacks. The apparent reduction in packet depth does not establish a general accuracy–delay improvement: validation constraints failed, source transfer is weak, seeds vary, and the development p95 context wait remains about 30 seconds.

Same-CPU batch64/context16 ONNX timings were approximately 40 ms FP32 versus 15.6 ms INT8 (two threads). This excludes packet waiting and the whole app pipeline.

Validation: 39 Python tests passed, one native-platform test skipped; all 20 frontend tests passed. Artifact hashes and all 15 same-machine neural probability replays passed after matching the original execution settings. Browser visual inspection and independent human reproduction remain pending.

[Method and limitations](../../RESEARCH_IMPLEMENTATION.md) · [Scorecard](scorecard.json) · [Full final results](final-evaluation.json) · [Ablation table](results.csv) · [Figure](accuracy-delay.svg)
