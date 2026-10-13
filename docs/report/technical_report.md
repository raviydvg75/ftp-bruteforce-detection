# FTP Brute-Force Detection Using Security Logs

**Organization:** RedKross Research Foundation  
**Research Track:** Reproducible Cybersecurity Research & Evaluation  
**Researcher:** Rabi Bhushan Yadav  
**Implementation:** Python  
**Status:** Initial implementation and synthetic-data evaluation  
**Submission deadline:** 25 October 2026

## Abstract

This project implements a Python-based method for identifying possible FTP brute-force activity from normalized authentication logs. The pipeline parses CSV events, groups failed login attempts by source IP address, and applies a sliding time window to detect repeated failures. Automated tests and a threshold-sensitivity experiment support reproducibility.

Four thresholds—3, 4, 5, and 6 failures within a 10-minute window—were evaluated against six handcrafted source-IP scenarios. Threshold 5 achieved 100% accuracy, precision, recall, and F1-score on this small synthetic dataset. Thresholds 3 and 4 produced one false positive, while threshold 6 missed both positive-labelled scenarios. These results describe only the constructed dataset and do not establish real-world detection performance.

## 1. Introduction

FTP authentication logs can contain evidence of repeated unsuccessful login attempts. A high number of failures from one source IP address within a short interval may indicate a brute-force attempt, although legitimate mistakes can produce similar patterns.

This project investigates a simple, interpretable detection method based on failure counts and a configurable time window. Its purpose is to develop a reproducible research prototype and examine how threshold selection affects detection outcomes.

### 1.1 Research question

How does the failed-login threshold affect the detection of labelled FTP brute-force scenarios within a fixed 10-minute window?

### 1.2 Objectives

1. Parse and validate structured authentication logs.
2. Detect repeated failures from individual source IP addresses.
3. Evaluate four detection thresholds.
4. Calculate classification metrics.
5. Validate core behavior through automated tests.
6. Document the experiment for independent reproduction.

### 1.3 Hypothesis

A moderate failure threshold may balance detection sensitivity and false-positive reduction better than thresholds that are too low or too high.

## 2. Scope

The current implementation processes normalized CSV records offline. It is a research prototype, not a production intrusion detection system.

The expected fields are:

- `timestamp`: authentication event time.
- `source_ip`: originating IP address.
- `username`: account used in the attempt.
- `event`: `success` or `failure`.

The evaluation data and labels are handcrafted synthetic scenarios. No claim is made that the dataset represents real-world FTP traffic.

## 3. Methodology

### 3.1 Processing pipeline

The pipeline follows these stages:

1. Read and validate the input CSV.
2. Parse timestamps into datetime objects.
3. Select failed authentication events.
4. Group failures by source IP.
5. Sort each IP's events chronologically.
6. Maintain a rolling window of failures.
7. Generate an alert when the configured threshold is reached.
8. Compare flagged IP addresses with the labelled scenarios.
9. Calculate and save evaluation metrics.

### 3.2 Detection rule

An alert is generated when the number of failed logins from a source IP within the rolling window reaches the configured threshold.

\[
F_{IP}(t,W)\geq T
\]

Where:

- \(F_{IP}(t,W)\) is the number of failures from an IP address in the window.
- \(W\) is the window duration.
- \(T\) is the threshold.

The baseline experiment uses a 10-minute window and tests thresholds of 3, 4, 5, and 6. Events exactly at the window boundary remain in the active window because the implementation removes events only when their age exceeds the configured duration.

### 3.3 Dataset

The evaluation contains six source-IP scenarios, with labels stored in `data/sample/ground_truth.csv` and events in `data/sample/evaluation_events.csv`.

The positive labels are assigned to `192.0.2.10` and `192.0.2.50`. The other four scenarios are labelled negative. These are manually constructed scenario labels, not independent ground truth derived from actual network traffic.

### 3.4 Evaluation metrics

The project calculates:

\[
Accuracy=\frac{TP+TN}{TP+TN+FP+FN}
\]

\[
Precision=\frac{TP}{TP+FP}
\]

\[
Recall=\frac{TP}{TP+FN}
\]

\[
F_1=2\frac{Precision\times Recall}{Precision+Recall}
\]

\[
FPR=\frac{FP}{FP+TN}
\]

Here, TP means true positive, TN true negative, FP false positive, and FN false negative.

## 4. Implementation

| Component | Purpose |
|---|---|
| `src/parser.py` | CSV parsing and input validation |
| `src/detector.py` | Sliding-window detection |
| `src/metrics.py` | Classification metrics |
| `src/evaluator.py` | Baseline evaluation |
| `scripts/evaluate_dataset.py` | Label-based evaluation |
| `scripts/threshold_experiment.py` | Threshold comparison |
| `tests/` | Automated unit tests |
| `data/sample/` | Synthetic input data and labels |
| `results/metrics/` | Generated metric files |

The project uses Python's standard library for the main pipeline and automated tests.

## 5. Results

### 5.1 Threshold comparison

| Threshold | TP | TN | FP | FN | Accuracy | Precision | Recall | F1-score | FPR |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 3 | 2 | 3 | 1 | 0 | 83.33% | 66.67% | 100% | 80% | 25% |
| 4 | 2 | 3 | 1 | 0 | 83.33% | 66.67% | 100% | 80% | 25% |
| 5 | 2 | 4 | 0 | 0 | 100% | 100% | 100% | 100% | 0% |
| 6 | 0 | 4 | 0 | 2 | 66.67% | 0% | 0% | 0% | 0% |

These figures are from the recorded synthetic-data experiment.

### 5.2 Flagged source IPs

- **Threshold 3:** `192.0.2.10`, `192.0.2.40`, `192.0.2.50`.
- **Threshold 4:** `192.0.2.10`, `192.0.2.40`, `192.0.2.50`.
- **Threshold 5:** `192.0.2.10`, `192.0.2.50`.
- **Threshold 6:** No source IPs flagged.

The address `192.0.2.40` is labelled negative and becomes a false positive at thresholds 3 and 4. At threshold 5, the two positive-labelled scenarios are detected without a false positive in this dataset. At threshold 6, both positive-labelled scenarios are missed.

### 5.3 Unit tests

The test suite completed successfully with 13 passing tests:

- Five detector tests.
- Five metric tests.
- Three parser tests.

The tests cover selected behaviors, including threshold detection, successful logins, time-window handling, source-IP separation, invalid parameters, metric calculations, and invalid input. They establish correctness only for the cases tested.

## 6. Discussion

The results illustrate a trade-off between sensitivity and false positives. Lower thresholds can identify smaller bursts of failures but may flag benign activity. Higher thresholds may reduce alerts while missing attacks that do not reach the threshold.

Threshold 5 performed best on the six constructed scenarios. This does not establish that five failures is the optimal threshold for real systems. The result depends on the small dataset, event timing, and manually assigned labels.

Alert counts and source-IP classifications should also be distinguished: the detector can produce alerts, while the evaluation treats each source IP as one binary prediction.

## 7. Limitations

1. The dataset contains only six source-IP scenarios.
2. The events and labels are synthetic and manually constructed.
3. The detector uses a limited set of authentication features.
4. Shared IP addresses, NAT, proxies, and changing addresses can complicate attribution.
5. The current evaluation does not establish performance on unseen real-world traffic.
6. The implementation has not been validated as a production monitoring system.

## 8. Ethical considerations

The current evaluation uses synthetic records. Any future use of real security logs should be authorized and should follow appropriate privacy, access-control, and data-retention practices. Testing should be confined to systems owned by the researcher or used with explicit permission.

## 9. Future work

1. Collect representative authentication logs from an authorized lab.
2. Document data collection, preprocessing, and independent labelling.
3. Add tests for exact window boundaries and out-of-order events.
4. Document alert deduplication and alert-event counting.
5. Evaluate more thresholds and window durations.
6. Compare results on a larger, independently labelled dataset.
7. Add visualizations and a reproducible demonstration.
8. Conduct and document a sourced literature review.

## 10. Conclusion

This project implements a Python pipeline for identifying repeated FTP authentication failures and evaluating threshold-based detection. The experiment found that threshold 5 classified all six handcrafted scenarios correctly, while thresholds 3 and 4 produced one false positive and threshold 6 missed both positive-labelled scenarios.

The results provide a reproducible starting point for further investigation, but they should not be interpreted as evidence of real-world detection accuracy. Additional evaluation with representative, independently labelled logs is required.

## References

**To complete before submission:** Add verified references on FTP security, authentication-log analysis, threshold-based intrusion detection, classification metrics, and reproducible cybersecurity research. Each reference should be read and cited in the relevant section; do not include sources that have not been checked.

## Appendix A: Reproduction commands

Run from the repository root:

```bash
python -m src.evaluator
python -m scripts.evaluate_dataset
python -m scripts.threshold_experiment
python -m unittest discover -s tests -v
```

Before submission, verify these commands, document the Python version and dependencies, capture actual terminal evidence, and add the GitHub repository and demonstration-video URLs.
