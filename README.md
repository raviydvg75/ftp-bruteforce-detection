FTP Brute-Force Detection
A reproducible cybersecurity research project that explores detecting repeated FTP authentication failures from security logs using a configurable sliding time window. The project includes a Python detection pipeline, evaluation utilities, and a Streamlit dashboard for inspecting authentication events and alerts.
Research note: This is a research prototype, not a production security control. Sample logs are synthetic and must not be presented as evidence of real-world detection performance.

Project goals
- Parse authentication events from log data.
- Group failed login attempts by source IP address.
- Detect repeated failures using a configurable threshold and time window.
- Evaluate detection behavior using metrics such as precision, recall, F1-score, and false-positive rate.
- Make experiments easier to reproduce and inspect.
Features
- Configurable failed-login threshold and time window.
- Python-based event parsing and detection.
- Evaluation scripts for labelled datasets and threshold experiments.
- Streamlit dashboard for viewing events and generated alerts.
- Synthetic FTP authentication log for local testing.
Repository structure
ftp-bruteforce-detection/
├── app.py
├── requirements.txt
├── src/
│   ├── parser.py
│   ├── detector.py
│   ├── metrics.py
│   └── evaluator.py
├── scripts/
│   ├── evaluate_dataset.py
│   └── threshold_experiment.py
├── data/
│   └── ftp_bruteforce_sample.log
└── tests/
The exact files may vary as the project evolves. Keep datasets, scripts, and documentation aligned with the actual repository contents.
Requirements
- Python 3.10 or newer is recommended.
- pip and Python virtual-environment support.
- Linux is recommended for testing against Linux authentication logs.
- For the dashboard, install the dependencies listed in requirements.txt.
Setup
Clone the repository and enter its directory:
git clone https://github.com/raviydvg75/ftp-bruteforce-detection.git
cd ftp-bruteforce-detection
Create and activate a virtual environment:
python3 -m venv .venv
source .venv/bin/activate
Install dependencies:
python -m pip install --upgrade pip
pip install -r requirements.txt
Run the dashboard
Start Streamlit from the repository root:
python -m streamlit run app.py
Streamlit will print a local URL (usually http://localhost:8501) to open in your browser.
In the dashboard, select the available input mode, configure the failure threshold and time window, then inspect the events and alerts. For a quick test, use the synthetic sample log if the dashboard supports uploaded log files.
Test with the synthetic log
The repository's sample log is synthetic and contains simulated FTP/PAM authentication-failure entries. It is intended to exercise log parsing and alerting logic; it is not a capture from a real system.
If the sample is stored at data/ftp_bruteforce_sample.log, you can inspect it with:
head data/ftp_bruteforce_sample.log
wc -l data/ftp_bruteforce_sample.log
For an upload-based dashboard, choose Upload log file and select data/ftp_bruteforce_sample.log.
With a threshold of 5 failures in a 10-minute window, the source IP 192.168.56.101 is intended to trigger an alert if the parser recognizes the sample's log format and the dashboard evaluates the historical timestamps correctly. Other source IPs have fewer failures. Actual outcomes depend on the current parser and detection implementation.
Detection approach
At a high level, the detector:
1. Reads authentication events and extracts timestamps, usernames, source IPs, and outcomes.
2. Identifies failed authentication events.
3. Groups events by source IP address.
4. Counts failures within a sliding time window.
5. Emits an alert when the configured threshold is reached.
The threshold and window should be treated as experimental parameters. Lower thresholds can detect more activity but may increase false positives; higher thresholds may miss slower or less frequent attempts.
Evaluation
The evaluation utilities are intended to compare detector output against labelled examples. Common classification metrics include:
- Precision: proportion of predicted positive cases that are true positives.
- Recall: proportion of true positive cases that are detected.
- F1-score: harmonic mean of precision and recall.
- False-positive rate (FPR): proportion of actual negative cases incorrectly flagged.
Report the dataset source, number of events, label-generation method, threshold, time window, and evaluation procedure alongside any results. Synthetic or very small datasets are useful for functional tests but are not sufficient to establish generalizable real-world performance.
Research reproducibility checklist
For each experiment, record:
- Dataset name, provenance, and whether it is synthetic or real.
- Data-cleaning and parsing rules.
- Train/test separation or evaluation split, if applicable.
- Detection threshold and time window.
- Definitions of positive and negative cases.
- TP, TN, FP, FN, precision, recall, F1-score, and FPR where applicable.
- Software versions, command used, and experiment date.
- Limitations, failed cases, and known parser assumptions.
Do not publish private, personally identifiable, or sensitive production logs. Sanitize any real log data before using it in a public repository.
Safe lab setup
For live-log experiments, use an isolated lab consisting only of systems you own or have explicit permission to test. Keep the FTP service on a VirtualBox host-only or internal network and avoid exposing an intentionally vulnerable service to the public internet. Use a dedicated test account and controlled failed-login attempts.
FTP transmits credentials without encryption in its standard form. Do not use real or reused passwords in this lab. Prefer secure alternatives such as SFTP for actual file transfers.
Limitations
- Log formats vary between FTP servers, PAM configurations, and Linux distributions.
- Timestamp parsing may depend on the year and timezone assumed for syslog-style timestamps.
- A source-IP threshold is a simple baseline and does not detect every attack pattern.
- NAT, shared networks, legitimate user mistakes, and distributed attempts can affect detection quality.
- The dashboard and scripts should be validated against representative labelled data before operational use.
Contributing
Issues and pull requests are welcome. Include reproducible steps, example inputs that contain no sensitive data, expected behavior, and actual behavior when reporting bugs.
License
No license has been specified yet. Unless a license is added to the repository, standard copyright restrictions apply. Add a LICENSE file before explicitly granting reuse permissions.
Author
Rabi Bhushan Yadav
Computer Engineering student | Cybersecurity research and detection engineering
GitHub: @raviydvg75
