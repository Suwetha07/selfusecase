import re,json,datetime
from collections import Counter, defaultdict
from pathlib import Path
logfile = "sample.log"        
REPORT_FILE = "anomaly_report.json"
RARE_THRESHOLD = 2               
ANOMALY_SCORE_THRESHOLD = 2      
def clean_and_tokenize(text):
    words = re.findall(r"\b[a-zA-Z0-9_]+\b", text.lower())
    return words
def analyze_log(file_path):
    word_counter = Counter()
    lines = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            tokens = clean_and_tokenize(line)
            word_counter.update(tokens)
            lines.append((line.strip(), tokens))
    rare_words = {word for word, count in word_counter.items() if count <= RARE_THRESHOLD}
    suspicious_entries = []
    for line_text, tokens in lines:
        rare_count = sum(1 for token in tokens if token in rare_words)
        if rare_count >= ANOMALY_SCORE_THRESHOLD:
            suspicious_entries.append({
                "log_line": line_text,
                "rare_word_count": rare_count,
                "rare_words_found": [token for token in tokens if token in rare_words]
            })
    report = {
        "scan_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "total_lines_analyzed": len(lines),
        "unique_words": len(word_counter),
        "rare_word_threshold": RARE_THRESHOLD,
        "anomaly_score_threshold": ANOMALY_SCORE_THRESHOLD,
        "total_anomalies_detected": len(suspicious_entries),
        "top_10_most_common_words": word_counter.most_common(10),
        "anomalies": suspicious_entries
    }
    return report
def save_report(report):
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=4)
if __name__ == "__main__":
    if not Path(LOG_FILE).exists():
        print(f"Log file '{LOG_FILE}' not found.")
        exit()
    report = analyze_log(LOG_FILE)
    save_report(report)
    print("\n=== LOG ANOMALY SUMMARY ===")
    print(f"Lines Analyzed: {report['total_lines_analyzed']}")
    print(f"Unique Words: {report['unique_words']}")
    print(f"Anomalies Detected: {report['total_anomalies_detected']}")
    print(f"Report saved to: {Path(REPORT_FILE).absolute()}")
