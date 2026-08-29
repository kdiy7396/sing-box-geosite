import os
import time

RULE_DIR = "rule"
# 定义过期阈值（秒）：30 天 = 30 * 24 * 3600
DAYS_THRESHOLD = 30
SECONDS_THRESHOLD = DAYS_THRESHOLD * 24 * 3600

def clean_expired_rules():
    if not os.path.exists(RULE_DIR):
        print(f"[Clean] Directory '{RULE_DIR}' does not exist. Skipping clean up.")
        return

    now = time.time()
    removed_count = 0

    print(f"[Clean] Scanning for files older than {DAYS_THRESHOLD} days in '{RULE_DIR}'...")

    for root, _, files in os.walk(RULE_DIR):
        for file in files:
            if file.endswith(".srs") or file.endswith(".json"):
                file_path = os.path.join(root, file)
                try:
                    file_mtime = os.path.getmtime(file_path)
                    file_age_days = (now - file_mtime) / (24 * 3600)
                    
                    if (now - file_mtime) > SECONDS_THRESHOLD:
                        os.remove(file_path)
                        removed_count += 1
                        print(f"[Clean Removed] {file} (Unchanged for {file_age_days:.1f} days)")
                except Exception as e:
                    print(f"[Clean Error] Could not process {file_path}: {e}")

    print(f"[Clean Finished] Total expired files removed: {removed_count}")

if __name__ == "__main__":
    clean_expired_rules()
