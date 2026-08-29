import os
import subprocess
import time

RULE_DIR = "rule"
# 定义过期阈值（秒）：30 天 = 30 * 24 * 3600
DAYS_THRESHOLD = 30
SECONDS_THRESHOLD = DAYS_THRESHOLD * 24 * 3600


def get_git_file_mtime(file_path):
    """通过 git log 获取文件在 Git 仓库中最后一次提交的时间戳"""
    try:
        cmd = ["git", "log", "-1", "--format=%ct", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        timestamp_str = result.stdout.strip()
        if timestamp_str:
            return float(timestamp_str)
    except Exception as e:
        print(f"[Warning] Failed to get git mtime for {file_path}: {e}")

    # 如果无法获取 git 时间（例如新未提交的文件），回退使用文件系统 mtime
    return os.path.getmtime(file_path)


def clean_expired_rules():
    if not os.path.exists(RULE_DIR):
        print(f"[Clean] Directory '{RULE_DIR}' does not exist. Skipping clean up.")
        return

    now = time.time()
    removed_count = 0

    print(
        f"[Clean] Scanning for files older than {DAYS_THRESHOLD} days in '{RULE_DIR}'..."
    )

    for root, _, files in os.walk(RULE_DIR):
        for file in files:
            if file.endswith(".srs") or file.endswith(".json"):
                file_path = os.path.join(root, file)
                try:
                    # 获取文件真实的最后一次 Git 提交时间
                    last_commit_time = get_git_file_mtime(file_path)
                    file_age_days = (now - last_commit_time) / (24 * 3600)

                    if (now - last_commit_time) > SECONDS_THRESHOLD:
                        os.remove(file_path)
                        removed_count += 1
                        print(
                            f"[Clean Removed] {file} (Last commit: {file_age_days:.1f} days ago)"
                        )
                except Exception as e:
                    print(f"[Clean Error] Could not process {file_path}: {e}")

    print(f"[Clean Finished] Total expired files removed: {removed_count}")


if __name__ == "__main__":
    clean_expired_rules()
