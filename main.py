import json
import os
import re
import shutil
import subprocess
import sys
import time
import requests

RULE_DIR = "rule"
TEMP_DIR = "temp"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}


def setup_dirs():
    # 强制清理临时文件夹
    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)
    os.makedirs(RULE_DIR, exist_ok=True)
    os.makedirs(TEMP_DIR, exist_ok=True)


def fetch_content(url):
    sep = "&" if "?" in url else "?"
    fresh_url = f"{url}{sep}_t={int(time.time())}"

    for attempt in range(3):
        try:
            resp = requests.get(fresh_url, headers=HEADERS, timeout=20)
            if resp.status_code == 200:
                return resp.text
            else:
                print(f"[Warning] HTTP {resp.status_code} for {url}")
        except Exception as e:
            print(f"[Warning] Failed to fetch {url} (Attempt {attempt+1}): {e}")
            time.sleep(2)
    return None


def parse_to_singbox_json(content):
    content_str = content.strip()

    # 1. 已经是合法 JSON 格式
    if content_str.startswith("{"):
        try:
            data = json.loads(content_str)
            # 必须包含 rules 或 domain 节点
            if "rules" in data or "version" in data:
                return data
        except Exception:
            pass

    # 2. 文本/Clash/Rule 格式转换
    domain_list = []
    domain_suffix_list = []
    domain_keyword_list = []
    domain_regex_list = []

    for line in content_str.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//") or line.startswith("payload:"):
            continue

        line = re.sub(r"^[-'\"]+\s*", "", line).rstrip("',\"")

        if "," in line:
            parts = [p.strip() for p in line.split(",")]
            rule_type = parts[0].upper()
            target = parts[1] if len(parts) > 1 else ""
            if target:
                if rule_type in ["DOMAIN-SUFFIX", "HOST-SUFFIX"]:
                    domain_suffix_list.append(target)
                elif rule_type in ["DOMAIN", "HOST"]:
                    domain_list.append(target)
                elif rule_type in ["DOMAIN-KEYWORD", "HOST-KEYWORD"]:
                    domain_keyword_list.append(target)
                elif rule_type in ["DOMAIN-REGEX", "HOST-REGEX"]:
                    domain_regex_list.append(target)
            continue

        if line.startswith("full:"):
            domain_list.append(line[5:])
        elif line.startswith("domain:"):
            domain_suffix_list.append(line[7:])
        elif line.startswith("keyword:"):
            domain_keyword_list.append(line[8:])
        elif line.startswith("regexp:"):
            domain_regex_list.append(line[7:])
        elif line.startswith("+."):
            domain_suffix_list.append(line[2:])
        elif line.startswith("."):
            domain_suffix_list.append(line[1:])
        else:
            domain_suffix_list.append(line)

    rule_item = {}
    if domain_list:
        rule_item["domain"] = sorted(list(set(domain_list)))
    if domain_suffix_list:
        rule_item["domain_suffix"] = sorted(list(set(domain_suffix_list)))
    if domain_keyword_list:
        rule_item["domain_keyword"] = sorted(list(set(domain_keyword_list)))
    if domain_regex_list:
        rule_item["domain_regex"] = sorted(list(set(domain_regex_list)))

    return {
        "version": 1,
        "rules": [rule_item] if rule_item else []
    }


def compile_rule(rule_name, json_data):
    json_path = os.path.join(TEMP_DIR, f"{rule_name}.json")
    srs_path = os.path.join(RULE_DIR, f"{rule_name}.srs")

    # 写入严格规范的 JSON 文件
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, ensure_ascii=False, indent=2)

    cmd = ["sing-box", "rule-set", "compile", json_path, "-o", srs_path]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            print(f"[Success] Compiled: {rule_name}.srs")
            return True
        else:
            print(f"[Error] sing-box compile failed for {rule_name}: {res.stderr.strip()}")
            return False
    except Exception as e:
        print(f"[Exception] Failed to run sing-box for {rule_name}: {e}")
        return False


def process_links():
    if not os.path.exists("links.txt"):
        print("[Error] links.txt not found!")
        sys.exit(1)

    with open("links.txt", "r", encoding="utf-8") as f:
        lines = f.readlines()

    success_count = 0
    fail_count = 0

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(",", 1)
        if len(parts) < 2:
            continue

        rule_name = parts[0].strip()
        url = parts[1].strip()

        print(f"\n[Processing] {rule_name} from {url}")
        content = fetch_content(url)
        if not content:
            print(f"[Skip] Failed to fetch content for {rule_name}")
            fail_count += 1
            continue

        try:
            json_data = parse_to_singbox_json(content)
            if compile_rule(rule_name, json_data):
                success_count += 1
            else:
                fail_count += 1
        except Exception as e:
            print(f"[Error] Exception in parsing {rule_name}: {e}")
            fail_count += 1

    print(f"\nFinished processing. Success: {success_count}, Failed: {fail_count}")


if __name__ == "__main__":
    setup_dirs()
    process_links()
