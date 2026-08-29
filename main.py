import json
import os
import re
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
    "Expires": "0"
}


def setup_dirs():
    os.makedirs(RULE_DIR, exist_ok=True)
    os.makedirs(TEMP_DIR, exist_ok=True)


def fetch_content(url):
    sep = "&" if "?" in url else "?"
    fresh_url = f"{url}{sep}_t={int(time.time())}"

    for attempt in range(3):
        try:
            resp = requests.get(fresh_url, headers=HEADERS, timeout=15)
            if resp.status_code == 200:
                return resp.text
        except Exception as e:
            print(f"[Warning] Failed to fetch {url} (Attempt {attempt+1}): {e}")
            time.sleep(2)
    return None


def parse_to_singbox_json(content):
    """
    将非 JSON 格式的规则文本（纯域名列表/Clash payload/规则文件）解析为 sing-box 规范 JSON
    """
    content_str = content.strip()

    # 1. 如果本身就是合法的 JSON 格式
    if content_str.startswith("{"):
        try:
            data = json.loads(content_str)
            if "rules" in data:
                return data
        except Exception:
            pass

    # 2. 如果是纯文本/Clash 格式规则，逐行提取域名
    domain_list = []
    domain_suffix_list = []
    domain_keyword_list = []
    domain_regex_list = []

    for line in content_str.splitlines():
        line = line.strip()
        # 忽略注释和空行、YAML 语法头
        if not line or line.startswith("#") or line.startswith("//") or line.startswith("payload:"):
            continue

        # 兼容 Clash/V2Ray 格式前缀，如 "- DOMAIN-SUFFIX,google.com" 或 "domain:google.com"
        line = re.sub(r"^[-'\"]+\s*", "", line).rstrip("',\"")
        
        if "," in line:
            parts = [p.strip() for p in line.split(",")]
            rule_type = parts[0].upper()
            target = parts[1] if len(parts) > 1 else ""
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
            # 默认作为 domain_suffix 匹配
            domain_suffix_list.append(line)

    rule_item = {}
    if domain_list:
        rule_item["domain"] = list(set(domain_list))
    if domain_suffix_list:
        rule_item["domain_suffix"] = list(set(domain_suffix_list))
    if domain_keyword_list:
        rule_item["domain_keyword"] = list(set(domain_keyword_list))
    if domain_regex_list:
        rule_item["domain_regex"] = list(set(domain_regex_list))

    return {
        "version": 1,
        "rules": [rule_item] if rule_item else []
    }


def compile_rule(rule_name, json_data):
    json_path = os.path.join(TEMP_DIR, f"{rule_name}.json")
    srs_path = os.path.join(RULE_DIR, f"{rule_name}.srs")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, ensure_ascii=False, indent=2)

    cmd = ["sing-box", "rule-set", "compile", json_path, "-o", srs_path]
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[Success] Successfully compiled: {rule_name}.srs")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[Error] Failed to compile {rule_name}: {e.stderr}")
        return False


def process_links():
    if not os.path.exists("links.txt"):
        print("[Error] links.txt not found!")
        sys.exit(1)

    with open("links.txt", "r", encoding="utf-8") as f:
        lines = f.readlines()

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

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
            print(f"[Skip] Could not retrieve content for {rule_name}")
            continue

        try:
            json_data = parse_to_singbox_json(content)
            # 写入时间戳确保生成的 .srs md5 变更，触发 git push
            json_data["_build_info"] = f"Updated at {timestamp}"
            compile_rule(rule_name, json_data)
        except Exception as e:
            print(f"[Error] Failed to parse/compile rule {rule_name}: {e}")


if __name__ == "__main__":
    setup_dirs()
    process_links()
