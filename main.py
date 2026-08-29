import json
import os
import re
import shutil
import subprocess
import sys
import time
import requests
import ipaddress

RULE_DIR = "rule"
TEMP_DIR = "temp"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}


def setup_dirs():
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


def is_cidr(s):
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def compile_srs(json_path, srs_path, label):
    cmd = ["sing-box", "rule-set", "compile", json_path, "-o", srs_path]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            print(f"  [Success] Compiled: {os.path.basename(srs_path)}")
            return True
        print(f"  [Error] sing-box compile failed for {label}: {res.stderr.strip()}")
        return False
    except Exception as e:
        print(f"  [Exception] Failed to run sing-box for {label}: {e}")
        return False


def handle_direct_json(rule_name, raw_content):
    """
    需求1：源本身即合法 sing-box JSON -> 不做任何字段提取/拆分/排序，
    原样落盘并直接编译成 srs，文件命名不变。
    """
    final_json_path = os.path.join(RULE_DIR, f"{rule_name}.json")
    temp_json_path = os.path.join(TEMP_DIR, f"{rule_name}.json")
    srs_path = os.path.join(RULE_DIR, f"{rule_name}.srs")

    # 直接写入原始抓取内容，保证与源文件一致（“同步输出原json文件”）
    with open(final_json_path, "w", encoding="utf-8") as f:
        f.write(raw_content)
    with open(temp_json_path, "w", encoding="utf-8") as f:
        f.write(raw_content)

    return compile_srs(temp_json_path, srs_path, rule_name)


def parse_to_singbox_json_split(content):
    """
    需求2：把非 sing-box-JSON 格式的源（Clash/Surge/mosdns 纯文本等）解析后，
    按类型拆分为 domain 类 JSON 和 ip_cidr 类 JSON。
    """
    content_str = content.strip()
    domain_list, domain_suffix_list = [], []
    domain_keyword_list, domain_regex_list = [], []
    ip_cidr_list = []

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
                elif rule_type in ["IP-CIDR", "IP6-CIDR", "IP-CIDR6"]:
                    ip_cidr_list.append(target)
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
        elif is_cidr(line):
            ip_cidr_list.append(line)
        else:
            domain_suffix_list.append(line)

    domain_list = sorted(set(domain_list))
    domain_suffix_list = sorted(set(domain_suffix_list))
    domain_keyword_list = sorted(set(domain_keyword_list))
    domain_regex_list = sorted(set(domain_regex_list))
    ip_cidr_list = sorted(set(ip_cidr_list))

    domain_rule = {}
    if domain_list:
        domain_rule["domain"] = domain_list
    if domain_suffix_list:
        domain_rule["domain_suffix"] = domain_suffix_list
    if domain_keyword_list:
        domain_rule["domain_keyword"] = domain_keyword_list
    if domain_regex_list:
        domain_rule["domain_regex"] = domain_regex_list

    domain_json_data = {"version": 1, "rules": [domain_rule]} if domain_rule else None
    ip_json_data = {"version": 1, "rules": [{"ip_cidr": ip_cidr_list}]} if ip_cidr_list else None
    return domain_json_data, ip_json_data


def compile_rule(rule_name, json_data):
    temp_json_path = os.path.join(TEMP_DIR, f"{rule_name}.json")
    final_json_path = os.path.join(RULE_DIR, f"{rule_name}.json")
    srs_path = os.path.join(RULE_DIR, f"{rule_name}.srs")

    with open(final_json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, ensure_ascii=False, indent=2)
    with open(temp_json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, ensure_ascii=False, indent=2)

    return compile_srs(temp_json_path, srs_path, rule_name)


def derive_rule_name(url):
    base = url.rstrip("/").split("/")[-1]
    return re.sub(r"\.(ya?ml|list|txt|conf|json)$", "", base, flags=re.IGNORECASE)


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

        if "," in line and line.split(",", 1)[1].strip().startswith(("http://", "https://")):
            rule_name, url = (p.strip() for p in line.split(",", 1))
        else:
            url = line
            rule_name = derive_rule_name(url)

        if not rule_name or not url:
            print(f"[Skip] Invalid line: {line}")
            continue

        print(f"\n[Processing] {rule_name} from {url}")
        content = fetch_content(url)
        if not content:
            print(f"[Skip] Failed to fetch content for {rule_name}")
            fail_count += 1
            continue

        try:
            # 需求1：优先判定是否已是 sing-box JSON，是则直通，不再拆分
            if try_parse_as_singbox_json(content) is not None:
                if handle_direct_json(rule_name, content):
                    success_count += 1
                else:
                    fail_count += 1
                continue

            # 需求2：其余格式统一解析后按 domain / ip_cidr 拆分输出
            domain_json, ip_json = parse_to_singbox_json_split(content)
            processed_any = False

            if domain_json and compile_rule(rule_name, domain_json):
                processed_any = True
            if ip_json and compile_rule(f"{rule_name}-ip", ip_json):
                processed_any = True

            if processed_any:
                success_count += 1
            else:
                print(f"  [Warning] No valid rules found in {rule_name}")
                fail_count += 1

        except Exception as e:
            print(f"[Error] Exception in parsing {rule_name}: {e}")
            fail_count += 1

    print(f"\nFinished processing. Success: {success_count}, Failed: {fail_count}")
    if success_count == 0:
        print("[Fatal] 没有任何规则被成功编译，判定本次同步失败。")
        sys.exit(1)


if __name__ == "__main__":
    setup_dirs()
    process_links()
