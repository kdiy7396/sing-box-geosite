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


def try_parse_as_singbox_json(content):
    """
    判定源内容是否为 sing-box 规则集 JSON。
    """
    stripped = content.lstrip("\ufeff").strip()
    if not stripped.startswith("{"):
        return None
    try:
        data = json.loads(stripped)
    except Exception:
        return None
    if isinstance(data, dict) and "rules" in data:
        return data
    return None


def determine_domain_version(domain_rule):
    """
    需求4：非仅含有"domain"参数的域名文件使用"version": 2，
    仅含有"domain"参数域名文件使用"version": 1
    """
    if not domain_rule:
        return 1
    
    keys = set(domain_rule.keys())
    if keys == {"domain"}:
        return 1
    return 2


def split_singbox_json(data):
    """
    需求3：对于源 json 格式且符合 sing-box 规则的文件，提取其内部的域名与 IP 进行拆分。
    """
    domain_list, domain_suffix_list = [], []
    domain_keyword_list, domain_regex_list = [], []
    ip_cidr_list = []

    rules = data.get("rules", [])
    for r in rules:
        if not isinstance(r, dict):
            continue

    KNOWN_KEYS = {"domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr"}
    rules = data.get("rules", [])
    for r in rules:
        if not isinstance(r, dict):
            continue

        unknown_keys = set(r.keys()) - KNOWN_KEYS
        if unknown_keys:
            print(f"  [Warning] 源 JSON 中存在未处理的字段，可能导致规则丢失: {unknown_keys}")

        if "domain" in r:
            domain_list.extend(r["domain"] if isinstance(r["domain"], list) else [r["domain"]])
        if "domain_suffix" in r:
            domain_suffix_list.extend(r["domain_suffix"] if isinstance(r["domain_suffix"], list) else [r["domain_suffix"]])
        if "domain_keyword" in r:
            domain_keyword_list.extend(r["domain_keyword"] if isinstance(r["domain_keyword"], list) else [r["domain_keyword"]])
        if "domain_regex" in r:
            domain_regex_list.extend(r["domain_regex"] if isinstance(r["domain_regex"], list) else [r["domain_regex"]])
        if "ip_cidr" in r:
            ip_cidr_list.extend(r["ip_cidr"] if isinstance(r["ip_cidr"], list) else [r["ip_cidr"]])

    domain_rule = {}
    if domain_list:
        domain_rule["domain"] = sorted(set(domain_list))
    if domain_suffix_list:
        domain_rule["domain_suffix"] = sorted(set(domain_suffix_list))
    if domain_keyword_list:
        domain_rule["domain_keyword"] = sorted(set(domain_keyword_list))
    if domain_regex_list:
        domain_rule["domain_regex"] = sorted(set(domain_regex_list))

    domain_json_data = None
    if domain_rule:
        v = determine_domain_version(domain_rule)
        domain_json_data = {"version": v, "rules": [domain_rule]}

    ip_json_data = None
    if ip_cidr_list:
        ip_json_data = {"version": 1, "rules": [{"ip_cidr": sorted(set(ip_cidr_list))}]}

    return domain_json_data, ip_json_data


def parse_to_singbox_json_split(content):
    """
    处理 Clash/Surge/规则列表等纯文本文件，拆分为 domain 类和 ip_cidr 类。
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

    domain_rule = {}
    if domain_list:
        domain_rule["domain"] = sorted(set(domain_list))
    if domain_suffix_list:
        domain_rule["domain_suffix"] = sorted(set(domain_suffix_list))
    if domain_keyword_list:
        domain_rule["domain_keyword"] = sorted(set(domain_keyword_list))
    if domain_regex_list:
        domain_rule["domain_regex"] = sorted(set(domain_regex_list))

    domain_json_data = None
    if domain_rule:
        v = determine_domain_version(domain_rule)
        domain_json_data = {"version": v, "rules": [domain_rule]}

    ip_json_data = None
    ip_cidr_list = sorted(set(ip_cidr_list))
    if ip_cidr_list:
        ip_json_data = {"version": 1, "rules": [{"ip_cidr": ip_cidr_list}]}

    return domain_json_data, ip_json_data


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
            singbox_data = try_parse_as_singbox_json(content)
            
            if singbox_data is not None:
                # 尝试对 sing-box JSON 进行字段提取
                domain_json, ip_json = split_singbox_json(singbox_data)
                
                has_domain = domain_json is not None
                has_ip = ip_json is not None

                # 分情况处理：
                if has_domain and has_ip:
                    # 1. 混合规则 -> 需求3：触发拆分，分别输出 Name 和 Name-ip
                    pass  # 保持 domain_json 和 ip_json，进入下方的 compile_rule 流程

                elif has_domain and not has_ip:
                    # 2. 纯域名规则 -> 需求1：原样直通（保留原始 JSON 格式与缩进）
                    if handle_direct_json(rule_name, content):
                        success_count += 1
                    else:
                        fail_count += 1
                    continue

                elif not has_domain and has_ip:
                    # 3. 纯 IP 规则 -> 原样直通并加上 -ip 后缀命名（按需保持统一）
                    if handle_direct_json(f"{rule_name}-ip", content):
                        success_count += 1
                    else:
                        fail_count += 1
                    continue

            else:
                # 需求2：非 sing-box JSON 文本（Clash/Surge 等），走常规解析与拆分
                domain_json, ip_json = parse_to_singbox_json_split(content)

            # --- 统一的编译输出入口（处理混合规则 & 非 JSON 源）---
            processed_any = False

            # 输出与编译域名规则
            if domain_json and compile_rule(rule_name, domain_json):
                processed_any = True
            
            # 输出与编译 IP 规则 (-ip 后缀)
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
