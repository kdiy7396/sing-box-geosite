import json
import os
import subprocess
import sys

RULE_DIR = "rule"
TEMP_DIR = "temp"


def process_and_split_json_file(file_path):
    """检查指定的 JSON 文件是否混合包含域名与 IPcidr 规则，如果是则拆分输出并重新编译"""
    file_name = os.path.basename(file_path)
    if not file_name.endswith(".json") or file_name.endswith("-ip.json"):
        return

    base_name = file_name[:-5]

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[Error] Failed to load JSON {file_path}: {e}")
        return

    rules = data.get("rules", [])
    if not rules:
        return

    has_domain = False
    has_ip = False

    domain_rules_list = []
    ip_rules_list = []

    domain_keys = {"domain", "domain_suffix", "domain_keyword", "domain_regex"}

    for rule in rules:
        if not isinstance(rule, dict):
            continue

        # 校验是否存在域名类 key
        rule_domain_part = {k: v for k, v in rule.items() if k in domain_keys and v}
        if rule_domain_part:
            has_domain = True
            domain_rules_list.append(rule_domain_part)

        # 校验是否存在 IP 规则 key
        if "ip_cidr" in rule and rule["ip_cidr"]:
            has_ip = True
            ip_rules_list.append({"ip_cidr": rule["ip_cidr"]})

    # 当且仅当同时含有域名和 IP 规则时进行拆分
    if has_domain and has_ip:
        print(f"[Split Triggered] Mixed rule detected in: {file_name}")

        # 1. 覆盖生成原名称的纯域名 JSON & SRS
        domain_json_data = {"version": 1, "rules": domain_rules_list}
        domain_json_path = os.path.join(RULE_DIR, f"{base_name}.json")
        domain_srs_path = os.path.join(RULE_DIR, f"{base_name}.srs")

        with open(domain_json_path, "w", encoding="utf-8") as f:
            json.dump(domain_json_data, f, ensure_ascii=False, indent=2)
        subprocess.run(["sing-box", "rule-set", "compile", domain_json_path, "-o", domain_srs_path], capture_output=True)
        print(f"  -> Generated Domain rule: {base_name}.json & {base_name}.srs")

        # 2. 生成添加 -ip 后缀的纯 IP JSON & SRS
        ip_json_data = {"version": 1, "rules": ip_rules_list}
        ip_rule_name = f"{base_name}-ip"
        ip_json_path = os.path.join(RULE_DIR, f"{ip_rule_name}.json")
        ip_srs_path = os.path.join(RULE_DIR, f"{ip_rule_name}.srs")

        with open(ip_json_path, "w", encoding="utf-8") as f:
            json.dump(ip_json_data, f, ensure_ascii=False, indent=2)
        subprocess.run(["sing-box", "rule-set", "compile", ip_json_path, "-o", ip_srs_path], capture_output=True)
        print(f"  -> Generated IP rule: {ip_rule_name}.json & {ip_rule_name}.srs")


def scan_and_split():
    if not os.path.exists(RULE_DIR):
        print(f"[Error] Directory '{RULE_DIR}' does not exist.")
        sys.exit(1)

    print(f"[Scan] Scanning '{RULE_DIR}' for mixed domain & IPcidr rules...")
    for root, _, files in os.walk(RULE_DIR):
        for file in files:
            if file.endswith(".json"):
                file_path = os.path.join(root, file)
                process_and_split_json_file(file_path)

    print("[Scan Finished] Splitting complete.")


if __name__ == "__main__":
    scan_and_split()
