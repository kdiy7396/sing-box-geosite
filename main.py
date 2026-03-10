import pandas as pd
import re
import concurrent.futures
import os
import json
import requests
import yaml
import ipaddress
import datetime
from io import StringIO

MAP_DICT = {
    'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix', 'host-suffix': 'domain_suffix',
    'DOMAIN': 'domain', 'HOST': 'domain', 'host': 'domain',
    'DOMAIN-KEYWORD': 'domain_keyword', 'HOST-KEYWORD': 'domain_keyword', 'host-keyword': 'domain_keyword',
    'IP-CIDR': 'ip_cidr', 'ip-cidr': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 'IP6-CIDR': 'ip_cidr',
    'SRC-IP-CIDR': 'source_ip_cidr', 'GEOIP': 'geoip',
    'DST-PORT': 'port', 'SRC-PORT': 'source_port',
    "URL-REGEX": "domain_regex", "DOMAIN-REGEX": "domain_regex"
}

def is_ipv4_or_ipv6(address):
    try:
        ip_part = address.split('/')[0]
        ipaddress.ip_address(ip_part)
        return True
    except ValueError:
        return False

def fetch_url(url):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    try:
        response = requests.get(url, headers=headers, timeout=20)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"Fetch Error: {url} -> {e}")
        return None

def parse_source(link):
    content = fetch_url(link)
    if not content: return None, []
    rows = []
    logic_rules = []
    
    # 1. 尝试 YAML 解析
    is_yaml_success = False
    try:
        if link.endswith('.yaml') or 'payload' in content:
            yaml_data = yaml.safe_load(content)
            items = yaml_data.get('payload', []) if isinstance(yaml_data, dict) else yaml_data
            if isinstance(items, list):
                for item in items:
                    item_str = str(item).strip("'\" ")
                    if ',' in item_str:
                        parts = item_str.split(',')
                        rows.append({'pattern': parts[0].strip(), 'address': parts[1].strip()})
                    else:
                        # 智能识别模式
                        pattern = 'IP-CIDR' if is_ipv4_or_ipv6(item_str) else ('DOMAIN-SUFFIX' if item_str.startswith(('.', '+')) else 'DOMAIN')
                        rows.append({'pattern': pattern, 'address': item_str.lstrip('.+')})
                is_yaml_success = True
    except Exception:
        pass

    if is_yaml_success:
        return pd.DataFrame(rows), []

    # 2. 尝试 CSV 解析 (如果 YAML 没成功或不是 YAML 格式)
    try:
        df = pd.read_csv(StringIO(content), header=None, names=['pattern', 'address', 'other'], on_bad_lines='skip', engine='python')
        
        # 处理逻辑规则 (AND)
        and_rows = df[df['pattern'].str.contains('AND', na=False, case=False)]
        for _, row in and_rows.iterrows():
            rule = {"type": "logical", "mode": "and", "rules": []}
            components = re.findall(r'\((.*?)\)', str(row.values))
            for comp in components:
                for k, v in MAP_DICT.items():
                    if k in comp:
                        val = comp.split(',')[-1].strip("'\" ")
                        rule["rules"].append({v: val})
            if rule["rules"]: logic_rules.append(rule)
        
        # 处理普通规则
        df_clean = df[~df['pattern'].str.contains('AND', na=False, case=False)].dropna(subset=['pattern', 'address'])
        for _, row in df_clean.iterrows():
            rows.append({'pattern': str(row['pattern']).strip(), 'address': str(row['address']).strip()})
    except Exception as e:
        print(f"CSV Parsing Error for {link}: {e}")
    
    return pd.DataFrame(rows), logic_rules

def generate_google_rules(output_dir):
    """补全缺失的 Google 规则生成函数"""
    url = "https://www.gstatic.com/ipranges/goog.json"
    print(f"Fetching Google IP ranges from {url}...")
    content = fetch_url(url)
    if not content: return
    try:
        data = json.loads(content)
        ip_list = []
        for p in data.get("prefixes", []):
            cidr = p.get("ipv4Prefix") or p.get("ipv6Prefix")
            if cidr: ip_list.append(cidr)
        
        ruleset = {"version": 3, "rules": [{"ip_cidr": sorted(list(set(ip_list)))}]}
        file_path = os.path.join(output_dir, "google.json")
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(ruleset, f, indent=2, sort_keys=True)
        
        srs_path = file_path.replace(".json", ".srs")
        os.system(f"sing-box rule-set compile --output \"{srs_path}\" \"{file_path}\"")
    except Exception as e:
        print(f"Error generating Google rules: {e}")

def process_link(link, output_dir):
    try:
        df, logic_rules = parse_source(link)
        if df is None or df.empty: return None

        df['pattern'] = df['pattern'].str.upper().replace(MAP_DICT)
        df = df[df['pattern'].isin(MAP_DICT.values())].drop_duplicates()

        domain_set = set()
        suffix_set = set()
        other_grouped = {}

        for pattern, group in df.groupby('pattern'):
            # 清理地址，移除前导点和加号
            addresses = set(group['address'].str.strip("'\" ").str.lstrip('.+'))
            if pattern == 'domain_suffix':
                suffix_set.update(addresses)
                domain_set.update(addresses) # 同时包含 domain 以防部分客户端只匹配子域名
            elif pattern == 'domain':
                domain_set.update(addresses)
            else:
                other_grouped[pattern] = sorted(list(addresses))

        final_rule_list = []
        if domain_set: final_rule_list.append({"domain": sorted(list(domain_set))})
        if suffix_set: final_rule_list.append({"domain_suffix": sorted(list(suffix_set))})
        for p in sorted(other_grouped.keys()): 
            final_rule_list.append({p: other_grouped[p]})
        if logic_rules: final_rule_list.extend(logic_rules)

        # 推荐使用 version 1
        result_rules = {"version": 3, "rules": final_rule_list}
        
        file_base = os.path.basename(link).split('.')[0]
        json_path = os.path.join(output_dir, f"{file_base}.json")
        os.makedirs(output_dir, exist_ok=True)

        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(result_rules, f, ensure_ascii=False, indent=2, sort_keys=True)

        srs_path = json_path.replace(".json", ".srs")
        status = os.system(f"sing-box rule-set compile --output \"{srs_path}\" \"{json_path}\"")
        if status != 0:
            print(f"Compile failed: {file_base}")
            return None
        return srs_path
    except Exception as e:
        print(f"Error: {link} -> {e}")
        return None

if __name__ == "__main__":
    current_script_path = os.path.abspath(__file__)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    LINKS_FILE = os.path.join(base_dir, "links.txt")
    OUTPUT_DIR = os.path.join(base_dir, "rule")
    
    if not os.path.exists(LINKS_FILE):
        print("links.txt not found.")
        exit(1)
    
    with open(LINKS_FILE, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    
    # 并发处理
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(process_link, u, OUTPUT_DIR) for u in urls]
        concurrent.futures.wait(futures)
    
    # 额外处理 Google 规则
    generate_google_rules(OUTPUT_DIR)

    # ==================== 强制触发 Git commit 的标记文件 ====================
    marker_path = os.path.join(OUTPUT_DIR, "last_build.txt")
    with open(marker_path, "w", encoding="utf-8") as f:
        f.write(f"Last build: {datetime.datetime.utcnow().isoformat()} UTC\n")
        f.write(f"Processed {len(urls)} links\n")
    
    print(f"\nAll tasks completed. Build marker: {marker_path}")
