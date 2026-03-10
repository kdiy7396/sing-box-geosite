import pandas as pd
import re
import concurrent.futures
import os
import json
import requests
import yaml
import ipaddress
from io import StringIO

# 映射字典
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
    """判断是否为 IP 地址（处理带 CIDR 的情况）"""
    try:
        ip_part = address.split('/')[0]
        ipaddress.ip_address(ip_part)
        return True
    except ValueError:
        return False

def fetch_url(url):
    """通用的请求函数，带超时和 User-Agent"""
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
    try:
        response = requests.get(url, headers=headers, timeout=20)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None

def parse_source(link):
    """解析订阅源，支持 YAML, TXT, CSV 逻辑格式"""
    content = fetch_url(link)
    if not content:
        return None, []

    rows = []
    logic_rules = []

    # 1. 尝试作为 YAML 处理 (Clash Rule Provider 格式)
    if link.endswith('.yaml') or 'payload' in content:
        try:
            yaml_data = yaml.safe_load(content)
            items = yaml_data.get('payload', []) if isinstance(yaml_data, dict) else yaml_data
            if isinstance(items, list):
                for item in items:
                    item_str = str(item).strip("'\" ")
                    if ',' in item_str:
                        parts = item_str.split(',')
                        rows.append({'pattern': parts[0].strip(), 'address': parts[1].strip()})
                    else:
                        # 自动识别纯列表格式
                        pattern = 'IP-CIDR' if is_ipv4_or_ipv6(item_str) else ('DOMAIN-SUFFIX' if item_str.startswith(('.', '+')) else 'DOMAIN')
                        rows.append({'pattern': pattern, 'address': item_str.lstrip('.+')})
                return pd.DataFrame(rows), []
        except:
            pass

    # 2. 尝试作为 CSV/普通规则行处理
    csv_data = StringIO(content)
    try:
        df = pd.read_csv(csv_data, header=None, names=['pattern', 'address', 'other'], on_bad_lines='skip', engine='python')
        
        # 处理逻辑规则 (AND)
        and_rows = df[df['pattern'].str.contains('AND', na=False)]
        for _, row in and_rows.iterrows():
            rule = {"type": "logical", "mode": "and", "rules": []}
            components = re.findall(r'\((.*?)\)', str(row.values))
            for comp in components:
                for k, v in MAP_DICT.items():
                    if k in comp:
                        val = comp.split(',')[-1].strip("'\" ")
                        rule["rules"].append({v: val})
            if rule["rules"]:
                logic_rules.append(rule)

        # 过滤掉 AND 行并提取普通规则
        df_clean = df[~df['pattern'].str.contains('AND', na=False)].dropna(subset=['pattern', 'address'])
        for _, row in df_clean.iterrows():
            rows.append({'pattern': str(row['pattern']).strip(), 'address': str(row['address']).strip()})
    except Exception as e:
        print(f"CSV Parsing fallback for {link}: {e}")

    return pd.DataFrame(rows), logic_rules

def process_link(link, output_dir):
    """核心处理逻辑"""
    try:
        df, logic_rules = parse_source(link)
        if df is None or df.empty:
            return None

        # 统一映射 Pattern
        df['pattern'] = df['pattern'].str.upper().replace(MAP_DICT)
        df = df[df['pattern'].isin(MAP_DICT.values())].drop_duplicates()

        # 初始化 sing-box 规则集结构
        result_rules = {"version": 1, "rules": []}
        
        domain_set = set()
        suffix_set = set()
        other_grouped = {}

        # 处理不同类型的规则
        for pattern, group in df.groupby('pattern'):
            addresses = set(group['address'].str.strip("'\" ").str.lstrip('.+'))
            
            if pattern == 'domain_suffix':
                # 为确保“域名+子域名”都生效：
                # 1. 放入 domain_suffix 匹配所有子域名
                # 2. 放入 domain 匹配域名本身
                suffix_set.update(addresses)
                domain_set.update(addresses)
            elif pattern == 'domain':
                domain_set.update(addresses)
            else:
                other_grouped[pattern] = sorted(list(addresses))

        # 组装结果
        final_rule_list = []
        if domain_set:
            final_rule_list.append({"domain": sorted(list(domain_set))})
        if suffix_set:
            final_rule_list.append({"domain_suffix": sorted(list(suffix_set))})
        
        for p, addr_list in other_grouped.items():
            final_rule_list.append({p: addr_list})

        if logic_rules:
            final_rule_list.extend(logic_rules)

        result_rules["rules"] = final_rule_list

        # 保存 JSON
        file_base = os.path.basename(link).split('.')[0]
        json_path = os.path.join(output_dir, f"{file_base}.json")
        os.makedirs(output_dir, exist_ok=True)

        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(result_rules, f, ensure_ascii=False, indent=2)

        # 编译为 SRS
        srs_path = json_path.replace(".json", ".srs")
        status = os.system(f"sing-box rule-set compile --output \"{srs_path}\" \"{json_path}\"")
        
        if status == 0:
            print(f"Successfully generated: {srs_path}")
            return srs_path
        else:
            print(f"Failed to compile SRS for {file_base}")
            return json_path

    except Exception as e:
        print(f"Error processing {link}: {e}")
        return None

def generate_google_rules(output_dir):
    """Google 特殊规则生成"""
    url = "https://www.gstatic.com/ipranges/goog.json"
    print("Generating Google IP rules...")
    content = fetch_url(url)
    if not content: return None
    
    try:
        data = json.loads(content)
        ips = []
        for p in data.get("prefixes", []):
            cidr = p.get("ipv4Prefix") or p.get("ipv6Prefix")
            if cidr: ips.append(cidr)
        
        ruleset = {"version": 1, "rules": [{"ip_cidr": sorted(list(set(ips)))}]}
        json_path = os.path.join(output_dir, "google.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(ruleset, f, indent=2)
        
        srs_path = json_path.replace(".json", ".srs")
        os.system(f"sing-box rule-set compile --output \"{srs_path}\" \"{json_path}\"")
        return srs_path
    except:
        return None

if __name__ == "__main__":
    # 配置路径
    LINKS_FILE = "../links.txt"  # 请确保该文件存在
    OUTPUT_DIR = "./rules"
    
    if not os.path.exists(LINKS_FILE):
        # 兼容当前目录
        LINKS_FILE = "links.txt"
        if not os.path.exists(LINKS_FILE):
            print("Error: links.txt not found.")
            exit(1)

    with open(LINKS_FILE, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"Task started: {len(urls)} sources to process.")

    # 并发处理
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(process_link, url, OUTPUT_DIR) for url in urls]
        concurrent.futures.wait(futures)

    # 额外处理 Google 规则
    generate_google_rules(OUTPUT_DIR)
    
    print("\nAll tasks completed.")
