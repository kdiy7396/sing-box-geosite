import json
import os
import subprocess
import sys
import time
import requests

# 定义目录
RULE_DIR = "rule"
TEMP_DIR = "temp"

# HTTP 请求头（防缓存）
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
    """带防缓存机制与重试的下载函数"""
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


def compile_rule(rule_name, json_data):
    """将 JSON 规则强行编译为 sing-box .srs 文件"""
    json_path = os.path.join(TEMP_DIR, f"{rule_name}.json")
    srs_path = os.path.join(RULE_DIR, f"{rule_name}.srs")

    # 写入临时 JSON
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, ensure_ascii=False, indent=2)

    # 调用 sing-box 编译规则集
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

        # 解析规则内容（支持 plain text 域名列表 & 现有 JSON 格式）
        try:
            if content.strip().startswith("{"):
                # 原生 json 格式
                json_data = json.loads(content)
            else:
                # 文本域名列表转 sing-box domain_suffix 格式
                domains = []
                for domain_line in content.splitlines():
                    domain_line = domain_line.strip()
                    if domain_line and not domain_line.startswith("#"):
                        domains.append(domain_line)

                json_data = {
                    "version": 1,
                    "rules": [
                        {
                            "domain_suffix": domains
                        }
                    ]
                }

            # 在规则元数据中插入构建时间戳，保证二进制文件改变，强制 git 提交更新
            json_data["_build_info"] = f"Updated at {timestamp}"

            compile_rule(rule_name, json_data)

        except Exception as e:
            print(f"[Error] Failed to parse rule {rule_name}: {e}")


if __name__ == "__main__":
    setup_dirs()
    process_links()
