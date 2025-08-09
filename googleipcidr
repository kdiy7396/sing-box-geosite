import json
import requests

def fetch_google_ipranges(url="https://www.gstatic.com/ipranges/goog.json"):
    resp = requests.get(url)
    resp.raise_for_status()
    return resp.json()

def build_headless_rules(ipranges, version=3):
    rules = []
    for p in ipranges.get("prefixes", []):
        cidr = p.get("ipv4Prefix") or p.get("ipv6Prefix")
        if cidr:
            rule = {
                "ip_cidr": [cidr],
                # 可添加更多字段，如 "action": "route"，或其他条件字段
            }
            rules.append(rule)
    return {"version": version, "rules": rules}

def save_rules(rules_json, filename="goog_ruleset.json"):
    with open(filename, "w") as f:
        json.dump(rules_json, f, indent=2)

def main():
    data = fetch_google_ipranges()
    ruleset = build_headless_rules(data)
    save_rules(ruleset)
    print(f"Saved headless rule-set with {len(ruleset['rules'])} entries to goog_ruleset.json")

if __name__ == "__main__":
    main()
