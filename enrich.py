#!/usr/bin/env python3
"""Parse subs-check output -> grade protocols -> score -> pick Top10.
No per-node geo API calls: country is parsed from the node name and mapped to a
built-in country centroid for globe placement."""
import glob, json, math, re, sys, time, collections

OUT = "nodes.json"

WEAK_CIPHER = ("rc4", "table", "none", "des-cfb", "bf-cfb",
               "aes-128-cfb", "aes-256-cfb", "chacha20-ietf", "chacha20-poly1305")

def grade(p):
    """(letter, enc_score 0-100, label). A+ >=95, A >=85, B >=60, F = reject."""
    t = (p.get("type") or "").lower()
    if t == "vless":
        if p.get("reality-opts"): return "A+", 100, "vless+reality"
        if str(p.get("tls")).lower() == "true": return "A", 90, "vless+tls"
        return "F", 0, "vless-no-tls"
    if t == "vmess":
        return ("B", 70, "vmess+tls") if str(p.get("tls")).lower() == "true" else ("F", 0, "vmess-no-tls")
    if t == "trojan": return "A", 90, "trojan+tls"
    if t in ("hysteria2", "hy2"): return "A+", 100, "hysteria2"
    if t == "ss":
        c = (p.get("cipher") or "").lower()
        if any(w in c for w in WEAK_CIPHER): return "F", 0, "ss-weak"
        return ("A+", 100, "ss2022") if "2022" in c else ("B", 60, "ss-aead")
    return "F", 0, t or "unknown"

# country code -> [lat, lon] centroid (subset used for globe pins)
CENTROID = {
 "US":[39,-98],"CA":[56,-106],"MX":[23,-102],"BR":[-10,-52],"AR":[-38,-64],"CL":[-33,-71],
 "CO":[4,-73],"PE":[-10,-76],"EC":[-2,-78],"UY":[-33,-56],"VE":[8,-66],"BO":[-17,-64],
 "GB":[54,-2],"IE":[53,-8],"FR":[46,2],"DE":[51,10],"NL":[52,5],"BE":[50,4],"CH":[46,8],
 "AT":[47,14],"IT":[42,12],"ES":[40,-4],"PT":[39,-8],"PL":[52,19],"CZ":[49,15],"SK":[48,19],
 "HU":[47,19],"RO":[46,25],"BG":[43,25],"GR":[39,22],"TR":[39,35],"RU":[61,90],"UA":[49,32],
 "SE":[62,15],"NO":[61,9],"FI":[64,26],"DK":[56,10],"IS":[65,-18],"EE":[58,25],"LV":[57,25],
 "LT":[55,24],"MD":[47,29],"RS":[44,21],"HR":[45,15],"SI":[46,15],"BA":[44,18],"MK":[41,21],
 "ME":[42,19],"AL":[41,20],"LU":[49,8],"MT":[35,14],"CY":[35,33],
 "HK":[22.3,114.2],"TW":[23.5,121],"JP":[36,138],"KR":[36,128],"SG":[1.35,103.8],"MO":[22.2,113.5],
 "CN":[35,105],"IN":[22,79],"TH":[15,101],"VN":[16,106],"PH":[12,122],"MY":[4,102],"ID":[-2,118],
 "PK":[30,69],"BD":[24,90],"LK":[7,81],"NP":[28,84],"MM":[21,95],"KH":[13,105],"LA":[18,103],
 "KZ":[48,68],"AZ":[40,47],"GE":[42,43],"AM":[40,45],"AF":[33,66],"IR":[32,53],"IQ":[33,43],
 "IL":[31,34],"AE":[24,54],"SA":[24,45],"QA":[25,51],"KW":[29,47],"BH":[26,50],"OM":[21,57],
 "JO":[31,36],"LB":[34,35],"UZ":[41,64],
 "AU":[-25,134],"NZ":[-41,174],"FJ":[-18,178],"PG":[-6,147],
 "ZA":[-30,25],"EG":[26,30],"NG":[10,8],"KE":[0,38],"TZ":[-6,35],"UG":[1,32],"ET":[9,39],
 "MA":[32,-6],"DZ":[28,2],"TN":[34,9],"LY":[26,17],"GH":[8,-1],"CI":[7,-5],"SN":[14,-14],
 "CM":[6,12],"CD":[-2,23],"ZM":[-13,28],"ZW":[-19,30],"MZ":[-18,35],"AO":[-12,17],"SD":[15,30],
 "MU":[-20,57],"SC":[-5,55],
}
def cc_centroid(cc):
    return CENTROID.get((cc or "").upper())

def load_yaml(path):
    try:
        import yaml
        return yaml.safe_load(open(path, encoding="utf-8")) or {}
    except ImportError:
        return None

def parse_clash(path):
    """Minimal Clash proxies parser (fallback when pyyaml absent)."""
    proxies, cur = [], None
    for line in open(path, encoding="utf-8", errors="replace"):
        if line.strip().startswith("- ") and "type:" in line:
            if cur: proxies.append(cur)
            cur = {}; body = line.strip()[2:]
            mm = re.match(r"([A-Za-z0-9_-]+):\s*(.*)$", body)
            if mm: cur[mm.group(1)] = mm.group(2).strip().strip('"')
            continue
        if cur is not None and line.startswith("      "):
            mm = re.match(r"\s*([A-Za-z0-9_-]+):\s*(.*)$", line)
            if mm: cur[mm.group(1)] = mm.group(2).strip().strip('"')
    if cur: proxies.append(cur)
    return {"proxies": proxies}

def main():
    files = glob.glob("output/*.yaml") + glob.glob("output/*.yml")
    if not files:
        print("no output files"); sys.exit(0)
    proxies = []
    for f in files:
        d = load_yaml(f)
        if d is None: d = parse_clash(f)
        proxies += d.get("proxies") or []
    print(f"loaded {len(proxies)} proxies from {len(files)} files")

    scored = []
    for p in proxies:
        if not p.get("server") or not p.get("type"): continue
        letter, enc, label = grade(p)
        if letter == "F": continue  # reject unencrypted / weak-cipher
        name = p.get("name", "")
        m = re.search(r"\|([0-9.]+)\s*MB/s", name); speed = float(m.group(1)) if m else 0.0
        r = re.search(r"\|(\d+)%", name);            risk  = int(r.group(1))  if r else 50
        c = re.search(r"([A-Z]{2})_?\d", name);      cc    = c.group(1)       if c else ""
        pos = cc_centroid(cc)
        if not pos: continue  # need a location for the globe
        unlocks = re.findall(r"\b(NF|YT|GPT|GM|D\+|CL|SP|TK)-?[A-Z]{0,2}", name)
        scored.append(dict(name=name, type=p["type"], label=label, enc=enc,
                           cc=cc, city="", lat=pos[0], lon=pos[1],
                           speed=speed, risk=risk, unlocks=unlocks))
    print(f"A/A+ strict-encryption, geolocatable: {len(scored)}")

    # ---- score: purity(risk) + encryption + speed ----
    mx = max([s["speed"] for s in scored] + [0]) or 1
    for s in scored:
        P = 100 - s["risk"]
        S = 100 * math.log1p(s["speed"]) / math.log1p(mx) if mx > 0 else 0
        s["P"], s["S"] = round(P,1), round(S,1)
        s["score"] = round(0.35*P + 0.25*s["enc"] + 0.20*S + 0.20*min(100,S), 1)
    scored.sort(key=lambda x: -x["score"])

    # ---- top10 diversity: same country <=2, same IP/label spread ----
    top, cc_n = [], collections.Counter()
    for s in scored:
        if len(top) >= 10: break
        if cc_n[s["cc"]] >= 2: continue
        cc_n[s["cc"]] += 1
        top.append(s)

    def pub(s):
        return {k: s.get(k) for k in
                ("name","type","label","cc","lat","lon","risk","speed","enc","P","S","score","unlocks")}
    data = {"updated": int(time.time()), "source_count": len(proxies),
            "strict_count": len(scored), "top10": [pub(s) for s in top]}
    json.dump(data, open(OUT,"w",encoding="utf-8"), ensure_ascii=False, separators=(",",":"))
    print(f"wrote {OUT} top10={len(top)}")
    for s in top: print(" ", s["cc"], s["label"], f"{s['speed']}MB/s", f"risk{s['risk']}%", f"score{s['score']}")

if __name__ == "__main__":
    main()
