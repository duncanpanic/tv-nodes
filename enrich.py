#!/usr/bin/env python3
"""Parse subs-check output -> grade protocols -> score -> pick Top N.

No per-node geo API calls: the country comes from the node name (subs-check
renames every tested node to "🇩🇪DE_122|5.0MB/s|0%|YT-US|NF-HU") and is mapped
to a built-in centroid for globe placement.

Scoring is speed-first: score = 0.70*speed + 0.30*purity(100-risk). The protocol
grade stays a hard filter (weak / no-TLS protocols never reach scoring).

Exit codes: 0 = nodes.json/top.yaml written, 1 = nothing usable -> old data
files are left untouched so the published site keeps working.
"""
import glob, json, math, os, re, sys, time, collections

OUT = "nodes.json"
TOP = "top.yaml"
TOPN = int(os.environ.get("TOPN", "20"))
# 同一国家最多取几个（20 个节点要更宽的取样，避免全是一个机房）
MAX_PER_CC = int(os.environ.get("MAX_PER_CC", "2"))

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


# ---------------------------------------------------------------- YAML loading
def _uncomment(s):
    out, q = [], None
    for i, ch in enumerate(s):
        if q:
            out.append(ch)
            if ch == q:
                q = None
        elif ch in "\"'":
            q = ch
            out.append(ch)
        elif ch == "#" and (i == 0 or s[i - 1] in " \t"):
            break
        else:
            out.append(ch)
    return "".join(out).rstrip()


_ESC = re.compile(r"\\U([0-9a-fA-F]{8})|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|\\[ntr\"\\\\]")


def _unescape(body):
    def rep(m):
        if m.group(1):
            return chr(int(m.group(1), 16))
        if m.group(2):
            return chr(int(m.group(2), 16))
        if m.group(3):
            return chr(int(m.group(3), 16))
        return {"\\n": "\n", "\\t": "\t", "\\r": "\r", '\\"': '"', "\\\\": "\\"}.get(m.group(0), m.group(0))
    return _ESC.sub(rep, body)


def _scalar(v):
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        body = v[1:-1]
        if v[0] == '"' and "\\" in body:
            body = _unescape(body)
        return body
    if v in ("true", "True", "TRUE"): return True
    if v in ("false", "False", "FALSE"): return False
    if v in ("", "null", "Null", "~"): return None
    if re.fullmatch(r"-?\d+", v): return int(v)
    if re.fullmatch(r"-?\d*\.\d+", v): return float(v)
    return v


class _Frame:
    __slots__ = ("indent", "obj", "owner", "key")

    def __init__(self, indent, obj, owner=None, key=None):
        self.indent, self.obj, self.owner, self.key = indent, obj, owner, key


def parse_clash(path):
    """Indentation-aware Clash YAML reader (used when pyyaml is unavailable).

    Handles block sequences of block mappings with scalar values plus nested
    maps / lists (reality-opts, ws-opts, alpn, ...) - i.e. the shape subs-check
    writes into output/all.yaml.
    """
    root = {}
    stack = [_Frame(-1, root)]
    for raw in open(path, encoding="utf-8", errors="replace"):
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        line = _uncomment(line)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        s = line.strip()
        while len(stack) > 1 and stack[-1].indent >= indent:
            stack.pop()
        fr = stack[-1]
        if s.startswith("- ") or s == "-":
            # a "key:" waiting for a sequence -> turn its placeholder dict into a list
            if isinstance(fr.obj, dict) and fr.owner is not None and fr.key is not None:
                lst = []
                fr.owner[fr.key] = lst
                fr.obj, fr.owner, fr.key = lst, None, None
            if not isinstance(fr.obj, list):
                continue
            item = {}
            fr.obj.append(item)
            stack.append(_Frame(indent, item))
            body = s[2:].strip() if s.startswith("- ") else ""
            if body:
                m = re.match(r"^([\w.\-]+):\s*(.*)$", body)
                if m:
                    k, v = m.group(1), m.group(2)
                    if v.strip() == "":
                        child = {}
                        item[k] = child
                        stack.append(_Frame(indent + 2, child, item, k))
                    else:
                        item[k] = _scalar(v)
            continue
        m = re.match(r"^([\w.\-]+):\s*(.*)$", s)
        if not m or not isinstance(fr.obj, dict):
            continue
        k, v = m.group(1), m.group(2)
        if v.strip() == "":
            child = {}
            fr.obj[k] = child
            stack.append(_Frame(indent, child, fr.obj, k))
        else:
            fr.obj[k] = _scalar(v)
    return root


def load_yaml(path):
    try:
        import yaml
    except ImportError:
        return None
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dump_yaml(obj, path):
    try:
        import yaml
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(obj, f, allow_unicode=True, sort_keys=False)
        return
    except ImportError:
        pass
    # JSON is a subset of YAML 1.2 -> a valid Clash subscription file
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------- scoring
NAME_CC = re.compile(r"(?:^|[^A-Z])([A-Z]{2})(?:_\d|[\s\u4e00-\u9fff]|\||$)")
SPEED = re.compile(r"\|\s*([0-9]+(?:\.[0-9]+)?)\s*MB/s", re.I)
RISK = re.compile(r"\|\s*([0-9]+(?:\.[0-9]+)?)\s*%")
UNLOCK = re.compile(r"\b(GPT|NF|YT|GM|D\+|CL|SP|TK)-?[A-Z]{0,2}")


def read_name(name):
    """-> (cc, speed MB/s, risk%, unlock tags) parsed from a subs-check name."""
    cc = ""
    m = NAME_CC.search(name)
    if m:
        cc = m.group(1)
    sp = SPEED.search(name)
    speed = float(sp.group(1)) if sp else 0.0
    rk = RISK.search(name)
    risk = float(rk.group(1)) if rk else 50.0
    unlocks = []
    for u in UNLOCK.findall(name):
        if u not in unlocks:
            unlocks.append(u)
    return cc, speed, risk, unlocks


def main():
    files = sorted(glob.glob("output/*.yaml") + glob.glob("output/*.yml"))
    if not files:
        print("ERROR: no output/*.yaml from subs-check", file=sys.stderr)
        return 1
    proxies = []
    for f in files:
        d = load_yaml(f)
        src = f"pyyaml {f}" if d is not None else f"fallback-parser {f}"
        if d is None:
            d = parse_clash(f)
        got = d.get("proxies") or []
        print(f"  {src}: {len(got)} proxies")
        proxies += got
    print(f"loaded {len(proxies)} proxies from {len(files)} file(s)")
    if not proxies:
        print("ERROR: subs-check output contained no proxies", file=sys.stderr)
        return 1

    scored, seen = [], set()
    for p in proxies:
        if not p.get("server") or not p.get("type"):
            continue
        letter, enc, label = grade(p)
        if letter == "F":
            continue
        key = (str(p.get("server")), str(p.get("port")), str(p.get("type")))
        if key in seen:
            continue
        seen.add(key)
        name = str(p.get("name") or "")
        cc, speed, risk, unlocks = read_name(name)
        pos = cc_centroid(cc)
        if not pos:
            continue
        scored.append(dict(name=name, type=p["type"], label=label, enc=enc,
                           cc=cc, city="", lat=pos[0], lon=pos[1],
                           speed=speed, risk=risk, unlocks=unlocks, raw=p))
    print(f"strict-encryption + geolocatable: {len(scored)}")

    timed = [s for s in scored if s["speed"] > 0]
    fast = [s for s in timed if s["speed"] >= 0.5]
    print(f"with a measured speed this round: {len(timed)} (>=0.5MB/s: {len(fast)})")
    pool = fast or timed or scored
    if not pool:
        print("ERROR: no usable node after grading", file=sys.stderr)
        return 1

    mx = max([s["speed"] for s in pool] + [0]) or 1
    for s in pool:
        P = 100 - s["risk"]
        S = 100 * math.log1p(s["speed"]) / math.log1p(mx) if mx > 0 else 0
        s["P"], s["S"] = round(P, 1), round(S, 1)
        # 速度优先（70%），纯净度/低风险次之（30%）
        s["score"] = round(0.70 * S + 0.30 * P, 1)
    pool.sort(key=lambda x: (-x["score"], -x["speed"]))

    # 选 Top N：先按「同国家 ≤2」挑，挑不满再逐级放宽到 3、4、不限
    top, picked = [], set()
    for cap in (MAX_PER_CC, MAX_PER_CC + 1, MAX_PER_CC + 2, 10**6):
        if len(top) >= TOPN:
            break
        cc_n = collections.Counter(s["cc"] for s in top)
        for s in pool:
            if len(top) >= TOPN:
                break
            if id(s) in picked or cc_n[s["cc"]] >= cap:
                continue
            cc_n[s["cc"]] += 1
            picked.add(id(s))
            top.append(s)
    top.sort(key=lambda x: (-x["score"], -x["speed"]))

    def pub(s):
        return {k: s.get(k) for k in
                ("name", "type", "label", "cc", "lat", "lon", "risk", "speed",
                 "enc", "P", "S", "score", "unlocks")}

    out = []
    for s in top:
        r = dict(s["raw"])
        r["name"] = "%s_%s|%sMB/s|risk%s" % (s["cc"], s["label"], s["speed"],
                                             int(s["risk"]) if float(s["risk"]).is_integer() else s["risk"])
        out.append(r)
    dump_yaml({"proxies": out}, TOP)
    print(f"wrote {TOP} ({len(out)} nodes)")

    items = [pub(s) for s in top]
    data = {"updated": int(time.time()), "source_count": len(proxies),
            "strict_count": len(scored), "topn": len(items),
            "top": items, "top10": items}   # top10 是旧字段别名，保持兼容
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
    print(f"wrote {OUT} top={len(top)} (max {MAX_PER_CC}/country)")
    for s in top:
        print(" ", s["cc"], s["label"], f"{s['speed']}MB/s",
              f"risk{s['risk']}%", f"score{s['score']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
