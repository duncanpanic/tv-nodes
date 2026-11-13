#!/usr/bin/env python3
"""Connectivity test: filter Clash proxies that actually respond.

Reads output/*.yaml, spins up a temporary mihomo (MIHOMO_BIN), dial-tests each
node via the REST API (generate_204), and rewrites the same files keeping only
alive nodes. Runs inside GitHub Actions; mihomo binary is downloaded by the
workflow and passed via MIHOMO_BIN.
"""
import glob, json, os, re, subprocess, sys, tempfile, time
import urllib.request, urllib.parse
from concurrent.futures import ThreadPoolExecutor

MIXED_PORT = 17890
CTRL_PORT = 19090
TEST_URL = "http://cp.cloudflare.com/generate_204"
CTRL_TIMEOUT = 12
DIAL_TIMEOUT = 4000
MAX_WAIT_READY = 20
RETRY_READY = 10


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
            if cur:
                proxies.append(cur)
            cur = {}
            body = line.strip()[2:]
            mm = re.match(r"([A-Za-z0-9_-]+):\s*(.*)$", body)
            if mm:
                cur[mm.group(1)] = mm.group(2).strip().strip('"')
            continue
        if cur is not None and line.startswith("      "):
            mm = re.match(r"\s*([A-Za-z0-9_-]+):\s*(.*)$", line)
            if mm:
                cur[mm.group(1)] = mm.group(2).strip().strip('"')
    if cur:
        proxies.append(cur)
    return {"proxies": proxies}


def dump_yaml(doc, path):
    try:
        import yaml
        with open(path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(doc, fh, allow_unicode=True, sort_keys=False)
        return True
    except ImportError:
        return False


def wait_ready(ctrl_port, max_wait=MAX_WAIT_READY, retry=RETRY_READY):
    url = f"http://127.0.0.1:{ctrl_port}/version"
    for i in range(retry):
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{ctrl_port}/version", headers={"User-Agent": "ready-check"})
            with urllib.request.urlopen(req, timeout=5) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(max_wait / retry)
    return False


def test_one(name, ctrl_port=CTRL_PORT, dial_timeout=DIAL_TIMEOUT):
    url = (
        f"http://127.0.0.1:{ctrl_port}/proxies/"
        f"{urllib.parse.quote(name, safe='')}/delay"
        f"?timeout={dial_timeout}&url=http://cp.cloudflare.com/generate_204"
    )
    req = urllib.request.Request(url, headers={"User-Agent": "connectivity-test"})
    try:
        with urllib.request.urlopen(req, timeout=CTRL_TIMEOUT) as r:
            delay = json.load(r).get("delay")
            if delay and delay > 0:
                return (name, delay)
    except Exception:
        pass
    return None


def main():
    files = glob.glob("output/*.yaml") + glob.glob("output/*.yml")
    if not files:
        print("no output files")
        sys.exit(0)

    mihomo_bin = os.environ.get("MIHOMO_BIN")
    if not mihomo_bin or not os.path.exists(mihomo_bin):
        print(f"MIHOMO_BIN missing: {mihomo_bin!r}")
        sys.exit(1)

    proxies = []
    for f in files:
        d = load_yaml(f)
        if d is None:
            d = parse_clash(f)
        proxies += d.get("proxies") or []
    print(f"loaded {len(proxies)} proxies from {len(files)} files")

    if not proxies:
        print("no proxies to test")
        sys.exit(0)

    cfg = {
        "mixed-port": 17890,
        "external-controller": "127.0.0.1:19090",
        "log-level": "warning",
        "proxies": proxies,
        "proxy-groups": [{"name": "SEL", "type": "select", "proxies": [p["name"] for p in proxies]}],
        "rules": ["MATCH,SEL"],
    }

    with tempfile.TemporaryDirectory() as td:
        cfg_path = os.path.join(td, "cfg.yaml")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False)

        proc = subprocess.Popen(
            [mihomo_bin, "-d", td, "-f", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # wait for controller ready
        if not wait_ready(19090):
            print("mihomo controller not ready")
            proc.terminate()
            proc.wait(timeout=8)
            sys.exit(1)
        time.sleep(2)  # extra grace

        try:
            names = [p["name"] for p in proxies]
            with ThreadPoolExecutor(max_workers=50) as ex:
                results = list(ex.map(test_one, names))
            alive = [r for r in results if r]
            print(f"alive {len(alive)}/{len(proxies)}")
            alive_names = {r[0] for r in alive}

            # rewrite each output file keeping only alive nodes
            kept = 0
            for f in files:
                d = load_yaml(f)
                if d is None:
                    d = parse_clash(f)
                if d and d.get("proxies"):
                    d["proxies"] = [p for p in d["proxies"] if p["name"] in alive_names]
                    kept += len(d["proxies"])
                    if not dump_yaml(d, f):
                        print(f"WARN: cannot rewrite {f} (pyyaml missing)")
            print(f"filtered: {len(proxies)} -> {kept}")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    main()

