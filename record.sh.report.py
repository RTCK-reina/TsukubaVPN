#!/usr/bin/env python3
# 記録した生データから、人が読める判定つきレポートを作る。
import sys, os, re, glob

d = sys.argv[1]
def read(p, default=""):
    try:
        return open(p, encoding="utf-8", errors="replace").read()
    except Exception:
        return default

raw = [l.rstrip("\n").split("\t") for l in read(os.path.join(d, "raw.tsv")).splitlines()]
hdr, rows = (raw[0], raw[1:]) if raw else ([], [])
def col(r, name):
    try: return r[hdr.index(name)]
    except Exception: return ""

before, after = read(os.path.join(d, "before.txt")), read(os.path.join(d, "after.txt"))
events = read(os.path.join(d, "events.log"))

def val(text, key):
    m = re.search(r"^%s:\s*(.*)$" % re.escape(key), text, re.M)
    return m.group(1).strip() if m else ""

out = []
out.append("# つくばVPN 接続テスト記録\n")
out.append(f"- 記録フォルダ: `{d}`")
out.append(f"- サンプル数: {len(rows)}（3秒間隔）")
if rows:
    out.append(f"- 期間: {col(rows[0],'time')} 〜 {col(rows[-1],'time')}")
out.append("")

# ---------- 判定 ----------
utuns = [set(filter(None, col(r, "utun").split(","))) for r in rows]
base_utun = utuns[0] if utuns else set()
new_utun = sorted({u for s in utuns for u in (s - base_utun)})
routes = [col(r, "default_route") for r in rows if col(r, "default_route")]
route_changed = len(set(routes)) > 1
ips = [col(r, "public_ip") for r in rows if col(r, "public_ip") not in ("", "-")]
ip_changed = len(set(ips)) > 1
dnss = [col(r, "dns") for r in rows if col(r, "dns")]
dns_changed = len(set(dnss)) > 1
ovpn_seen = any(col(r, "openvpn_pid") for r in rows)
results = [col(r, "result") for r in rows if col(r, "result") not in ("", "-")]
ok_result = [x for x in results if x.startswith("OK")]
dnsstat = [col(r, "dns_status") for r in rows if col(r, "dns_status") not in ("", "-")]
dns_failed = [x for x in dnsstat if "failed" in x]
resolve = [col(r, "dns_ok") for r in rows if col(r, "dns_ok") in ("ok", "ng")]
resolve_ng = resolve.count("ng")
end_clean = (utuns[-1] == base_utun) if utuns else True
end_no_ovpn = (not col(rows[-1], "openvpn_pid")) if rows else True
end_route_ok = (routes[-1] == routes[0]) if routes else True
end_dns_ok = (dnss[-1] == dnss[0]) if dnss else True

def mark(b): return "✅" if b else "❌"
out.append("## 判定\n")
out.append(f"- {mark(ovpn_seen)} openvpn が root で起動した")
out.append(f"- {mark(bool(new_utun))} 仮想インターフェースが作られた: {', '.join(new_utun) if new_utun else '作られていない'}")
out.append(f"- {mark(bool(ok_result))} run.sh が接続成功を記録した: {ok_result[0] if ok_result else (results[-1] if results else '記録なし')}")
out.append(f"- {mark(route_changed)} デフォルト経路がトンネル側へ切り替わった")
out.append(f"- {mark(ip_changed)} グローバルIPが変わった: {' → '.join(dict.fromkeys(ips)) if ips else '取得できず'}")
out.append(f"- {mark(dns_changed)} DNSが切り替わった")
out.append(f"- {mark(not dns_failed)} DNS切替/復元にエラーなし" + (f"（{dns_failed[-1]}）" if dns_failed else ""))
out.append(f"- {mark(resolve_ng == 0)} 名前解決が常に通った（NG {resolve_ng} 回 / 計 {len(resolve)} 回）")
out.append("")
out.append("### 後片付け")
out.append(f"- {mark(end_clean)} utun が元の本数に戻った")
out.append(f"- {mark(end_no_ovpn)} openvpn が残っていない")
out.append(f"- {mark(end_route_ok)} デフォルト経路が元に戻った")
out.append(f"- {mark(end_dns_ok)} DNS が元に戻った")
out.append("")

out.append("## 開始時の状態\n```\n" + before.strip() + "\n```\n")
out.append("## 終了時の状態\n```\n" + after.strip() + "\n```\n")
out.append("## 状態変化の時系列\n```\n" + (events.strip() or "（変化なし）") + "\n```\n")

# ---------- openvpn ログの要点 ----------
out.append("## openvpn ログの要点\n")
pat = re.compile(r"VERIFY|EKU|Control Channel|PUSH: Received|Initialization Sequence|Exiting|error|ERROR|failed|Failed|AUTH|SIGTERM|SIGUSR1|utun|route|Socket bind|command failed")
for f in sorted(glob.glob(os.path.join(d, "openvpn", "*.log"))):
    body = read(f)
    hits = [l for l in body.splitlines() if pat.search(l)]
    out.append(f"### {os.path.basename(f)}（{len(body.splitlines())}行中 {len(hits)}行を抽出）")
    out.append("```\n" + "\n".join(hits[:80]) + "\n```\n")
for name in ["result.txt", "dns-status.txt", "openvpn.log"]:
    p = os.path.join(d, "openvpn", name)
    if os.path.exists(p):
        out.append(f"- `{name}`: `{read(p).strip()}`")
out.append("")
out.append("## 生データ\n- `raw.tsv` に全サンプルがタブ区切りで入っています。")
print("\n".join(out))
