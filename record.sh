#!/bin/bash
# つくばVPN 接続テストの記録ツール（ブラックボックス）
#
# Claude を落としている間に何が起きたかを、あとから完全に追えるようにする。
# Terminal から独立して動くので、Claude・Cowork を終了しても記録は続く。
#
#   ./record.sh start    記録開始
#   ./record.sh stop     記録停止してレポート生成
#   ./record.sh status   いま記録中かどうか
#
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
LOGROOT="$ROOT/logs"
WORK="$HOME/Library/TsukubaVPN"
PIDFILE="$LOGROOT/recorder.pid"
CURFILE="$LOGROOT/current"
NS=/usr/sbin/networksetup
mkdir -p "$LOGROOT"

now()  { date '+%Y-%m-%d %H:%M:%S'; }
stamp(){ date '+%Y%m%d-%H%M%S'; }

def_route() { /usr/sbin/netstat -rn -f inet 2>/dev/null | awk '$1=="default"{print $2" via "$NF; exit}'; }
utun_list() { /sbin/ifconfig -l 2>/dev/null | tr ' ' '\n' | grep '^utun' | tr '\n' ',' | sed 's/,$//'; }
utun_ips()  { for d in $(/sbin/ifconfig -l 2>/dev/null | tr ' ' '\n' | grep '^utun'); do
                ip=$(/sbin/ifconfig "$d" 2>/dev/null | awk '/inet /{print $2; exit}')
                [ -n "$ip" ] && printf '%s:%s ' "$d" "$ip"
              done; }
dns_state() { "$NS" -listallnetworkservices 2>/dev/null | tail -n +2 | sed 's/^\*//' | while IFS= read -r svc; do
                [ -z "$svc" ] && continue
                v=$("$NS" -getdnsservers "$svc" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
                case "$v" in *"aren't any"*) v="none";; esac
                printf '%s=%s;' "$svc" "$v"
              done; }
ovpn_pids() { pgrep -x openvpn 2>/dev/null | tr '\n' ',' | sed 's/,$//'; }
app_running(){ pgrep -f "MacOS/TsukubaVPN" >/dev/null 2>&1 && echo 1 || echo 0; }
readf()     { [ -f "$1" ] && tr '\n' ' ' < "$1" | sed 's/[[:space:]]*$//' || echo "-"; }
# DNS を使わずにグローバルIPを取る（DNSが壊れていても取れることが重要）
pub_ip()    { curl -s --max-time 8 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | awk -F= '/^ip=/{print $2} /^loc=/{printf "(%s)", $2}' | tr -d '\n'; }
# DNS が生きているかの判定（名前解決が必要なアクセス）
dns_ok()    { code=$(curl -s --max-time 6 -o /dev/null -w '%{http_code}' https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null); [ "$code" = "200" ] && echo ok || echo ng; }

case "${1:-}" in
status)
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "記録中です（PID $(cat "$PIDFILE")）: $(cat "$CURFILE" 2>/dev/null)"
  else
    echo "記録していません"
  fi
  exit 0 ;;

start)
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "すでに記録中です（PID $(cat "$PIDFILE")）"; exit 0
  fi
  DIR="$LOGROOT/session-$(stamp)"
  mkdir -p "$DIR/openvpn"
  echo "$DIR" > "$CURFILE"
  rm -f "$DIR/STOP"
  {
    echo "記録開始: $(now)"
    echo "macOS: $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
    echo "openvpn: $( { /opt/homebrew/sbin/openvpn --version 2>/dev/null || echo 未検出; } | head -1)"
    echo "アプリ: $(defaults read "/Applications/つくばVPN.app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo '-') / $(shasum -a 256 "/Applications/つくばVPN.app/Contents/MacOS/TsukubaVPN" 2>/dev/null | cut -c1-16)"
    echo "--- 開始時の状態 ---"
    echo "デフォルト経路: $(def_route)"
    echo "utun: $(utun_list)"
    echo "utun IP: $(utun_ips)"
    echo "DNS: $(dns_state)"
    echo "openvpn: $(ovpn_pids)"
    echo "グローバルIP: $(pub_ip)"
    echo "名前解決: $(dns_ok)"
    echo "--- scutil --dns（抜粋） ---"
    scutil --dns 2>/dev/null | grep -E "resolver #1|nameserver\[0\]|if_index" | head -8
  } > "$DIR/before.txt" 2>&1

  nohup /bin/bash "$0" __loop "$DIR" > "$DIR/loop.err" 2>&1 &
  echo $! > "$PIDFILE"
  sleep 1
  echo "記録を開始しました。"
  echo "  保存先: $DIR"
  echo "  この記録は Claude を終了しても続きます。"
  echo "  終わったら 記録停止.command をダブルクリックしてください。"
  exit 0 ;;

stop)
  DIR="$(cat "$CURFILE" 2>/dev/null)"
  if [ -z "${DIR:-}" ] || [ ! -d "$DIR" ]; then echo "記録セッションが見つかりません"; exit 1; fi
  touch "$DIR/STOP"
  for _ in $(seq 1 20); do
    [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null || break
    sleep 1
  done
  [ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null
  rm -f "$PIDFILE"
  {
    echo "記録終了: $(now)"
    echo "デフォルト経路: $(def_route)"
    echo "utun: $(utun_list)"
    echo "utun IP: $(utun_ips)"
    echo "DNS: $(dns_state)"
    echo "openvpn: $(ovpn_pids)"
    echo "グローバルIP: $(pub_ip)"
    echo "名前解決: $(dns_ok)"
  } > "$DIR/after.txt" 2>&1
  cp -f "$WORK"/*.log "$DIR/openvpn/" 2>/dev/null
  cp -f "$WORK"/result.txt "$WORK"/attempt.txt "$WORK"/dns-status.txt "$WORK"/skipped.txt "$WORK"/activelog.txt "$DIR/openvpn/" 2>/dev/null
  /usr/bin/python3 "$0.report.py" "$DIR" > "$DIR/report.md" 2>&1
  echo "記録を停止しました。"
  echo "  レポート: $DIR/report.md"
  open -R "$DIR/report.md" 2>/dev/null
  exit 0 ;;

__loop)
  DIR="$2"
  RAW="$DIR/raw.tsv"
  EV="$DIR/events.log"
  printf 'time\tdefault_route\tutun\tutun_ip\tdns\topenvpn_pid\tresult\tattempt\tdns_status\tapp\tpublic_ip\tdns_ok\n' > "$RAW"
  : > "$EV"
  prev=""
  i=0
  last_ip=""
  last_ipcheck=0
  # 止め忘れても永久に回らないよう3時間で自動終了する
  MAX=3600
  while [ ! -f "$DIR/STOP" ] && [ "$i" -lt "$MAX" ]; do
    i=$((i+1))
    R="$(def_route)"; U="$(utun_list)"; UI="$(utun_ips)"; D="$(dns_state)"
    P="$(ovpn_pids)"; RES="$(readf "$WORK/result.txt")"; ATT="$(readf "$WORK/attempt.txt")"
    DS="$(readf "$WORK/dns-status.txt")"; AP="$(app_running)"
    key="$R|$U|$D|$P|$RES|$ATT|$DS|$AP"
    IP="-"; DOK="-"
    # 状態が変わった直後と15秒おきにグローバルIPを取り直す
    if [ "$key" != "$prev" ] || [ $((i - last_ipcheck)) -ge 5 ]; then
      IP="$(pub_ip)"; DOK="$(dns_ok)"; last_ipcheck=$i
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$(now)" "$R" "$U" "$UI" "$D" "$P" "$RES" "$ATT" "$DS" "$AP" "$IP" "$DOK" >> "$RAW"
    if [ "$key" != "$prev" ]; then
      {
        echo "[$(now)] 状態変化"
        echo "    経路      : $R"
        echo "    utun      : ${U:-なし}   ${UI:-}"
        echo "    DNS       : $D"
        echo "    openvpn   : ${P:-なし}"
        echo "    result    : $RES / attempt: $ATT / dns-status: $DS"
        echo "    アプリ    : $AP"
        [ "$IP" != "-" ] && echo "    グローバルIP: $IP  名前解決: $DOK"
      } >> "$EV"
      [ -n "$P" ] && cp -f "$WORK"/try*.log "$DIR/openvpn/" 2>/dev/null
    fi
    if [ "$IP" != "-" ] && [ "$IP" != "$last_ip" ] && [ -n "$last_ip" ]; then
      echo "[$(now)] グローバルIPが変わりました: $last_ip → $IP （名前解決: $DOK）" >> "$EV"
    fi
    [ "$IP" != "-" ] && last_ip="$IP"
    prev="$key"
    sleep 3
  done
  cp -f "$WORK"/*.log "$DIR/openvpn/" 2>/dev/null
  exit 0 ;;

*)
  echo "使い方: $0 start | stop | status"; exit 1 ;;
esac
