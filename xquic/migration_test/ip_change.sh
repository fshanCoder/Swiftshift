#!/bin/bash
set -euo pipefail
# 依赖检查
require_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "[switcher] missing command: $1" >&2; exit 1; }; }
require_cmd jq

# 向外暴露自身 PID（便于外层脚本精确终止整个会话/进程组）
PIDFILE="${PIDFILE:-}"
if [ -n "$PIDFILE" ]; then
  echo $$ > "$PIDFILE"
fi
echo "[switcher] pid=$$" >&2
# 起始时间（纳秒），用于输出相对运行起点的毫秒时间
START_NS=$(date +%s%N)
elapsed_ms() {
  local now_ns
  now_ns=$(date +%s%N)
  echo $(( (now_ns - START_NS) / 1000000 ))
}
# 启用 ifb 模块
modprobe ifb
# 创建两个虚拟网络接口 ifb0 (入站) 和 ifb1 (出站)
if ! ip link show ifb0 >/dev/null 2>&1; then ip link add ifb0 type ifb; fi
if ! ip link show ifb1 >/dev/null 2>&1; then ip link add ifb1 type ifb; fi
ip link set dev ifb0 up || true
ip link set dev ifb1 up || true


# 选择 JSON 源：优先环境变量 JSON_FILE；否则默认脚本同目录下的 MontplierA.json
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
JSON_FILE="${JSON_FILE:-$SCRIPT_DIR/MontplierA.json}"
if [ ! -f "$JSON_FILE" ]; then
  echo "[switcher] JSON file not found: $JSON_FILE" >&2
  exit 1
fi
SEED="${1:-$(date +%s)}"
CHANGE_CNT=0

# 网络接口
INTERFACE="enp6s20"
if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
  echo "[switcher] interface not found: $INTERFACE" >&2
  exit 1
fi
#JITTER="5ms"
UP_LOSS_RATE=0%
DOWN_LOSS_RATE=0%

# IP 地址池 (示例IP地址, 可根据需要修改)
IP_POOL=("192.168.68.124" "192.168.68.125")
CURRENT_IP_INDEX=0

# 记录原始 IPv4 地址以便可选恢复
ORIG_IPV4=( $(ip -o -4 addr show dev "$INTERFACE" | awk '{print $4}') )
echo "[switcher] starting with INTERFACE=$INTERFACE JSON=$JSON_FILE" >&2

# helpers
has_ipv4() {
  local ip="$1"
  ip -o -4 addr show dev "$INTERFACE" | awk '{print $4}' | grep -q "^${ip}/"
}

ensure_ifb() {
  if ! ip link show ifb0 >/dev/null 2>&1; then ip link add ifb0 type ifb; ip link set dev ifb0 up || true; fi
  if ! ip link show ifb1 >/dev/null 2>&1; then ip link add ifb1 type ifb; ip link set dev ifb1 up || true; fi
  # ensure base qdiscs exist (idempotent)
  tc qdisc show dev ifb0 | grep -q "htb 1:" || {
    tc qdisc add dev ifb0 root handle 1: htb default 1 2>/dev/null || true
    tc class add dev ifb0 parent 1: classid 1:1 htb rate 100mbit 2>/dev/null || true
    tc qdisc add dev ifb0 parent 1:1 handle 10: netem delay 15ms loss 0% 2>/dev/null || true
  }
  tc qdisc show dev ifb1 | grep -q "htb 1:" || {
    tc qdisc add dev ifb1 root handle 1: htb default 1 2>/dev/null || true
    tc class add dev ifb1 parent 1: classid 1:1 htb rate 100mbit 2>/dev/null || true
    tc qdisc add dev ifb1 parent 1:1 handle 10: netem delay 15ms loss 0% 2>/dev/null || true
  }
}

# 清理函数
cleanup() {
  echo "[switcher] cleaning up tc/ifb on $INTERFACE" >&2
  tc qdisc del dev "$INTERFACE" root 2>/dev/null || true
  tc qdisc del dev "$INTERFACE" ingress 2>/dev/null || true
  tc qdisc del dev "$INTERFACE" clsact 2>/dev/null || true
  tc qdisc del dev ifb0 root 2>/dev/null || true
  tc qdisc del dev ifb1 root 2>/dev/null || true
  ip link del ifb0 2>/dev/null || true
  ip link del ifb1 2>/dev/null || true
  # 可选：恢复原始地址（如需）
  if [ ${#ORIG_IPV4[@]} -gt 0 ]; then
    ip addr flush dev "$INTERFACE" || true
    for a in "${ORIG_IPV4[@]}"; do ip addr add "$a" dev "$INTERFACE" || true; done
  fi
}

trap 'cleanup; exit 0' INT TERM QUIT EXIT

# 删除旧的tc配置（忽略不存在的错误以配合 set -e）
tc qdisc del dev $INTERFACE root 2> /dev/null || true
tc qdisc del dev $INTERFACE ingress 2> /dev/null || true
tc qdisc del dev $INTERFACE clsact 2> /dev/null || true
tc qdisc del dev ifb0 root 2> /dev/null || true
tc qdisc del dev ifb1 root 2> /dev/null || true

# 配置物理网卡 $INTERFACE：使用 clsact + matchall，统一重定向入/出站到 ifb
tc qdisc add dev $INTERFACE clsact
tc filter add dev $INTERFACE ingress matchall action mirred egress redirect dev ifb0
tc filter add dev $INTERFACE egress  matchall action mirred egress redirect dev ifb1

# 在 ifb0 上配置入站规则（HTB + NETEM）
tc qdisc add dev ifb0 root handle 1: htb default 1
tc class add dev ifb0 parent 1: classid 1:1 htb rate 100mbit
tc qdisc add dev ifb0 parent 1:1 handle 10: netem delay 15ms loss 0%

# 在 ifb1 上配置出站规则（HTB + NETEM）
tc qdisc add dev ifb1 root handle 1: htb default 1
tc class add dev ifb1 parent 1: classid 1:1 htb rate 100mbit
tc qdisc add dev ifb1 parent 1:1 handle 10: netem delay 15ms loss 0%


# 设置初始 IPv4 地址（注意子网掩码 /24）
sudo ip addr flush dev $INTERFACE
sudo ip addr add ${IP_POOL[$CURRENT_IP_INDEX]}/24 dev $INTERFACE
echo "初始配置完成：网卡=${INTERFACE} IP=${IP_POOL[$CURRENT_IP_INDEX]}"

# 主循环
while true; do
  CURRENT_SECOND=$(date +%S)

  if (( 10#$CURRENT_SECOND % 10 == 0 )); then
    CHANGE_CNT=$((CHANGE_CNT + 1))

    # 12个点的循环序号（1..12）
    TOTAL_ENTRIES=12
    INDEX=$(( (CHANGE_CNT - 1) % TOTAL_ENTRIES ))

    # 从 JSON 中取第 INDEX 个点
    ENTRY=$(jq ".[$INDEX]" "$JSON_FILE")

    DOWNLOAD=$(echo "$ENTRY" | jq '.download')
    PING=$(echo "$ENTRY" | jq '.mainPing')

    DOWNLOAD_MBPS=$(awk "BEGIN {printf \"%.2f\", $DOWNLOAD / 125000}")
    UPLOAD=$(echo "$ENTRY" | jq '.upload')
    UPLOAD_MBPS=$(awk "BEGIN {printf \"%.2f\", $UPLOAD / 125000}")
    BANDWIDTH1="${DOWNLOAD_MBPS}mbit"
    BANDWIDTH2="${UPLOAD_MBPS}mbit"

    HALF_DELAY=$(awk "BEGIN {printf \"%.2f\", $PING / 2}")
    DELAY="${HALF_DELAY}ms"
    DELAY="50ms"
    #BANDWIDTH1="20mbit"
    #BANDWIDTH2="20mbit"
    RAND_LOSS=$(awk -v seed="$SEED" "BEGIN {srand(seed); print 0.4 + (rand() * 0.6)}")
    LOSS_RATE=$(printf "%.2f" $RAND_LOSS)"%"
    LOSS_RATE="0%"
    SEED=$((SEED + 1))
    echo "handovers - 切换IP和重新配置tc"
# 主循环里切换时改成 IPv4 + /24
OLD_IP_INDEX=$CURRENT_IP_INDEX
CURRENT_IP_INDEX=$(( (CURRENT_IP_INDEX + 1) % ${#IP_POOL[@]} ))

# Make-before-break with idempotence checks to avoid RTNETLINK errors
NEW_IP=${IP_POOL[$CURRENT_IP_INDEX]}
OLD_IP=${IP_POOL[$OLD_IP_INDEX]}
if ! has_ipv4 "$NEW_IP"; then
  sudo ip addr add "$NEW_IP"/24 dev "$INTERFACE" 2>/dev/null || true
fi
sleep 0.2
if has_ipv4 "$OLD_IP"; then
  sudo ip addr del "$OLD_IP"/24 dev "$INTERFACE" 2>/dev/null || true
fi

    # 打印事件行（包含运行起点起的毫秒数），便于与 decode_ts.log 人工对照
    echo "[EVENT] IP_SWITCH t_ms=$(elapsed_ms) interface=$INTERFACE new_ip=${IP_POOL[$CURRENT_IP_INDEX]} index=$INDEX change_cnt=$CHANGE_CNT"
    # tc重新配置（确保ifb存在）
    ensure_ifb
    tc qdisc change dev ifb0 parent 1:1 handle 10: netem delay $DELAY loss $LOSS_RATE 2>/dev/null || true
    tc class  change dev ifb0 parent 1: classid 1:1 htb rate $BANDWIDTH1       2>/dev/null || true

    tc qdisc change dev ifb1 parent 1:1 handle 10: netem delay $DELAY loss $LOSS_RATE 2>/dev/null || true
    tc class  change dev ifb1 parent 1: classid 1:1 htb rate $BANDWIDTH2       2>/dev/null || true


    echo "$(date +%T) - 配置已更新：网卡=${INTERFACE} IP=${IP_POOL[$CURRENT_IP_INDEX]} 下行带宽=${BANDWIDTH1} 上行带宽=${BANDWIDTH2}  延迟=${DELAY}*2 上行链路丢包率=${UP_LOSS_RATE} 下行链路丢包率=${DOWN_LOSS_RATE} (索引: $INDEX)"

    sleep 1
  fi

  sleep 0.1
done