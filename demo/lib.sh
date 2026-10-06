#!/usr/bin/env bash
# demo/lib.sh — uc demo scriptinin ortak kismi. Dogrudan calistirilmaz.
#
# Her demo ayni dort adimli hikayeyi anlatir:
#
#   1. saglikli trafik akar          eBPF: ESTABLISHED
#   2. bir politika bozulur          gercek hayatta sik yapilan bir hata
#   3. eBPF kesintiyi gorur          eBPF: DROPPED -- Kubernetes ise hicbir sey soylemez
#   4. politika geri yuklenir        eBPF: ESTABLISHED
#
# Loglar tek terminalde, canli akar. Pod IP'leri okunabilirlik icin pod
# adlarina cevrilir. Script nasil biterse bitsin (Ctrl-C dahil) politika
# geri yuklenir ve eBPF programi cekirdekten sokulur.
set -uo pipefail

NS=agentic-sre
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIN=$ROOT/bin/flowmon
MAN=$ROOT/manifests

HEALTHY_SECS=${HEALTHY_SECS:-10}   # bozmadan once / geri aldiktan sonra izleme suresi
BROKEN_SECS=${BROKEN_SECS:-25}     # kesik akisin izlenme suresi

B=$'\e[1m'; D=$'\e[2m'; R=$'\e[31m'; N=$'\e[0m'

say()  { printf '\n%s==> %s%s\n' "$B" "$*" "$N"; }
note() { printf '%s    %s%s\n' "$D" "$*" "$N"; }
die()  { printf '%sHATA: %s%s\n' "$R" "$*" "$N" >&2; exit 1; }

WATCHING=0
cleanup() {
	[[ $WATCHING -eq 1 ]] && sudo pkill -INT -x flowmon 2>/dev/null
	kubectl apply -f "$MAN/20-netpol-baseline.yaml" >/dev/null 2>&1
	wait 2>/dev/null
}

preflight() {
	[[ -x $BIN ]] || die "$BIN yok - once 'make build'"
	# Parolasiz sudo varsa sormadan gecer, yoksa bir kez parola ister.
	sudo -n true 2>/dev/null || sudo -v || die "sudo gerekiyor (eBPF programini cekirdege yuklemek icin)"
	kubectl get ns "$NS" >/dev/null 2>&1 || die "ortam yok - once 'make bootstrap'"
	# DNS ya da pod agi calismiyorsa uygulama connect() hic cagiramaz ve sensor
	# hicbir sey gormez -- ekran bos kalir. Demo baslamadan bunu dogruluyoruz.
	kubectl exec -n "$NS" api -- wget -T 3 -qO /dev/null \
		"http://store.$NS.svc.cluster.local:19090/" 2>/dev/null ||
		die "kume ici ag/DNS calismiyor (worker1 acik mi? 'kubectl get pods -n calico-system')"
}

# start_watch <port> — eBPF sensorunu baslatir, olaylari renkli ve pod adlariyla
# canli basar. Arka planda calisir; cleanup() durdurur.
start_watch() {
	local names
	names=$(kubectl get pods -n "$NS" -o json |
		jq -c '[.items[] | {(.status.podIP): .metadata.name}] | add')
	sudo "$BIN" -dport "$1" 2>/dev/null | jq -r --unbuffered --argjson m "$names" '
		(if .class == "established" then "\u001b[32m"
		 elif .class == "dropped"   then "\u001b[31m"
		 else "\u001b[33m" end) as $c
		| ((.class | ascii_upcase) + "           ")[0:11] as $k
		| "    \(.time[11:19])  \($c)\($k)\u001b[0m  \($m[.src] // .src) -> \($m[.dst] // .dst):\(.dport)   retrans=\(.retrans)   \(.duration_ms) ms"' &
	WATCHING=1
	sleep 2
}

# run_scenario <manifest> <bozulan-politika> <port> <akis> <hatanin-tarifi>
run_scenario() {
	local file=$1 pol=$2 port=$3 flow=$4 what=$5 since ev
	trap cleanup EXIT INT TERM

	say "Hazirlik: dogru politikalar yukleniyor, ag kontrol ediliyor"
	kubectl apply -f "$MAN/20-netpol-baseline.yaml" >/dev/null
	sleep 5
	preflight
	note "izlenen baglanti: $flow"

	say "1/4  Saglikli trafik -- eBPF cekirdekten canli izliyor"
	start_watch "$port"
	sleep "$HEALTHY_SECS"

	say "2/4  Ariza: '$pol' politikasi bozuluyor"
	note "$what"
	since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	kubectl apply -f "$MAN/$file" >/dev/null
	sleep "$BROKEN_SECS"

	say "3/4  Ayni anda Kubernetes ne diyor?"
	kubectl get pods -n "$NS" --no-headers |
		awk '{printf "    %-9s %s  %-8s restarts=%s\n", $1, $2, $3, $4}'
	ev=$(kubectl get events -n "$NS" -o json | jq --arg t "$since" \
		'[.items[] | select(.type == "Warning" and ((.lastTimestamp // .eventTime // "") >= $t))] | length')
	note "pod'lar calisiyor; ariza boyunca uretilen uyari olayi: $ev"
	note "Kubernetes'in kesintiden haberi yok -- eBPF ise saniyesi saniyesine gordu"
	sleep 3

	say "4/4  Politika geri yukleniyor"
	kubectl apply -f "$MAN/20-netpol-baseline.yaml" >/dev/null
	sleep "$HEALTHY_SECS"

	sudo pkill -INT -x flowmon 2>/dev/null
	WATCHING=0
	wait 2>/dev/null
	say "Bitti."
}
