#!/usr/bin/env bash
# agentic-sre gozlem ortami surucusu.
#
#   ./scripts/env.sh up                    is yuklerini kur -- POLITIKASIZ
#   ./scripts/env.sh baseline              bilinen-iyi politika kumesini uygula
#   ./scripts/env.sh capture 30 baseline   30 sn yakala -> out/*-baseline.*
#   ./scripts/env.sh break <senaryo>       ariza uygula: selector|port|and-or
#   ./scripts/env.sh restore               bilinen-iyi politikaya don
#   ./scripts/env.sh status                pod, politika ve mevcut durum
#   ./scripts/env.sh down                  ortami sil
#
# Referans dongu -- dogrulama kapisinin girdisini ureten sey budur:
#
#   up                      politikasiz kurulum
#   capture 60 no-policy    R kumesi: uygulama KISITSIZ neye baglaniyor
#   baseline                bilinen-iyi politikalari uygula
#   capture 30 baseline     A kumesi: politika neye izin veriyor
#   break <senaryo>         arizayi uygula
#   capture 45 <senaryo>    kesilen akisi olc
#   restore                 geri al
#
# Ilk adimin politikasiz olmasi kasitli. Politika ile politikasizlik, IZIN
# VERILEN trafik icin ayirt edilemez -- ikisinde de hicbir paket dusmez. Fark
# ancak uygulama reddedilen bir sey DENEDIGINDE ortaya cikar. Politikasiz
# olcum "uygulama kisitsiz neye baglanirdi" sorusunu cevaplar; PMR'nin
# paydasi olan R kumesi budur (Proje Ozeti §6).
set -uo pipefail

NS=agentic-sre
PORTS=18080,18081,19090

# senaryo -> (manifest, kesilen akis, bozulan politika)
declare -A SCENARIO=(
	[selector]="31-break-selector.yaml|api -> store:19090|allow-store-data"
	[port]="32-break-port.yaml|frontend -> api:18081|allow-api-admin"
	[and-or]="33-break-and-or.yaml|frontend -> api:18080|allow-api-app"
)
# Is yuklerinin sabitlenecegi dugum. flowmon dugum basina calistigi icin
# pod'lar bu scriptin kostugu makineye gelmeli; baska bir dugum isterseniz
# NODE=... ile gecin.
NODE=${NODE:-$(hostname)}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
MAN="$ROOT/manifests"
OUT="$ROOT/out"
BIN=${BIN:-$ROOT/bin/flowmon}

die() { echo "HATA: $*" >&2; exit 1; }

cmd_up() {
	echo "==> is yukleri (dugum: $NODE)"
	kubectl apply -f "$MAN/00-namespace.yaml"
	# nodeName manifeste sabit yazili; bu makinenin adiyla degistiriyoruz.
	sed "s/^\( *nodeName: \).*/\1$NODE/" "$MAN/10-workloads.yaml" | kubectl apply -f -
	for p in store api frontend; do
		kubectl wait -n "$NS" --for=condition=Ready "pod/$p" --timeout=180s \
			|| { kubectl describe -n "$NS" "pod/$p" | tail -25; die "$p hazir olmadi"; }
	done
	# Politika UYGULANMIYOR: ilk olcum kisitsiz alinmali.
	cmd_status
	echo
	echo "Ortam politikasiz ayakta. Sonraki adim -- R kumesini olc:"
	echo "  ./scripts/env.sh capture 60 no-policy"
	echo "  ./scripts/env.sh baseline"
}

cmd_baseline() {
	echo "==> bilinen-iyi politika kumesi"
	kubectl apply -f "$MAN/20-netpol-baseline.yaml"
	# Politikanin veri duzlemine inmesi bir kac saniye surer; hemen olcum
	# alinirsa politika oncesi trafik olcume karisir.
	sleep 5
	cmd_status
	echo
	echo "Sonraki adim -- A kumesini olc:"
	echo "  ./scripts/env.sh capture 30 baseline"
}

cmd_status() {
	echo
	# custom-columns: RESTARTS sutunu "1 (4m ago)" gibi bosluk icerdigi icin
	# --no-headers ciktisinda alan sayisi degisiyor ve pozisyonel awk kayiyor.
	kubectl get pods -n "$NS" --no-headers \
		-o custom-columns='N:.metadata.name,S:.status.phase,IP:.status.podIP' 2>/dev/null \
		| awk '{printf "  %-9s %-9s %s\n", $1, $2, $3}' || die "ortam yok - once 'up'"
	echo
	kubectl get netpol -n "$NS" --no-headers 2>/dev/null \
		| awk '{printf "  netpol %-22s %s\n", $1, $2}'
	echo
	# Her senaryonun kendine ozgu bir imzasi var; hangisinin yurulukte
	# oldugunu politikalarin icerigine bakarak buluyoruz.
	local n
	n=$(kubectl get netpol -n "$NS" --no-headers 2>/dev/null | wc -l)
	if [[ $n -eq 0 ]]; then
		echo "  durum: POLITIKASIZ  (kisitsiz -- R kumesi olcumu icin)"
		return
	fi
	local active=""
	[[ $(pol_json allow-store-data) == *'"app":"api-v2"'*      ]] && active=selector
	[[ $(pol_json allow-api-admin)  == *'"port":18082'*        ]] && active=port
	[[ $(pol_json allow-api-app)    == *'"namespaceSelector"'* ]] && active=and-or
	if [[ -n $active ]]; then
		IFS='|' read -r _ flow pol <<<"${SCENARIO[$active]}"
		echo "  durum: ARIZALI  senaryo=$active"
		echo "         kesik   $flow   (politika: $pol)"
	else
		echo "  durum: saglikli  (3 akis da acik)"
	fi
}

cmd_capture() {
	local secs=${1:?kullanim: capture <saniye> <etiket>} label=${2:?kullanim: capture <saniye> <etiket>}
	[[ -x $BIN ]] || die "$BIN yok - once 'make build'"
	mkdir -p "$OUT"
	local ev="$OUT/events-$label.jsonl" ob="$OUT/observed-$label.json"

	echo "==> $secs sn yakalaniyor (portlar $PORTS) -> $label"
	# timeout INT gonderiyor; flowmon bunu duzgun kapanma olarak isliyor ve
	# gozlenen kumeyi cikista yaziyor.
	sudo timeout -s INT "$secs" "$BIN" -dport "$PORTS" -observed "$ob" > "$ev"
	sudo chown "$(id -u):$(id -g)" "$ev" "$ob" 2>/dev/null

	echo
	echo "--- gozlenen akis kumesi ---"
	python3 - "$ob" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
if not d["flows"]:
    print("  (akis yok - is yukleri henuz baglanmamis olabilir)"); sys.exit()
for f in sorted(d["flows"], key=lambda x: x["dport"]):
    tot = f["established"] + f["dropped"] + f["refused"]
    mark = "OK   " if f["dropped"] == 0 and f["refused"] == 0 else "KESIK"
    print(f'  {mark} {f["src"]:>15} -> {f["dst"]}:{f["dport"]:<6} '
          f'est={f["established"]:<3} drop={f["dropped"]:<3} rst={f["refused"]:<3} '
          f'({tot} deneme)')
PY
	echo
	echo "  olay akisi     $ev"
	echo "  gozlenen kume  $ob"
}

# pol_json, bir politikanin spec'ini tek satir JSON olarak dondurur; imza
# aramasi bunun uzerinden yapiliyor.
pol_json() {
	kubectl get netpol -n "$NS" "$1" -o jsonpath='{.spec}' 2>/dev/null | tr -d ' '
}

cmd_break() {
	local name=${1:-}
	[[ -n ${SCENARIO[$name]:-} ]] || {
		echo "kullanim: break <senaryo>"
		for k in "${!SCENARIO[@]}"; do
			IFS='|' read -r _ flow pol <<<"${SCENARIO[$k]}"
			printf "  %-9s %-24s %s\n" "$k" "$flow" "$pol"
		done | sort
		exit 1
	}
	IFS='|' read -r file flow pol <<<"${SCENARIO[$name]}"
	echo "==> senaryo '$name' uygulaniyor -> $pol"
	kubectl apply -f "$MAN/$file"
	sleep 5
	cmd_status
	echo
	echo "Kubernetes hicbir sey bildirmedi. Kanit:"
	echo "  kubectl get events -n $NS --sort-by=.lastTimestamp | tail -5"
	echo "  ./scripts/env.sh capture 45 $name"
}

cmd_restore() {
	echo "==> bilinen-iyi politika kumesi geri yukleniyor"
	kubectl apply -f "$MAN/20-netpol-baseline.yaml"
	sleep 5
	cmd_status
}

cmd_down() {
	echo "==> ortam siliniyor"
	kubectl delete ns "$NS" --wait=false
}

case "${1:-}" in
	up)       cmd_up ;;
	baseline) cmd_baseline ;;
	status)  cmd_status ;;
	capture) shift; cmd_capture "$@" ;;
	break)   shift; cmd_break "$@" ;;
	restore) cmd_restore ;;
	down)    cmd_down ;;
	*) sed -n '2,15p' "$0" | sed 's/^# \?//'; exit 1 ;;
esac
