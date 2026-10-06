#!/usr/bin/env bash
# Statik politika analizi (Proje Ozeti §3.3, Faz 0'in ikinci yarisi).
#
# eBPF ne OLDUGUNU olcer; np-guard neyin OLMASI GEREKTIGINI hesaplar.
# Bu script ikisini yan yana koyar.
#
#   ./scripts/analyze.sh            tum senaryolar icin matris
#   ./scripts/analyze.sh diff       baseline'a gore anlamsal fark (metin)
#   ./scripts/analyze.sh json       makine okunur cikti + hesaplanan fark
#   ./scripts/analyze.sh compare    np-guard'in HESAPLADIGI ile eBPF'in OLCTUGUNU
#                                   hucre hucre karsilastirir (out/ olcumleri gerekir:
#                                   once 'make bootstrap && make all-scenarios')
#
# NEDEN AYRI BIR json MODU VAR
#
# Dogrulama kapisi bu ciktiyi PROGRAMLA okuyacak, gozle degil. Ama araclarin
# cikti bicimleri simetrik degil:
#
#   netpolicy list   txt, JSON, dot, csv, md, svg
#   netpolicy diff   txt,       dot, csv, md, svg      <-- JSON YOK
#
# Yani kapi "diff" komutunun ciktisini ayristiramaz. Bunun yerine her iki
# dizin icin `list -o json` alip farki KENDISI hesaplamali. Asagidaki json
# modu tam olarak bunu yapiyor ve kapinin prototipi sayilir.
#
# Gereksinim:  netpolicy PATH'te (scripts/setup-deps.sh /usr/local/bin'e kurar)
set -uo pipefail

NS=agentic-sre
ROOT=$(cd "$(dirname "$0")/.." && pwd)
MAN="$ROOT/manifests"
WORK=$(mktemp -d)
NP=${NP:-$(command -v netpolicy || echo "$(go env GOPATH)/bin/netpolicy")}

# Gozlenen akislar: kaynak hedef port. eBPF'in olctugu ucluler.
FLOWS=("frontend api 18080" "frontend api 18081" "api store 19090")

# senaryo -> break dosyasi | uzerine yazdigi politika
SCENARIOS=(
	"selector|31-break-selector.yaml|allow-store-data"
	"port|32-break-port.yaml|allow-api-admin"
	"and-or|33-break-and-or.yaml|allow-api-app"
)

trap 'rm -rf "$WORK"' EXIT
[[ -x $NP ]] || { echo "HATA: netpolicy bulunamadi ($NP)"; exit 1; }

# compose <hedef-dizin> [uzerine-yazilan-politika] [break-dosyasi]
#
# Ariza manifestleri baseline'daki bir politikanin UZERINE YAZILIR (ayni ad).
# Statik analiz bir DIZIN okudugu icin ayni adli iki politika birakamayiz --
# once eskisini cikarip yenisini koymak zorundayiz.
compose() {
	local dir=$1 drop=${2:-} brk=${3:-}
	mkdir -p "$dir"
	cp "$MAN/00-namespace.yaml" "$MAN/10-workloads.yaml" "$dir/"
	if [[ -z $drop ]]; then
		cp "$MAN/20-netpol-baseline.yaml" "$dir/policies.yaml"
	else
		python3 - "$MAN/20-netpol-baseline.yaml" "$drop" > "$dir/policies.yaml" <<'PY'
import re, sys
docs = open(sys.argv[1]).read().split('\n---\n')
keep = [d for d in docs
        if (re.search(r'^  name: (\S+)', d, re.M) or [None, ''])[1] != sys.argv[2]]
print('\n---\n'.join(keep))
PY
		cp "$MAN/$brk" "$dir/break.yaml"
	fi
}

compose "$WORK/baseline"
for row in "${SCENARIOS[@]}"; do
	IFS='|' read -r name file pol <<<"$row"
	compose "$WORK/$name" "$pol" "$file"
done

if [[ ${1:-} == compare ]]; then
	# Iki bagimsiz yontem ayni soruyu cevapliyor: "bu baglanti bu durumda acik mi?"
	#   np-guard  YAML okuyarak HESAPLAR (trafik yok)
	#   eBPF      kumede gercekten kurup OLCER (out/observed-<durum>.json)
	# Ayni cevabi veriyorlarsa analizorun modeli ile kumenin gercek davranisi
	# ortusuyor demektir -- Proje Ozeti §3.4'un "en tehlikeli hata modu" dedigi
	# ayrisma yok.
	OUT="$ROOT/out"
	printf "%-25s" "BAGLANTI"
	for d in baseline selector port and-or; do printf " %-16s" "$d"; done
	echo; printf '%.0s-' {1..92}; echo
	total=0 match=0
	for f in "${FLOWS[@]}"; do
		set -- $f
		printf "%-8s -> %-5s:%-6s" "$1" "$2" "$3"
		for d in baseline selector port and-or; do
			np=$("$NP" evaluate --dirpath "$WORK/$d" \
				-n "$NS" -s "$1" --destination-namespace "$NS" -d "$2" -p "$3" 2>&1 | tail -1)
			[[ $np == *": true" ]] && np=acik || np=KAPALI
			# Olcum dosyasinda akisi PORTA gore buluyoruz: pod IP'leri her yeniden
			# baslatmada degisiyor, ama bu ortamda her port tek bir akisa ait.
			ebpf=$(python3 - "$OUT/observed-$d.json" "$3" <<'PY'
import json, sys
try:
    flows = json.load(open(sys.argv[1]))["flows"]
except FileNotFoundError:
    print("yok"); sys.exit()
f = [x for x in flows if x["dport"] == int(sys.argv[2])]
if not f:
    print("yok")
else:
    print("KAPALI" if f[0]["dropped"] > 0 else "acik")
PY
)
			total=$((total + 1))
			if [[ $ebpf == "$np" ]]; then
				match=$((match + 1)); mark="="
			else
				mark="X"
			fi
			printf " %-16s" "$np $mark $ebpf"
		done
		echo
	done
	echo
	echo "  her hucre:  np-guard (hesaplanan)  =/X  eBPF (olculen)"
	echo
	echo "  ORTUSEN: $match / $total"
	[[ $match -eq $total ]] || echo "  'yok' gorunuyorsa olcum eksik: make bootstrap && make all-scenarios"
	exit 0
fi

if [[ ${1:-} == json ]]; then
	for row in "${SCENARIOS[@]}"; do
		IFS='|' read -r name _ pol <<<"$row"
		echo "=== baseline -> $name   (bozulan: $pol) ==="
		python3 - "$NP" "$WORK/baseline" "$WORK/$name" <<'PY'
import json, subprocess, sys
np, d1, d2 = sys.argv[1:4]

def conns(d):
    """Bir dizindeki izin verilen baglantilari (kaynak,hedef) -> port seti
    olarak dondurur. Kume disi hedefler (0.0.0.0/0) atlaniyor: politika
    analizinde gurultu, gozlenen akis kumesinde karsiligi yok."""
    out = subprocess.run([np, "list", "--dirpath", d, "-o", "json"],
                         capture_output=True, text=True).stdout
    return {(e["src"], e["dst"]): e["conn"]
            for e in json.loads(out) if "0.0.0.0" not in e["dst"]}

a, b = conns(d1), conns(d2)
for k in sorted(set(a) | set(b)):
    if a.get(k) != b.get(k):
        print(f'  {k[0]} -> {k[1]}')
        print(f'      baseline: {a.get(k, "(yok)")}')
        print(f'      sonra   : {b.get(k, "(yok)")}')
PY
		echo
	done
	exit 0
fi

if [[ ${1:-} == diff ]]; then
	for row in "${SCENARIOS[@]}"; do
		IFS='|' read -r name _ pol <<<"$row"
		echo "=== baseline -> $name   (bozulan: $pol) ==="
		"$NP" diff --dir1 "$WORK/baseline" --dir2 "$WORK/$name" 2>&1 \
			| grep -v '0\.0\.0\.0' | sed 's/^/  /'
		echo
	done
	exit 0
fi

printf "%-25s %-10s %-10s %-10s %-10s\n" "GOZLENEN AKIS" "baseline" "selector" "port" "and-or"
printf '%.0s-' {1..68}; echo
for f in "${FLOWS[@]}"; do
	set -- $f
	row=$(printf "%-8s -> %-5s:%-6s" "$1" "$2" "$3")
	for d in baseline selector port and-or; do
		out=$("$NP" evaluate --dirpath "$WORK/$d" \
			-n "$NS" -s "$1" --destination-namespace "$NS" -d "$2" -p "$3" 2>&1 | tail -1)
		[[ $out == *": true" ]] && v="izinli" || v="ENGELLI"
		row="$row $(printf '%-10s' "$v")"
	done
	echo "$row"
done
echo
echo "Kosegen ENGELLI'ler eBPF'in ayni senaryoda 'dropped' olctugu akislarla"
echo "eslesmeli. Eslesmiyorsa analizorun modeli ile kumenin davranisi ayrilmis"
echo "demektir -- Proje Ozeti §3.4'teki en tehlikeli hata modu."
