#!/usr/bin/env bash
# Sifirdan bir Ubuntu/Debian makinesini bu depoyu calistirabilir hale getirir.
#
# Kurdugu sey uc grup:
#   1) eBPF arac zinciri   clang, libbpf, bpftool -- bpf/*.c'yi derlemek icin
#   2) Go                  ikiliyi derlemek icin (go.mod 1.22+ istiyor)
#   3) yardimci araclar    python3, jq -- scriptler bunlari kullaniyor
#   4) netpol-analyzer     statik politika analizi (scripts/analyze.sh)
#
# KURMADIGI sey: Kubernetes kumesi ve CNI. Bu depo calisan bir kumeyi
# varsayiyor (Calico eBPF veri duzleminde test edildi). kubectl'in calisan
# bir kume gordugu asagida yalnizca DOGRULANIYOR, kurulmuyor.
set -euo pipefail

SUDO=""
[[ $EUID -ne 0 ]] && SUDO=sudo

echo "==> apt paketleri"
$SUDO apt-get update -qq
$SUDO apt-get install -y --no-install-recommends \
	clang llvm libbpf-dev libelf-dev zlib1g-dev \
	build-essential pkg-config golang-go \
	python3 jq curl

# bpftool cogu dagitimda linux-tools icinde; bulunmazsa zararsiz gec.
if ! command -v bpftool >/dev/null && [[ ! -x /usr/sbin/bpftool ]]; then
	echo "==> bpftool"
	$SUDO apt-get install -y --no-install-recommends \
		linux-tools-common "linux-tools-$(uname -r)" || \
		echo "UYARI: bpftool kurulamadi; vmlinux.h uretemezsiniz."
fi

# apt'taki Go cok eskiyse (go.mod 1.22 istiyor) resmi tarball'a dus.
GO_BIN=$(command -v go || echo /usr/local/go/bin/go)
if ! "$GO_BIN" version >/dev/null 2>&1 || \
   [[ $("$GO_BIN" env GOVERSION 2>/dev/null | sed 's/go1\.\([0-9]*\).*/\1/') -lt 22 ]]; then
	GO_VERSION=1.23.4
	case "$(uname -m)" in
		x86_64)  GO_ARCH=amd64 ;;
		aarch64) GO_ARCH=arm64 ;;
		*) echo "desteklenmeyen mimari: $(uname -m)"; exit 1 ;;
	esac
	echo "==> Go ${GO_VERSION} (${GO_ARCH})"
	tmp=$(mktemp -d)
	curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -o "$tmp/go.tgz"
	$SUDO rm -rf /usr/local/go
	$SUDO tar -C /usr/local -xzf "$tmp/go.tgz"
	rm -rf "$tmp"
	echo "   PATH'e ekleyin:  export PATH=\$PATH:/usr/local/go/bin"
fi

# netpol-analyzer (np-guard): statik politika analizi. Hazir ikili
# yayinlanmiyor, kaynaktan derlemek gerekiyor. Derlenen ikili /usr/local/bin'e
# kuruluyor: PATH'te her zaman var, yeniden baslatmada export gerekmiyor.
NP=/usr/local/bin/netpolicy
if [[ ! -x $NP ]]; then
	echo "==> netpol-analyzer"
	# Linker bellek yiyor: 4 GB'in altindaki makinelerde OOM ile olebiliyor.
	# Once sayfa onbellegini birakip daha siki GC ile deniyoruz.
	avail=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)
	if [[ ${avail:-0} -lt 1200 ]]; then
		echo "   (bellek dusuk: ${avail}MB -- onbellek birakiliyor)"
		$SUDO sync && $SUDO sh -c 'echo 3 > /proc/sys/vm/drop_caches' 2>/dev/null || true
	fi
	if GOGC=20 go install github.com/np-guard/netpol-analyzer/cmd/netpolicy@v1.4.4; then
		$SUDO install -m 0755 "$(go env GOPATH)/bin/netpolicy" "$NP"
	else
		echo "UYARI: netpolicy derlenemedi; scripts/analyze.sh calismaz."
	fi
fi

echo "==> dogrulama"
for t in clang llvm-strip; do
	printf '  %-12s ' "$t"
	command -v "$t" >/dev/null && echo OK || echo EKSIK
done
printf '  %-12s ' bpftool
(command -v bpftool >/dev/null || [[ -x /usr/sbin/bpftool ]]) && echo OK || echo EKSIK
printf '  %-12s ' go
(command -v go >/dev/null || [[ -x /usr/local/go/bin/go ]]) && echo OK || echo EKSIK
for t in python3 jq; do
	printf '  %-12s ' "$t"
	command -v "$t" >/dev/null && echo OK || echo EKSIK
done
printf '  %-12s ' netpolicy
[[ -x $NP ]] && echo OK || echo "EKSIK - analyze.sh calismaz"
printf '  %-12s ' BTF
[[ -r /sys/kernel/btf/vmlinux ]] && echo OK || echo "EKSIK - CO-RE calismaz"

# Asagidakiler kurulmuyor, yalnizca var olup olmadiklari bildiriliyor.
printf '  %-12s ' kubectl
command -v kubectl >/dev/null && echo OK || echo "EKSIK - manifests/ uygulanamaz"
printf '  %-12s ' "kume erisimi"
kubectl get nodes >/dev/null 2>&1 && echo OK || echo "ERISILEMIYOR - kubeconfig?"
printf '  %-12s ' "CNI"
kubectl get pods -A 2>/dev/null | grep -qi 'calico\|cilium' && echo OK || \
	echo "UYARI - NetworkPolicy uygulayan bir CNI gerekiyor"
