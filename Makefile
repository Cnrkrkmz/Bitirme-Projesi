# Faz 0/1 eBPF telemetri katmani.
#
# Akis:  vmlinux.h  ->  clang (BPF hedefi)  ->  .o  ->  go build (go:embed)

SHELL      := /bin/bash
CLANG      ?= clang
# llvm-strip Ubuntu'da surum ekiyle gelebilir (llvm-strip-21); bulunamazsa
# atlaniyor - sadece .o boyutunu kucultuyor, derlemeyi etkilemiyor.
STRIP      ?= $(shell command -v llvm-strip || ls /usr/bin/llvm-strip-* 2>/dev/null | sort -V | tail -1)
GO         ?= go

BPF_SRC    := bpf/flowmon.bpf.c
BPF_OBJ    := internal/probe/bpf/flowmon.bpf.o
VMLINUX    := bpf/vmlinux.h
BIN        := bin/flowmon

# BPF hedefinde CO-RE relocation icin mimari makrosu gerekiyor.
ARCH       := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/; s/ppc64le/powerpc/; s/mips.*/mips/')

# Son uc bastirma libbpf orneklerinde standart: vmlinux.h ve BPF yardimci
# imzalari bu uyarilari kacinilmaz olarak uretiyor.
CFLAGS := -g -O2 -Wall -Werror \
          -target bpf \
          -D__TARGET_ARCH_$(ARCH) \
          -I bpf \
          -Wno-unused-value \
          -Wno-pointer-sign \
          -Wno-compare-distinct-pointer-types

.PHONY: all
all: $(BIN)

# vmlinux.h calisan cekirdegin BTF'inden uretilir; farkli bir hedef cekirdek
# icin o makinede yeniden uretin.
$(VMLINUX):
	@command -v bpftool >/dev/null || { echo "bpftool yok: apt install linux-tools-common linux-tools-$$(uname -r)"; exit 1; }
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) bpf/flowmon.h $(VMLINUX)
	@mkdir -p $(dir $@)
	$(CLANG) $(CFLAGS) -c $< -o $@
	@[ -n "$(STRIP)" ] && $(STRIP) -g $@ || echo "  (llvm-strip yok, atlandi)"

.PHONY: bpf
bpf: $(BPF_OBJ)

# go.sum depoda tutulmuyor; ilk derlemede uretiliyor.
go.sum: go.mod
	$(GO) mod tidy

$(BIN): $(BPF_OBJ) go.sum $(shell find . -name '*.go' 2>/dev/null)
	@mkdir -p bin
	$(GO) build -o $(BIN) ./cmd/flowmon

.PHONY: build
build: $(BIN)

.PHONY: test
test:
	$(GO) test ./...

.PHONY: vet
vet:
	$(GO) vet ./...

# Sensor kendi kendini dogrular: uc sinif da uretiliyor mu? Kubernetes gerekmez.
.PHONY: smoke
smoke: $(BIN)
	sudo ./scripts/smoke.sh

# agentic-sre gozlem ortami (manifests/). Ayrintilar scripts/env.sh.
.PHONY: env-up env-baseline env-break env-restore env-status env-down
env-up:      $(BIN) ; ./scripts/env.sh up
env-baseline:        ; ./scripts/env.sh baseline
env-break:           ; ./scripts/env.sh break $(SCENARIO)
env-restore:         ; ./scripts/env.sh restore
env-status:          ; ./scripts/env.sh status
env-down:            ; ./scripts/env.sh down

# make env-capture SECS=30 LABEL=baseline
.PHONY: env-capture
env-capture: $(BIN)
	./scripts/env.sh capture $(or $(SECS),30) $(or $(LABEL),capture)

# Referans dongu: bilinen-iyi olcum -> ariza -> arizali olcum -> geri al.
# Dogrulama kapisinin (§3.3) girdi ciftini bu uretiyor.
#   make reference-case                    (varsayilan: selector senaryosu)
#   make reference-case SCENARIO=and-or
.PHONY: reference-case
reference-case: $(BIN)
	./scripts/env.sh capture 30 baseline
	./scripts/env.sh break $(or $(SCENARIO),selector)
	./scripts/env.sh capture 45 $(or $(SCENARIO),selector)
	./scripts/env.sh restore

# Sifirdan tam akis: politikasiz kurulum -> R kumesi -> politika -> A kumesi.
# Ilk olcum POLITIKASIZ alinir; uygulamanin kisitsiz neye baglandigini yalnizca
# o olcum soyler (PMR'nin paydasi, Proje Ozeti §6).
.PHONY: bootstrap
bootstrap: $(BIN)
	./scripts/env.sh up
	./scripts/env.sh capture 60 no-policy
	./scripts/env.sh baseline
	./scripts/env.sh capture 30 baseline

# Tum senaryolari sirayla olcer. bootstrap'tan sonra calistirilir.
.PHONY: all-scenarios
all-scenarios: $(BIN)
	for s in selector port and-or protocol target; do \
		./scripts/env.sh break $$s; \
		./scripts/env.sh capture 45 $$s; \
		./scripts/env.sh restore; \
	done

.PHONY: deps
deps:
	./scripts/setup-deps.sh

.PHONY: clean
clean:
	rm -rf bin $(BPF_OBJ)

# vmlinux.h uretilmis bir yapaydir; silmek icin ayri hedef.
.PHONY: distclean
distclean: clean
	rm -f $(VMLINUX)
