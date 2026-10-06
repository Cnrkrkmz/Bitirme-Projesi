# Autonomous eBPF-Observed Agentic Remediation for Kubernetes

Faz 0/1 telemetri katmani. Bu depo su an yalnizca **tek bir soruyu** yanitliyor:
basarisiz bir `connect()` denemesinden `(kaynak, hedef, port)` ucluosu
cikarilabiliyor mu, ve o deneme **neden** basarisiz oldu?

Proje ozetindeki uyari kasitli olarak baslangic noktasi secildi:

> Kacinilmasi gereken en yaygin hata: her sey calismadan once eBPF katmanini
> mukemmellestirmek. Faz 1–3 ondan tek bir sey istiyor.

Sayfa-hatasi izleme, DNS korelasyonu ve syscall filtreleme bilerek **yok**.

## Ne olcuyor

Uc kanca, uc farkli soruyu yanitliyor:

| Kanca | Tur | Ne veriyor |
|---|---|---|
| `tcp_v4_connect` | kprobe | cgroup id, pid, comm — yalnizca gorev baglaminda okunabilir |
| `inet_sock_set_state` | tp_btf | `SYN_SENT` cikisi: baglanti kuruldu mu, kurulamadi mi |
| `tcp_retransmit_skb` | tp_btf | `SYN_SENT` sirasinda yeniden iletim = SYN cevapsiz kaldi |

Ucuncusu ayrimi yapan sinyal:

| Sinif | Kosul | Anlami |
|---|---|---|
| `established` | el sikisma tamamlandi | akis calisiyor |
| `dropped` | SYN yeniden iletildi, cevap gelmedi | **sessiz dusurme** — NetworkPolicy veya partition |
| `refused` | RST, yeniden iletim yok | yol acik, portta dinleyen yok |

`kubectl describe` bu ucunu de ayni gosterir. Ayrimi burada yapiyoruz.

## Kurulum

```bash
make deps        # clang, libbpf, bpftool, Go  (Ubuntu/Debian)
make build       # go mod tidy -> vmlinux.h -> .o -> bin/flowmon
sudo make smoke  # sensor kendini dogrular: uc sinif da uretiliyor mu?
```

`go.sum` depoda tutulmuyor; ilk `make build` `go mod tidy` ile uretiyor.

Gereksinim: BTF'li Linux cekirdegi (`/sys/kernel/btf/vmlinux`). CO-RE ve
`tp_btf` bunun uzerine kurulu — proje ozetinde de zaten sart kosulmus durumda.

## Kullanim

```bash
sudo ./bin/flowmon -dport 18080,19090 -observed observed.json
```

Stdout'a JSONL olay akisi gider:

```json
{"time":"...","class":"dropped","src":"10.244.219.113","dst":"10.244.219.118",
 "dport":19090,"retrans":2,"duration_ms":3000.15,"comm":"wget",
 "pod_uid":"3f2b...","container_id":"9c1a..."}
```

`-observed` ile cikista **gozlenen akis kumesi** yazilir. Dogrulama kapisini
(§3.3) sinirlayan girdi budur: kapinin sordugu soru "bu oneri gozlenen akistan
fazlasini aciyor mu". Kume hem basarisiz hem basarili akislari icerir —
yalnizca basarisizlari toplamak kapinin mesru trafigi kapatmasina, yani
UPR > 0'a yol acar.

| Bayrak | Islev |
|---|---|
| `-dport N,M` | yalnizca bu hedef portlari izle (virgulle ayrilmis) |
| `-failed-only` | yalnizca basarisiz denemeleri yaz |
| `-exclude-loopback=false` | 127.0.0.0/8 hedeflerini de dahil et |
| `-observed DOSYA` | cikista gozlenen akis kumesini yaz |
| `-quiet` | olay akisini bastir, yalnizca ozet |

## Yapi

```
bpf/flowmon.bpf.c       eBPF programi (CO-RE)
bpf/flowmon.h           C ve Go arasindaki olay sozlesmesi
internal/probe/         .o yukleme ve kanca takma (gomulu ELF)
internal/flow/          olay cozumleme, siniflandirma, gozlenen akis kumesi
internal/cgroups/       cgroup id -> pod/container eslemesi
cmd/flowmon/            CLI
manifests/              gozlem altindaki is yukleri ve politikalar
scripts/                ortam surucusu ve on kontroller
```

`bpf/vmlinux.h` ve `internal/probe/bpf/flowmon.bpf.o` uretilen yapaylar;
sirasiyla `bpftool` ve `clang` uretiyor, ikisi de `.gitignore`'da. `go build`
`.o` dosyasini `go:embed` ile ikiliye gomdugu icin **once `make bpf`
calismali** — `make build` bu sirayi zaten kuruyor.

## Bilinen sinirlar

- **Yalnizca IPv4.** `inet_sock_set_state` icinde `AF_INET6` atlaniyor.
- **Yalnizca TCP.** UDP'nin baglanti durumu yok; DNS icin ayri bir kanca gerekecek.
- **Yalnizca giden baglantilar.** `tcp_v4_connect` istemci tarafi; dinleyen
  tarafta reddedilen baglantilar icin `inet_csk_accept` gerekir.
- **Kanca oncesi soketler.** Biz baglanmadan once yaratilmis soketlerde
  cgroup/pid yok; olay `flags` icinde isaretlenip yine de yayinlaniyor, uclu
  gecerli kaliyor.
- **Ring buffer tasmasi** sessiz degil: dusen olay sayisi `dropped` map'inde
  tutuluyor ve cikista uyari olarak basiliyor. Sifirdan buyukse o kosudan
  hesaplanan metrikler eksik veriye dayaniyor demektir.

## Demo

Uc script, uc ariza. Her biri tek terminalde ayni hikayeyi canli gosterir:
saglikli trafik akar, bir politika bozulur, eBPF kesintiyi saniyesi saniyesine
gorur, Kubernetes ise hicbir sey soylemez, politika geri yuklenir.

```bash
./demo/1-etiket-hatasi.sh     # app: api -> api-v2          api -> store:19090 kesilir
./demo/2-port-hatasi.sh       # port 18081 -> 18082         frontend -> api:18081 kesilir
./demo/3-ve-veya-hatasi.sh    # iki secici ayni ogede (VE)  frontend -> api:18080 kesilir
```

Her biri ~50 sn surer. Ctrl-C ile yarida kesilse bile politika geri yuklenir
ve eBPF programi cekirdekten sokulur. Baslamadan once kume ici ag/DNS'i
dogrular: DNS calismiyorsa uygulama connect() cagiramaz ve ekran bos kalirdi.

## Gozlem ortami

`manifests/` altinda kalici bir ortam var: `agentic-sre` namespace'inde iki pod
ve uc NetworkPolicy. Sunucu iki port aciyor, istemci ikisine de baglaniyor.

```
client --18080--> server   uygulama yolu    (arizada AYAKTA KALIR)
client --19090--> server   admin yolu       (arizada KESILIR)
```

Iki akis olmasi kasitli. Tek akis olsaydi ariza tetiklendiginde gozlenen
kumenin tamami kirik olurdu; dogrulama kapisinin neyi KORUMASI gerektigi
olculemezdi. Kapinin mesru trafigi kapatmasi (UPR) tam bu kor noktadan dogar.

Referans ariza tek bir etiket hatasi -- `app: client` yerine `app: client-v2`.
Ekleme degil uzerine yazma: NetworkPolicy'ler birlesimle calistigi icin bos
bir deny eklemek mevcut izni kaldirmaz. Gercek regresyonlar da boyle olur.

```bash
make env-up                                  # ortami kur
make env-capture SECS=30 LABEL=baseline      # bilinen-iyi olcum
make env-break                               # arizayi uygula
make env-capture SECS=45 LABEL=faulted       # arizali olcum
make env-restore                             # geri al

make reference-case                          # yukaridakilerin tamami
```

Olculen sonuc:

```
# baseline
10.244.219.95 -> 10.244.219.97:18080  est=15  drop=0
10.244.219.95 -> 10.244.219.97:19090  est=10  drop=0

# faulted
10.244.219.95 -> 10.244.219.97:18080  est=22  drop=0   <- kontrol akisi ayakta
10.244.219.95 -> 10.244.219.97:19090  est=0   drop=7   <- kesilen akis
```

Ayni sirada `kubectl get pods` iki pod'u da `1/1 Running`, restart yok
gosteriyor ve `kubectl get events` bos. Kapatilmaya calisilan boslugu bu.

Olculen ile hesaplananin karsilastirmasi tek komut:

```bash
./scripts/analyze.sh compare      # 3 baglanti x 4 durum = 12 hucre, ORTUSEN: 12 / 12
```

Bu iki dosya -- `out/observed-baseline.json` ve `out/observed-faulted.json` --
dogrulama kapisinin (§3.3) girdi cifti olacak: baseline kumesi kapinin
korumasi gerekeni, faulted kumesi onarmasi gerekeni tanimliyor.
