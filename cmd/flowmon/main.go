// Command flowmon — Kubernetes'te sessizce dusurulen TCP baglantilarini
// cekirdekten tespit eder.
//
// # NE ISE YARIYOR
//
// Calistigi dugumdeki her giden IPv4 TCP baglanti denemesini yakalar, ucune
// ayirir ve her denemeyi onu baslatan pod'a baglar:
//
//	established  el sikisma tamamlandi
//	dropped      SYN'e hic cevap gelmedi     -> NetworkPolicy, firewall, partition
//	refused      RST dondu, yeniden iletim yok -> o portta dinleyen surec yok
//
// kubectl describe bu uc durumu da ayni gosterir. Projenin cozmeye calistigi
// gozlem boslugu bu.
//
// # BU DOSYANIN ROLU
//
// Burasi KONTROL PANELI, is mantigi degil. Bayraklari okur, parcalari
// birbirine baglar, okuma dongusunu cevirir. Asil is baska yerde:
//
//	internal/probe    eBPF programini cekirdege yukler, kancalari takar
//	internal/flow     ham baytlari cozer, siniflandirir, akislari toplar
//	internal/cgroups  cgroup id'yi pod kimligine cevirir
//	bpf/              cekirdekte calisan asil sensor (C)
//
// # IKI CIKTI BICIMI
//
// stdout'a JSONL olay akisi gider: her satir bir connect() denemesi. Canli
// izlemek ve hata ayiklamak icin.
//
// -observed ile kapanista GOZLENEN AKIS KUMESI yazilir: akis bazinda ozet.
// Dogrulama kapisinin (Proje Ozeti §3.3) girdisi budur; kapi onerilen bir
// NetworkPolicy yamasini bu kumeye karsi sinar.
//
// KULLANIM
//
//	sudo ./bin/flowmon -dport 18080,19090 -observed observed.json
//	sudo ./bin/flowmon -dport 19090 -raw     # cekirdekten gelen ham baytlar
//
// Root gerekiyor (BPF program yukleme) ve cekirdekte BTF olmali.
// Ctrl-C ile duzgun kapanir ve gozlenen kumeyi yazar.
//
// # SINIRLAR
//
// Yalnizca giden IPv4 TCP. UDP yok, yani DNS hatalari GORUNMEZ. Gelen
// baglantilar yok (sunucu tarafi accept() cagirir, connect() degil).
// El sikismadan sonrasi yok: kurulmus bir baglanti sonradan koparsa ya da
// uygulama HTTP 403 donerse bizim icin "established".
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/caner/k8s-agentic-sre/internal/cgroups"
	"github.com/caner/k8s-agentic-sre/internal/flow"
	"github.com/caner/k8s-agentic-sre/internal/probe"
)

func main() {
	var (
		dports       = flag.String("dport", "", "yalnizca bu hedef portlari izle, virgulle ayrilmis (bos = hepsi)")
		failedOnly   = flag.Bool("failed-only", false, "yalnizca basarisiz denemeleri yaz")
		exclLoopback = flag.Bool("exclude-loopback", true, "127.0.0.0/8 hedeflerini atla")
		observedPath = flag.String("observed", "", "cikista gozlenen akis kumesini bu dosyaya yaz")
		cgroupRoot   = flag.String("cgroup-root", cgroups.DefaultRoot, "cgroup v2 kok dizini")
		quiet        = flag.Bool("quiet", false, "olay akisini bastir, yalnizca ozet yaz")
		raw          = flag.Bool("raw", false, "cekirdekten gelen 72 baytlik ham kaydi yorumlamadan bas")
	)
	flag.Parse()

	ports, err := parsePorts(*dports)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flowmon: %v\n", err)
		os.Exit(2)
	}

	if err := run(runOpts{
		dports:       ports,
		failedOnly:   *failedOnly,
		exclLoopback: *exclLoopback,
		observedPath: *observedPath,
		cgroupRoot:   *cgroupRoot,
		quiet:        *quiet,
		raw:          *raw,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "flowmon: %v\n", err)
		os.Exit(1)
	}
}

// parsePorts — "-dport 18080,19090" bicimini cozer. Bos girdi "hepsi" demek.
//
// Liste kabul etmesinin sebebi: gozlem ortaminda birden fazla akis var ve
// hepsini tek kosuda olcmek gerekiyor. Tek port destegi yetseydi her akis
// icin ayri kosu gerekirdi ve olcumler zaman icinde kayardi.
func parsePorts(s string) (map[uint16]bool, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	out := make(map[uint16]bool)
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, err := strconv.ParseUint(f, 10, 16)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("gecersiz port: %q", f)
		}
		out[uint16(n)] = true
	}
	return out, nil
}

type runOpts struct {
	dports       map[uint16]bool
	failedOnly   bool
	exclLoopback bool
	observedPath string
	cgroupRoot   string
	quiet        bool
	raw          bool
}

// jsonEvent — stdout'a yazilan JSONL satirinin bicimi.
//
// Ic Event tipinden ayri tutuluyor: bu yapi DIS SOZLESME (baska araclar
// okuyacak), oteki ic temsil. omitempty olan alanlar meta bilgisi olmayan
// olaylarda dusuyor -- probe takilmadan once yaratilmis soketlerde cgroup ve
// pid anlamsiz, bos yazmak yaniltici olurdu.
type jsonEvent struct {
	Time       time.Time  `json:"time"`
	Class      flow.Class `json:"class"`
	Src        string     `json:"src"`
	Dst        string     `json:"dst"`
	Dport      uint16     `json:"dport"`
	Retrans    uint32     `json:"retrans"`
	DurationMS float64    `json:"duration_ms"`
	Comm       string     `json:"comm,omitempty"`
	PID        uint32     `json:"pid,omitempty"`
	CgroupID   uint64     `json:"cgroup_id,omitempty"`
	Cgroup     string     `json:"cgroup,omitempty"`
	PodUID     string     `json:"pod_uid,omitempty"`
	Container  string     `json:"container_id,omitempty"`
}

func run(o runOpts) error {
	p, err := probe.Load()
	if err != nil {
		return err
	}
	defer p.Close()

	fmt.Fprintln(os.Stderr, "flowmon: kancalar takildi, dinleniyor (Ctrl-C ile bitir)")

	resolver := cgroups.New(o.cgroupRoot)
	observed := flow.NewObservedSet()
	enc := json.NewEncoder(os.Stdout)

	// Cekirdek monotonik saatini duvar saatine cevirmek icin tek seferlik
	// referans. Olay zaman damgalari bu offsetle kaydiriliyor.
	bootTime, err := bootWallClock()
	if err != nil {
		return err
	}

	// Sinyal geldiginde okuyucuyu kapatiyoruz; bu, Read()'i ErrClosed ile
	// dondurup donguyu duzgun sonlandiriyor.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		p.Events.Close()
	}()

	var seen, written uint64
	for {
		rec, err := p.Events.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			return fmt.Errorf("ring buffer okunamadi: %w", err)
		}

		ev, err := flow.Parse(rec.RawSample)
		if err != nil {
			// Bozuk kayit sozlesme uyusmazligina isaret eder; sessizce gecmek
			// yanlis olcume yol acar.
			fmt.Fprintf(os.Stderr, "flowmon: kayit cozumlenemedi: %v\n", err)
			continue
		}
		seen++

		if o.exclLoopback && ev.Dst.Addr().IsLoopback() {
			continue
		}
		if len(o.dports) > 0 && !o.dports[ev.Dst.Port()] {
			continue
		}

		wall := bootTime.Add(ev.Timestamp)
		observed.Add(ev, wall)

		if o.raw {
			written++
			printRaw(written, rec.RawSample)
			continue
		}

		if o.quiet || (o.failedOnly && !ev.Failed()) {
			continue
		}

		out := jsonEvent{
			Time:       wall,
			Class:      ev.Class(),
			Src:        ev.Src.Addr().String(),
			Dst:        ev.Dst.Addr().String(),
			Dport:      ev.Dst.Port(),
			Retrans:    ev.Retrans,
			DurationMS: float64(ev.Duration.Microseconds()) / 1000,
			Comm:       ev.Comm,
			PID:        ev.TGID,
		}
		if ev.HasMeta {
			out.CgroupID = ev.CgroupID
			if path, ok := resolver.Path(ev.CgroupID); ok {
				out.Cgroup = path
				c := cgroups.Parse(path)
				out.PodUID, out.Container = c.PodUID, c.ContainerID
			}
		}
		if err := enc.Encode(out); err != nil {
			return fmt.Errorf("cikti yazilamadi: %w", err)
		}
		written++
	}

	return finish(p, observed, o.observedPath, seen, written)
}

func finish(p *probe.Probe, observed *flow.ObservedSet, path string, seen, written uint64) error {
	fmt.Fprintf(os.Stderr, "\nflowmon: %d olay alindi, %d yazildi, %d benzersiz akis\n",
		seen, written, len(observed.Snapshot()))

	// Dusen olay varsa gozlenen akis kumesi eksik demektir ve bununla
	// hesaplanan her metrik supheli — gurultuye karistirmadan bildiriyoruz.
	if dropped, err := p.Dropped(); err == nil && dropped > 0 {
		fmt.Fprintf(os.Stderr,
			"flowmon: UYARI — ring buffer doldugu icin %d olay dusuruldu; kume eksik\n", dropped)
	}

	if path == "" {
		return nil
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("gozlenen akis dosyasi olusturulamadi: %w", err)
	}
	defer f.Close()
	if err := observed.WriteJSON(f); err != nil {
		return fmt.Errorf("gozlenen akis yazilamadi: %w", err)
	}
	fmt.Fprintf(os.Stderr, "flowmon: gozlenen akis kumesi -> %s\n", path)
	return nil
}

// printRaw — eBPF programinin ring buffer'a yazdigi kaydi HIC YORUMLAMADAN basar.
//
// Ekranda gorunen sey, bpf/flowmon.bpf.c icindeki fm_inet_sock_set_state'in
// cekirdekte doldurdugu struct flow_event'in baytlari -- Go tarafi bunlara
// henuz dokunmadi. Altindaki satir yalnizca bu baytlari flowmon.h'deki alan
// sinirlarina gore boluyor: sayilar oldugu gibi (verdict 0/1, sure nanosaniye,
// adresler ag bayt sirasinda). "dropped/refused" karari burada YOK; o karar
// internal/flow/event.go'da bu ham degerlerden turetiliyor.
func printRaw(n uint64, b []byte) {
	e := binary.NativeEndian
	fmt.Printf("olay #%d  (%d bayt)\n", n, len(b))
	for i := 0; i < len(b); i += 16 {
		end := min(i+16, len(b))
		fmt.Printf("  %04x  % x\n", i, b[i:end])
	}
	fmt.Printf("  ts_ns=%d cgroup_id=%d duration_ns=%d pid=%d tgid=%d\n",
		e.Uint64(b[0:8]), e.Uint64(b[8:16]), e.Uint64(b[16:24]), e.Uint32(b[24:28]), e.Uint32(b[28:32]))
	fmt.Printf("  saddr=[% x] daddr=[% x] retrans=%d sport=%d dport=%d verdict=%d family=%d flags=%d comm=%q\n\n",
		b[32:36], b[36:40], e.Uint32(b[40:44]), e.Uint16(b[44:46]), e.Uint16(b[46:48]),
		b[48], b[49], b[50], strings.TrimRight(string(b[52:68]), "\x00"))
}

// bootWallClock — cekirdek monotonik saatinin sifir noktasina karsilik gelen
// duvar saati.
//
// Cekirdek olaylari bpf_ktime_get_ns() ile damgaliyor: acilistan beri gecen
// nanosaniye. Bu sayi tek basina "saat 14:32'de oldu" bilgisi vermez.
// Ayni saat kaynagini burada bir kez okuyup farki alarak cevrim katsayisini
// buluyoruz; sonra her olaya ekleniyor.
//
// Neden duvar saati degil de monotonik kullaniliyor: duvar saati NTP ile
// geri atlayabilir ve sureler negatif cikabilirdi.
func bootWallClock() (time.Time, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return time.Time{}, fmt.Errorf("monotonik saat okunamadi: %w", err)
	}
	return time.Now().Add(-time.Duration(ts.Nano())), nil
}
