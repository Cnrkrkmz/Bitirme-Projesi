// Package flow — cekirdekten gelen ham baytlari anlamli olaylara cevirir ve
// gozlenen akis kumesini olusturur.
//
// Paket iki dosyadan olusuyor:
//
//	event.go     tek bir connect() denemesi: cozumleme + siniflandirma
//	observed.go  olaylarin akis bazinda toplanmasi
//
// NE ISE YARIYOR (event.go)
//
// Bu dosya projenin KARAR noktasi. Cekirdek yalnizca ham olguyu bildirir --
// "el sikisma tamamlandi" ya da "tamamlanmadi". Bir denemenin SESSIZCE mi
// dusuruldugu yoksa RST ile mi reddedildigi burada belirlenir.
//
// Ayrim neden onemli: kubectl describe her iki durumu da ayni gosterir,
// ama kok nedenleri tamamen farklidir.
//
//	dropped  -> NetworkPolicy, guvenlik duvari, ag bolunmesi, dugum olumu
//	refused  -> hedefe ULASILDI ama o portta dinleyen surec yok
//
// # NEDEN SINIFLANDIRMA CEKIRDEKTE DEGIL BURADA
//
// Siniflandirma politikasi hizli degisir: esik degeri ayarlanir, yeni bir
// sinif eklenir, kural rafine edilir. Bu karar bpf/flowmon.bpf.c icinde
// olsaydi her degisiklik icin eBPF'i yeniden derleyip verifier'dan gecirip
// cekirdege yeniden yuklemek gerekirdi. Burada bir `go build` yetiyor.
//
// Cekirdek olcer, userspace yorumlar.
package flow

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

// EventSize, bpf/flowmon.h icindeki FLOW_EVENT_SIZE ile AYNI olmali.
//
// Cekirdek ile userspace arasinda serilestirme yok: cekirdek struct'i ham
// olarak ring buffer'a yaziyor, Parse() asagida elle offsetlerden okuyor.
// Hizli ama kirilgan -- iki taraf kayarsa hata VERMEZ, sessizce yanlis veri
// uretir. Bu sabit ve event_test.go o kaymayi yakalamak icin var.
const EventSize = 72

// Cekirdekteki enum fm_verdict ile ayni.
const (
	verdictEstablished uint8 = 0
	verdictFailed      uint8 = 1
)

const flagNoMeta uint8 = 1 << 0

// Class, bir connect() denemesinin ne anlama geldigi.
//
// kubectl describe bu ucunu de ayni gosterir; ayrimi yapan sey retransmit
// sayaci: SYN'e hic cevap gelmediyse paket sessizce dusurulmustur
// (NetworkPolicy, partition), aninda RST geldiyse hedef erisilebilir ama o
// portta dinleyen yoktur.
type Class string

const (
	ClassOK      Class = "established"
	ClassDropped Class = "dropped" /* SYN yeniden iletildi, cevap yok */
	ClassRefused Class = "refused" /* RST — hedefe ulasildi, port kapali */
)

// dropInferenceThreshold — yeniden iletim gorulmediginde sureye bakan yedek
// olcut.
//
// Ilk SYN yeniden iletimi ~1 sn sonra gelir. Uygulama bundan once vazgecerse
// (non-blocking connect + kisa timeout) hic retransmit gormeyiz ve olay
// yanlislikla "refused" sayilirdi. Bu esik o bosluğu kapatiyor.
//
// 900 ms neden guvenli: anlik RST milisaniyeler icinde doner (olculen:
// ~0.03 ms), sessiz dusurme saniyeler surer (olculen: ~3000 ms). Iki durum
// arasinda dort buyukluk mertebesi var, esigin tam yeri kritik degil.
const dropInferenceThreshold = 900 * time.Millisecond

// Event, tek bir connect() denemesinin sonucu.
type Event struct {
	Timestamp time.Duration // cekirdek monotonik saati (bpf_ktime_get_ns)
	CgroupID  uint64
	Duration  time.Duration
	PID       uint32
	TGID      uint32
	Src       netip.AddrPort
	Dst       netip.AddrPort
	Retrans   uint32
	Comm      string
	HasMeta   bool // false ise cgroup/pid alanlari anlamsiz
	verdict   uint8
}

// Class, olayin sinifini dondurur.
func (e Event) Class() Class {
	if e.verdict == verdictEstablished {
		return ClassOK
	}
	if e.Retrans > 0 || e.Duration >= dropInferenceThreshold {
		return ClassDropped
	}
	return ClassRefused
}

// Failed, denemenin el sikismayi tamamlayamadigini soyler.
func (e Event) Failed() bool { return e.verdict == verdictFailed }

// Parse — ring buffer'dan gelen 72 baytlik ham kaydi Event'e cevirir.
//
// Offsetler bpf/flowmon.h icindeki struct flow_event ile birebir eslesmek
// zorunda. Sihirli sayilar orada gerekce ile birlikte yaziyor; degistirmeden
// once iki tarafi da okuyun.
//
// Bayt sirasi iki farkli kuralda: cekirdek struct alanlarini host sirasinda
// yaziyor (bu yuzden NativeEndian), ama IP adresleri soket icinde zaten
// network byte order'da duruyor ve netip.AddrFrom4 de onu bekliyor -- bu
// yuzden adreslere cevrim UYGULANMIYOR. Portlar cekirdek tarafinda zaten
// host sirasina cevrilmis durumda.
func Parse(raw []byte) (Event, error) {
	if len(raw) < EventSize {
		return Event{}, fmt.Errorf("kisa kayit: %d bayt, beklenen %d", len(raw), EventSize)
	}
	// Cekirdek struct'i host sirasinda yaziyor.
	e := binary.NativeEndian
	ev := Event{
		Timestamp: time.Duration(e.Uint64(raw[0:8])),
		CgroupID:  e.Uint64(raw[8:16]),
		Duration:  time.Duration(e.Uint64(raw[16:24])),
		PID:       e.Uint32(raw[24:28]),
		TGID:      e.Uint32(raw[28:32]),
		Retrans:   e.Uint32(raw[40:44]),
		verdict:   raw[48],
	}
	// saddr/daddr network byte order; netip.AddrFrom4 zaten big-endian bekliyor.
	ev.Src = netip.AddrPortFrom(netip.AddrFrom4([4]byte(raw[32:36])), e.Uint16(raw[44:46]))
	ev.Dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(raw[36:40])), e.Uint16(raw[46:48]))
	ev.HasMeta = raw[50]&flagNoMeta == 0
	ev.Comm = cstr(raw[52:68])
	return ev, nil
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
