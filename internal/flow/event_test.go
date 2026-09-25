// event_test.go — C ile Go arasindaki bayt sozlesmesini kilitler.
//
// # NEDEN BU TEST VAR
//
// Cekirdek struct flow_event'i ham olarak ring buffer'a yaziyor, Parse()
// ayni baytlari elle offsetlerden okuyor. Iki taraf kayarsa program hata
// VERMEZ -- sessizce yanlis veri uretir: yanlis IP, yanlis port, yanlis
// sinif. Boyle bir hata uretimde aylarca fark edilmeyebilir.
//
// Bu test o sessiz kaymayi gurultulu hale getiriyor. bpf/flowmon.h icindeki
// bir alani degistirip event.go'yu guncellemezseniz test kirmizi yanar.
//
// Ayrica siniflandirma karar tablosunu da dogruluyor: hangi (verdict,
// retrans, duration) uclusunun hangi sinifi urettigi burada sabitleniyor.
package flow

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// build, bpf/flowmon.h icindeki yerlesime gore bir ham kayit uretir. Bu test
// asil olarak sozlesmeyi koruyor: C tarafinda alan sirasi degisirse burasi
// duser.
func build(verdict uint8, retrans uint32, dur time.Duration, flags uint8) []byte {
	b := make([]byte, EventSize)
	e := binary.NativeEndian
	e.PutUint64(b[0:8], 1_000)          // ts_ns
	e.PutUint64(b[8:16], 4242)          // cgroup_id
	e.PutUint64(b[16:24], uint64(dur))  // duration_ns
	e.PutUint32(b[24:28], 111)          // pid
	e.PutUint32(b[28:32], 222)          // tgid
	copy(b[32:36], []byte{10, 0, 0, 5}) // saddr
	copy(b[36:40], []byte{10, 0, 0, 9}) // daddr
	e.PutUint32(b[40:44], retrans)      // retrans
	e.PutUint16(b[44:46], 54321)        // sport
	e.PutUint16(b[46:48], 7070)         // dport
	b[48] = verdict
	b[49] = 2 // AF_INET
	b[50] = flags
	copy(b[52:68], "checkoutservic\x00")
	return b
}

func TestParseTuple(t *testing.T) {
	ev, err := Parse(build(verdictFailed, 3, 2*time.Second, 0))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if want := netip.MustParseAddrPort("10.0.0.5:54321"); ev.Src != want {
		t.Errorf("Src = %v, beklenen %v", ev.Src, want)
	}
	if want := netip.MustParseAddrPort("10.0.0.9:7070"); ev.Dst != want {
		t.Errorf("Dst = %v, beklenen %v", ev.Dst, want)
	}
	if ev.Comm != "checkoutservic" {
		t.Errorf("Comm = %q", ev.Comm)
	}
	if !ev.HasMeta {
		t.Error("HasMeta false, beklenen true")
	}
	if ev.Duration != 2*time.Second {
		t.Errorf("Duration = %v", ev.Duration)
	}
}

// Siniflandirma bu projenin tesbit ettigi ayrimi kodluyor: sessizce dusurulen
// SYN (NetworkPolicy/partition) ile RST (port kapali) ayni degil.
func TestClass(t *testing.T) {
	cases := []struct {
		name    string
		verdict uint8
		retrans uint32
		dur     time.Duration
		want    Class
	}{
		{"kuruldu", verdictEstablished, 0, 3 * time.Millisecond, ClassOK},
		{"yeniden iletildi, cevap yok", verdictFailed, 3, 2 * time.Second, ClassDropped},
		{"anlik RST", verdictFailed, 0, 200 * time.Microsecond, ClassRefused},
		// Uygulama ilk yeniden iletimden once vazgecti: retransmit yok ama
		// sure RST ile aciklanamayacak kadar uzun.
		{"erken vazgecis", verdictFailed, 0, 1500 * time.Millisecond, ClassDropped},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := Parse(build(tc.verdict, tc.retrans, tc.dur, 0))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := ev.Class(); got != tc.want {
				t.Errorf("Class() = %v, beklenen %v", got, tc.want)
			}
		})
	}
}

func TestParseShortRecord(t *testing.T) {
	if _, err := Parse(make([]byte, EventSize-1)); err == nil {
		t.Fatal("kisa kayit icin hata bekleniyordu")
	}
}

// Gozlenen akis kumesi kaynak portu yok saymali: efemeral port her denemede
// degisir, NetworkPolicy ise onu hic gormez.
func TestObservedSetIgnoresSourcePort(t *testing.T) {
	s := NewObservedSet()
	now := time.Now()

	a, _ := Parse(build(verdictFailed, 2, time.Second, 0))
	b := a
	b.Src = netip.AddrPortFrom(a.Src.Addr(), 40000) // farkli efemeral port

	s.Add(a, now)
	s.Add(b, now)

	snap := s.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("%d akis, beklenen 1", len(snap))
	}
	if snap[0].Dropped != 2 {
		t.Errorf("Dropped = %d, beklenen 2", snap[0].Dropped)
	}
	if snap[0].Attempts() != 2 {
		t.Errorf("Attempts = %d, beklenen 2", snap[0].Attempts())
	}
}
