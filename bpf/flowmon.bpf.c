// SPDX-License-Identifier: GPL-2.0
/*
 * flowmon.bpf.c — projenin SENSORU. Cekirdegin icinde calisir.
 *
 * NE ISE YARIYOR
 *
 * Dugumdeki her giden IPv4 TCP baglanti denemesini yakalar ve sonucunu
 * userspace'e bildirir. Amac (Proje Ozeti §3.3, §15) basarisiz bir
 * connect() denemesinden (kaynak, hedef, port) uclusunu cikarmak; bu uclu
 * dogrulama kapisini sinirlayan "gozlenen akis" kumesini olusturur.
 *
 * NEREDE DURUYOR
 *
 * Kancalar TCP SOKET katmaninda. Calico'nun NetworkPolicy programlari
 * asagida, TC katmaninda:
 *
 *     uygulama  --connect()-->  TCP soket katmani   <-- BIZ BURADAYIZ
 *                                      |
 *                                      v
 *                               TC hook (Calico)    <-- politika BURADA
 *                                      X               uygulaniyor
 *
 * Yani SYN'in gonderildigini goruyoruz, dusuruldugunu GORMUYORUZ. Gordugumuz
 * tek sey cevabin hic gelmemesi. Sensorun NetworkPolicy'ye ozel olmamasinin
 * sebebi de bu: iptables, ag bolunmesi, dugum olumu -- el sikismayi engelleyen
 * her sey ayni imzayi uretiyor.
 *
 * CALISMA BAGLAMI UYARISI
 *
 * Uc kanca AYNI baglamda calismiyor ve bu tasarimi belirliyor:
 *
 *   kprobe/tcp_v4_connect   GOREV baglami -- cagiran surecin icinde.
 *                           bpf_get_current_cgroup_id(), pid ve comm
 *                           YALNIZCA burada anlamli.
 *
 *   tp_btf kancalari        SOFTIRQ baglami -- "hangi surec" sorusunun
 *                           cevabi yok. Bu yuzden gorev bilgisi once
 *                           conn_meta_map'e yaziliyor, sonra oradan
 *                           okunuyor.
 *
 * Neden bu uc kanca:
 *
 *   tcp_v4_connect (kprobe)   — TEK gorev baglaminda calisan nokta. cgroup id,
 *                               pid ve comm yalnizca burada dogru okunabilir;
 *                               asagidaki tracepoint'ler softirq'te tetiklenir.
 *
 *   inet_sock_set_state       — SYN_SENT -> ESTABLISHED  = baglanti kuruldu
 *   (tp_btf)                    SYN_SENT -> CLOSE        = el sikisma bitmedi
 *
 *   tcp_retransmit_skb        — SYN_SENT sirasinda yeniden iletim = SYN sessizce
 *   (tp_btf)                    dusuruldu. NetworkPolicy/partition ile RST'yi
 *                               (baglanti reddedildi) ayiran sinyal budur.
 *
 * kubectl describe her uc durumda da ayni goruntuyu verir; ayrimi burada
 * yapiyoruz. Siniflandirmanin kendisi userspace'te (internal/flow), cunku
 * politikasi hizli degisiyor — cekirdek yalnizca ham olguyu bildirir.
 *
 * tp_btf tercih edildi: trace_event_raw_* struct ADLARI cekirdek surumleri
 * arasinda degisiyor (ornegin tcp_event_sk_skb -> tcp_retransmit_skb), ham
 * tracepoint imzalari ise degismiyor. CO-RE alan offset'lerini zaten cozuyor.
 */
/* vmlinux.h bpftool tarafindan uretiliyor ve cekirdegin BTF'indeki isimsiz
 * struct/union uyeleri icin gecersiz ileri bildirimler iceriyor. Uretilmis
 * dosyaya -Werror uygulamiyoruz; kendi kodumuzda siki kaliyor. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "flowmon.h"

char LICENSE[] SEC("license") = "GPL";

/* vmlinux.h icindeki enum'larla catismamak icin kendi adlarimiz. */
#define FM_TCP_ESTABLISHED 1
#define FM_TCP_SYN_SENT    2
#define FM_TCP_CLOSE       7
#define FM_AF_INET         2

/* Gorev baglaminda toplanip tracepoint'e tasinan bilgi.
 *
 * struct sock * isaretcisi ile anahtarlaniyor: connect() sirasinda yazilan
 * kayit, ayni soket icin tetiklenen tracepoint'te bulunuyor. Soket
 * CLOSE'a dustugunde siliniyor. */
struct conn_meta {
	__u64 ts_ns;
	__u64 cgroup_id;
	__u32 pid;
	__u32 tgid;
	__u32 retrans;
	char  comm[FM_COMM_LEN];
};

/* LRU, duz HASH degil: bir soket durum degisikligi tracepoint'i uretmeden
 * kaybolursa girdi sizar. LRU'da bu girdiler zamanla atilir; en kotu durumda
 * olay FM_FLAG_NO_META ile yayinlanir (uclu yine gecerli), harita dolup
 * guncellemeler basarisiz olmaz. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct conn_meta);
} conn_meta_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1 MiB */
} events SEC(".maps");

/* Ring buffer dolu oldugu icin ATILAN olay sayisi.
 *
 * Neden ayri bir sayac: kayipli bir olcum sessizce yanlis PMR uretir ve
 * yanlis oldugu belli olmaz. Bu sayac sifirdan buyukse gozlenen akis kumesi
 * eksik demektir; userspace bunu kapanista uyari olarak basiyor. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dropped SEC(".maps");

static __always_inline void count_drop(void)
{
	__u32 k = 0;
	__u64 *v = bpf_map_lookup_elem(&dropped, &k);
	if (v)
		__sync_fetch_and_add(v, 1);
}

/*
 * KANCA 1/3 — connect() giris noktasi.
 *
 * Tek isi, tracepoint'lerin erisemeyecegi gorev baglamini kaydetmek:
 * cgroup_id (pod eslestirmesi icin), pid/tgid ve comm. Bu degerler softirq
 * baglaminda okunamaz, bu yuzden burada yakalanip haritaya konuyor.
 *
 * Hedef adresi burada OKUMUYORUZ. uaddr'den okumak mumkun ama gereksiz:
 * soket henuz baglanmadi ve adresleri asagida inet_sock_set_state'te
 * sock'tan kesin degerleriyle aliyoruz.
 */
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(fm_tcp_v4_connect, struct sock *sk)
{
	__u64 key = (__u64)(unsigned long)sk;
	__u64 id  = bpf_get_current_pid_tgid();
	struct conn_meta m = {};

	m.ts_ns     = bpf_ktime_get_ns();
	m.cgroup_id = bpf_get_current_cgroup_id();
	m.tgid      = id >> 32;
	m.pid       = (__u32)id;
	bpf_get_current_comm(&m.comm, sizeof(m.comm));

	bpf_map_update_elem(&conn_meta_map, &key, &m, BPF_ANY);
	return 0;
}

/*
 * KANCA 2/3 — SYN yeniden iletimi. Projenin AYIRT EDICI sinyali.
 *
 * Yalnizca SYN_SENT durumundakiler sayiliyor. Ayrim kritik: kurulmus bir
 * baglantidaki retransmit siradan paket kaybidir ve hicbir sey ifade etmez;
 * SYN_SENT'teki ise "SYN gonderildi, hic cevap gelmedi" demektir.
 *
 * Bu sayac sayesinde userspace sessiz dusurmeyi (dropped) RST ile
 * reddedilmeden (refused) ayirabiliyor. Sayac olmasaydi iki durum
 * birbirinden ayirt edilemezdi -- ve kubectl'in yapamadigi sey tam olarak bu.
 */
SEC("tp_btf/tcp_retransmit_skb")
int BPF_PROG(fm_tcp_retransmit_skb, const struct sock *sk)
{
	__u64 key = (__u64)(unsigned long)sk;
	struct conn_meta *m;
	__u8 state;

	state = BPF_CORE_READ(sk, __sk_common.skc_state);
	if (state != FM_TCP_SYN_SENT)
		return 0;

	m = bpf_map_lookup_elem(&conn_meta_map, &key);
	if (m)
		__sync_fetch_and_add(&m->retrans, 1);
	return 0;
}

/*
 * KANCA 3/3 — denemenin sonucu ve olayin yayinlandigi yer.
 *
 * SYN_SENT'ten cikis iki yone olur:
 *   -> ESTABLISHED   el sikisma tamamlandi
 *   -> CLOSE         tamamlanmadi (sessiz dusurme ya da RST)
 *
 * IKISI DE raporlaniyor. Basarili baglantilari atlamak cazip gorunur ama
 * kapiyi bozar: gozlenen akis kumesi (§3.3) calisan trafigi de icermek
 * zorunda, yoksa kapi mesru akislari kapatan bir oneriyi gecirir -- projenin
 * UPR dedigi hata.
 *
 * Adresler burada sock'tan okunuyor cunku baglanti denemesi tamamlandigi
 * icin kesin degerleri artik belli.
 */
SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(fm_inet_sock_set_state, const struct sock *sk, int oldstate, int newstate)
{
	__u64 key = (__u64)(unsigned long)sk;
	struct conn_meta *m;
	struct flow_event *e;
	__u16 family, dport_be;

	if (oldstate != FM_TCP_SYN_SENT)
		goto cleanup;

	if (newstate != FM_TCP_ESTABLISHED && newstate != FM_TCP_CLOSE)
		return 0;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != FM_AF_INET) /* IPv6 henuz kapsam disi */
		goto cleanup;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		goto cleanup;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->ts_ns   = bpf_ktime_get_ns();
	e->family  = FM_AF_INET;
	e->verdict = (newstate == FM_TCP_ESTABLISHED) ? FM_VERDICT_ESTABLISHED
						      : FM_VERDICT_FAILED;

	e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	e->sport = BPF_CORE_READ(sk, __sk_common.skc_num); /* zaten host sirasi */
	dport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);
	e->dport = bpf_ntohs(dport_be);

	m = bpf_map_lookup_elem(&conn_meta_map, &key);
	if (m) {
		e->cgroup_id   = m->cgroup_id;
		e->pid         = m->pid;
		e->tgid        = m->tgid;
		e->retrans     = m->retrans;
		e->duration_ns = e->ts_ns - m->ts_ns;
		__builtin_memcpy(e->comm, m->comm, FM_COMM_LEN);
	} else {
		/* Soket biz kancalari takmadan once yaratilmis. Olayi atmiyoruz —
		 * uclu gecerli — ama pod eslestirmesi yapilamayacagini isaretliyoruz. */
		e->flags |= FM_FLAG_NO_META;
	}

	bpf_ringbuf_submit(e, 0);

cleanup:
	if (newstate == FM_TCP_CLOSE)
		bpf_map_delete_elem(&conn_meta_map, &key);
	return 0;
}
