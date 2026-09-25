/* SPDX-License-Identifier: GPL-2.0 */
/*
 * flowmon.h — cekirdek ile userspace arasindaki olay sozlesmesi.
 *
 * NE ISE YARIYOR
 *
 * Cekirdekteki eBPF programi ile Go tarafinin uzerinde anlastigi TEK yapi
 * bu. Aralarinda serilestirme yok: cekirdek asagidaki struct'i ham olarak
 * ring buffer'a yaziyor, Go tarafi internal/flow/event.go icinde ayni
 * offsetlerden elle okuyor.
 *
 * NEDEN SERILESTIRME YOK
 *
 * Hiz. Olaylar softirq baglaminda uretiliyor ve saniyede binlerce olabilir;
 * JSON ya da protobuf kodlamasi cekirdek tarafinda hem pahali hem de BPF
 * verifier acisindan sorunlu olurdu.
 *
 * BEDELI: bu dosya ile event.go BIRLIKTE degismek zorunda. Kayarlarsa
 * program hata VERMEZ -- sessizce yanlis veri uretir. Iki koruma var:
 *   1) FLOW_EVENT_SIZE sabiti Go tarafinda EventSize ile karsilastiriliyor
 *   2) internal/flow/event_test.go yerlesimi bayt bayt kilitliyor
 *
 * Alan ekler/cikarirsaniz ucunu de guncelleyin.
 */
#ifndef __FLOWMON_H
#define __FLOWMON_H

#define FM_COMM_LEN 16

/* connect() denemesinin nasil sonuclandigi.
 *
 * Dikkat: burada YALNIZCA iki deger var, ucu degil. Cekirdek "el sikisma
 * tamamlandi mi" sorusunu cevapliyor; bunun sessiz dusurme mu yoksa RST mi
 * oldugu (dropped/refused ayrimi) userspace'te retrans sayacina bakilarak
 * belirleniyor. Gerekcesi internal/flow/event.go basinda. */
enum fm_verdict {
	FM_VERDICT_ESTABLISHED = 0, /* SYN_SENT -> ESTABLISHED */
	FM_VERDICT_FAILED      = 1, /* SYN_SENT -> CLOSE (el sikisma tamamlanmadi) */
};

/* flags
 *
 * FM_FLAG_NO_META: soket, biz kancalari takmadan ONCE yaratilmis. Boyle bir
 * sokette cgroup_id/pid/comm alanlari doldurulamaz (kprobe hic tetiklenmedi).
 * Olay yine de yayinlaniyor -- (kaynak, hedef, port) uclusu gecerli ve akis
 * kumesi icin yeterli -- ama pod eslestirmesi yapilamayacagi isaretleniyor.
 * Alternatif olan "olayi tamamen atmak" akis kumesini eksik birakirdi. */
#define FM_FLAG_NO_META (1 << 0)

struct flow_event {
	__u64 ts_ns;       /* olayin cekirdek zamani (bpf_ktime_get_ns) */
	__u64 cgroup_id;   /* connect() cagiran gorevin cgroup v2 id'si */
	__u64 duration_ns; /* connect() basi ile sonucu arasindaki sure */
	__u32 pid;         /* thread id */
	__u32 tgid;        /* process id */
	__u32 saddr;       /* IPv4, network byte order */
	__u32 daddr;       /* IPv4, network byte order */
	__u32 retrans;     /* SYN_SENT sirasinda gorulen yeniden iletim sayisi */
	__u16 sport;       /* host byte order */
	__u16 dport;       /* host byte order */
	__u8  verdict;     /* enum fm_verdict */
	__u8  family;      /* 2 = AF_INET */
	__u8  flags;
	__u8  _pad;
	char  comm[FM_COMM_LEN];
	__u8  _pad2[4];    /* 8-bayt hizalamayi acikca tamamlar */
};

/* Struct'in derleyici dolgusu dahil toplam boyutu. Go tarafi bu degeri
 * dogruluyor; uyusmazsa okuma offsetleri kaymis demektir. */
#define FLOW_EVENT_SIZE 72

#endif /* __FLOWMON_H */
