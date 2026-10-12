#!/usr/bin/env bash
# demo/ebpf-stream.sh — cekirdegin HAM olay akisi. Demoyla yan yana calistirilir.
#
#   Terminal 1:  ./demo/ebpf-stream.sh 19090      (izlenecek port; bos = uc port)
#   Terminal 2:  ./demo/1-etiket-hatasi.sh
#
#   Demo -> port:  1-etiket-hatasi 19090   2-port-hatasi 18081   3-ve-veya-hatasi 18080
#
# NE GOSTERIYOR
#
# Demo scriptleri flowmon'un YORUMLANMIS ciktisini gosterir: "DROPPED".
# Bu script ise o karara giden HAM cekirdek olaylarini, olduklari anda basar:
#
#   CONNECT     uygulama connect() cagirdi             (kprobe: tcp_v4_connect)
#   RETRANSMIT  SYN'e cevap gelmedi, cekirdek tekrar   (tracepoint: tcp_retransmit_skb)
#               gonderiyor
#   DROP        SYN paketi cekirdekte atildi + SEBEBI  (tracepoint: skb:kfree_skb)
#   STATE       TCP durum degisikligi                  (tracepoint: inet_sock_set_state)
#               SYN_SENT -> ESTABLISHED  ya da  -> CLOSE
#
# flowmon bu olaylarin ilk ucunu kullaniyor (DROP sebebi henuz flowmon'da
# yok; burada gorunen TC_EGRESS gibi sebepler ileride eklenecek alan).
#
# NASIL CALISIYOR
#
# bpftrace ile yazilmis kucuk bir eBPF programi. flowmon'dan BAGIMSIZ: ayri
# bir program, ayni cekirdek noktalarina takiliyor. Yani ekranda iki farkli
# eBPF programinin ayni olaylari gordugunu izlersiniz. Yalnizca demo
# portlarindaki (18080, 18081, 19090) olaylar basiliyor; IP'ler pod adlarina
# cevriliyor. Ctrl-C ile durur, program cekirdekten sokulur.
set -uo pipefail

NS=agentic-sre
PORTS=${1:-18080,18081,19090}
# bpftrace kosulu: "$p == 18080 || $p == 18081 ..." -- her probe icin uretiliyor
cond() { local v=$1 o="" x; for x in ${PORTS//,/ }; do o+="${o:+ || }$v == $x"; done; echo "$o"; }
command -v bpftrace >/dev/null || { echo "bpftrace yok: sudo apt install bpftrace"; exit 1; }
sudo -n true 2>/dev/null || sudo -v || exit 1

# IP -> pod adi cevirisi icin sed ifadesi. Pod'lar yeniden baslarsa IP'ler
# degisir; script baslarken bir kez okunuyor.
MAP=$(kubectl get pods -n "$NS" -o jsonpath='{range .items[*]}{.status.podIP}{" "}{.metadata.name}{"\n"}{end}' 2>/dev/null |
	awk 'NF==2{gsub(/\./,"\\.",$1); printf "s/\\<%s\\>/%s/g;", $1, $2}')

B=$'\e[1m'; N=$'\e[0m'
printf '%seBPF cekirdek akisi%s  (port: %s -- Ctrl-C ile cik)\n' "$B" "$N" "${PORTS//,/ }"
printf '%-12s %-11s %s\n' "ZAMAN" "OLAY" "AYRINTI"
printf '%.0s-' {1..78}; echo

sudo bpftrace -B line -q -e "

BEGIN { @st[1]=\"ESTABLISHED\"; @st[2]=\"SYN_SENT\"; @st[7]=\"CLOSE\"; }

/* 1) Uygulama connect() cagirdi. Hedef adres henuz sokette degil, cagrinin
 *    ikinci argumanindan (sockaddr_in) okunuyor. */
kprobe:tcp_v4_connect {
	\$sa = (struct sockaddr_in *)arg1;
	\$p = bswap(\$sa->sin_port);
	if ($(cond \$p)) {
		printf(\"%s  \\033[36mCONNECT\\033[0m     %s (pid %d) -> %s:%d\\n\",
			strftime(\"%H:%M:%S\", nsecs), comm, pid, ntop(\$sa->sin_addr.s_addr), \$p);
	}
}

/* 2) SYN yeniden iletimi: cevap gelmedi. Sessiz dusurmenin cekirdekteki izi. */
tracepoint:tcp:tcp_retransmit_skb
/ ($(cond args.dport)) && args.state == 2 /
{
	printf(\"%s  \\033[33mRETRANSMIT\\033[0m  %s -> %s:%d   SYN cevapsiz, tekrar gonderiliyor\\n\",
		strftime(\"%H:%M:%S\", nsecs), ntop(args.saddr), ntop(args.daddr), args.dport);
}

/* 3) Paket cekirdekte atildi. Tracepoint adres tasimiyor; adresi ve portu
 *    paketin kendi basliklarindan okuyoruz. reason = cekirdegin drop sebebi. */
tracepoint:skb:kfree_skb {
	\$skb = (struct sk_buff *)args.skbaddr;
	\$ip = (struct iphdr *)(\$skb->head + \$skb->network_header);
	if (\$ip->protocol == 6) {
		\$th = (struct tcphdr *)(\$skb->head + \$skb->transport_header);
		\$p = bswap(\$th->dest);
		/* Yalnizca SYN: baglanti denemesini kesen dusus. Kapanista kuyrugun
		 * bosaltilmasi (QUEUE_PURGE) gibi normal atilmalar boylece eleniyor. */
		if (\$th->syn == 0 || \$th->ack == 1) { return; }
		if ($(cond \$p)) {
			printf(\"%s  \\033[31mDROP\\033[0m        %s -> %s:%d   sebep: %s\\n\",
				strftime(\"%H:%M:%S\", nsecs), ntop(\$ip->saddr), ntop(\$ip->daddr), \$p, args.reason);
		}
	}
}

/* 4) Denemenin sonucu: SYN_SENT durumundan cikis. */
tracepoint:sock:inet_sock_set_state
/ args.protocol == 6 && args.oldstate == 2 &&
  ($(cond args.dport)) /
{
	\$col = args.newstate == 1 ? \"\\033[32m\" : \"\\033[31m\";
	printf(\"%s  %sSTATE\\033[0m       %s -> %s:%d   SYN_SENT -> %s%s\\033[0m\\n\",
		strftime(\"%H:%M:%S\", nsecs), \$col, ntop(args.saddr), ntop(args.daddr), args.dport,
		\$col, @st[args.newstate]);
}

END { clear(@st); }
" 2>&1 | sed -u "$MAP; s/SKB_DROP_REASON_//"
