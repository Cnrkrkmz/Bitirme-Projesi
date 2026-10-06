#!/usr/bin/env bash
# Senaryo 2 — PORT HATASI
#
# allow-api-admin politikasinda port numarasi yanlis yaziliyor:
#     port: 18081   ->   port: 18082
# Kaynak dogru, hedef dogru, yalnizca port yanlis. Senaryo 1'den farkli bir
# kok neden: duzeltmesi de farkli olmali.
#
# Kesilen:  frontend -> api:18081     Diger iki baglanti calismaya devam eder.
source "$(dirname "$0")/lib.sh"
run_scenario 32-break-port.yaml allow-api-admin 18081 \
	"frontend -> api:18081" \
	"port: 18081  ->  port: 18082   (kimse 18082'yi dinlemiyor, 18081 kapandi)"
