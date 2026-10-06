#!/usr/bin/env bash
# Senaryo 1 — ETIKET HATASI
#
# allow-store-data politikasinda kaynak etiketi yanlis yaziliyor:
#     app: api   ->   app: api-v2
# Kural duruyor ve YAML gecerli, ama artik hicbir gercek pod'a uymuyor.
# En sik gorulen hata: biri pod'un etiketini degistirir, politikayi unutur.
#
# Kesilen:  api -> store:19090        Diger iki baglanti calismaya devam eder.
source "$(dirname "$0")/lib.sh"
run_scenario 31-break-selector.yaml allow-store-data 19090 \
	"api -> store:19090" \
	"app: api  ->  app: api-v2   (boyle bir pod yok, kural kimseye uymuyor)"
