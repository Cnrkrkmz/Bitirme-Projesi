#!/usr/bin/env bash
# Senaryo 3 — VE/VEYA HATASI (NetworkPolicy'nin en bilinen tuzagi)
#
# allow-api-app politikasinda iki secici AYNI liste ogesine yaziliyor:
#
#     from:                          from:
#       - namespaceSelector: A         - namespaceSelector: A
#         podSelector: B               - podSelector: B
#     -> A VE B                      -> A VEYA B
#
# Niyet "frontend pod'lari VEYA monitoring namespace'i" idi; sonuc
# "monitoring namespace'indeki frontend pod'lari" oldu. Boyle bir pod yok.
# Goz bunu yakalayamaz, kubectl uyarmaz.
#
# Kesilen:  frontend -> api:18080     Diger iki baglanti calismaya devam eder.
source "$(dirname "$0")/lib.sh"
run_scenario 33-break-and-or.yaml allow-api-app 18080 \
	"frontend -> api:18080" \
	"iki secici ayni ogede -> VE ile birlesti, hicbir pod iki kosulu birden saglamiyor"
