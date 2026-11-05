# PHP2Shell Local Checker (unpacked extension)

`dldionfdhfhfdaaojoopdaadobkajdfc` (CWS "PHP Vulnerability Checker") extension'ının **local, offline, sertifikasız** varyantı.
CWS sürümü uzak API'ye (`api.getpickads.com`) + Google OAuth + billing'e bağımlıydı ve **local host'ları reddediyordu**. Bu varyant hiçbirine ihtiyaç duymaz.

## Akış (v1.2)

1. Popup açılınca **aktif sekmenin URL'si otomatik alınır** (`activeTab`).
2. Hedef **canlı fetch** edilir — `X-Powered-By` → `Server` → body sırasıyla PHP sürümü çekilir.
   **IP/port değişse bile sorun değil: her seferinde hedefi yeniden sorar** (sabit host DB'si yok).
3. Çıkan sürüm, **sürüm-tabanlı yerel DB**'de (`data/db.json`) sorgulanır → php2shell risk notu.
4. Uzak API **yok**, auth **yok**, PostHog **yok**, CWS `key`/`update_url` **yok**.

## Kurulum (Load unpacked)

1. Chrome → `chrome://extensions`
2. Sağ üstte **Developer mode**'ü aç
3. **Load unpacked** → bu dizin: `/Users/emredagdelen/Desktop/php2shell/local-checker-ext`
4. Bir PHP hedef sekmesindeyken (örn. `http://192.168.8.123:18101`) toolbar ikonuna tıkla → otomatik kontrol.

## Sertifika (ücertsiz)

- **Plain HTTP hedefler** (18101–18114, 18120): doğrudan çalışır, sertifika gerekmez.
- **Self-signed HTTPS**: tarayıcı fetch'inde TLS doğrulaması bypass edilemez → hata `http://` kullanmayı söyler.
- Geçerli sertifikalı uzak hedefler çalışır.

## Veri: `data/db.json` (tek düzenleme noktası)

```jsonc
{
  "cve": "CVE-2026-109618/19 (php2shell)",
  "rules":  { "eolBefore": [8,2], "fixedBranch": null },   // map'te olmayan branch'ler için fallback
  "versions": {                                            // branch (major.minor) -> durum
    "8.4": { "status": "POTENTIAL_RISK", "note": "..." },
    "8.6": { "status": "CONFIRMED_FIXED", "note": "..." }  // fixed branch dogrulaninca ekle
  }
}
```

- **Sürüm tespiti kurala bağımlı değil** — her zaman doğru sürümü canlı gösterir.
- Risk etiketi `versions[branch]`'ten gelir; branch yoksa `rules` fallback'i devreye girer.
- `status` değerleri: `EOL_NO_PATCH`, `POTENTIAL_RISK`, `CONFIRMED_FIXED`, `DISTRO_BUILD`, `NO_KNOWN_INDICATORS`.

## Dosyalar

| Dosya | Görev |
|---|---|
| `manifest.json` | MV3 — `storage` + `activeTab` + host `http/https://*/*` |
| `data/db.json` | **Sürüm-tabanlı risk DB'si** (düzenlenecek yer) |
| `lib/version.js` | sürüm parse + rule skorlama (saf fonksiyonlar) |
| `lib/check.js` | hedef canlı probe (timeout, hata mesajları, probe path'leri) |
| `lib/lookup.js` | db.json sürüm sorgulama |
| `popup.html/css/js` | UI |

## Doğrulama (Node, gerçek hedefler — 2026-10-24)

```
192.168.8.123:18101 → PHP/5.4.45  (X-Powered-By) → EOL_NO_PATCH
192.168.8.123:18113 → PHP/8.4.26  (X-Powered-By) → POTENTIAL_RISK (baseline)
192.168.8.123:18120 → PHP/8.4.26  (Server header) → POTENTIAL_RISK
```
