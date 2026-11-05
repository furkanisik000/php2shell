# PHP2Shell Local Checker (unpacked extension)

`dldionfdhfhfdaaojoopdaadobkajdfc` (CWS "PHP Vulnerability Checker") extension'inin **local, offline, sertifikasiz** varyanti.
CWS surumu uzak API'ye (`the vendor cloud API`) + Google OAuth + billing'e bagimliydi ve **local host'lari reddediyordu**. Bu varyant hicbirine ihtiyac duymaz.

## Akis (v1.2)

1. Popup acilinca **aktif sekmenin URL'si otomatik alinir** (`activeTab`).
2. Hedef **canli fetch** edilir — `X-Powered-By` → `Server` → body sirasiyla PHP surumu cekilir.
   **IP/port degisse bile sorun degil: her seferinde hedefi yeniden sorar** (sabit host DB'si yok).
3. Cikan surum, **surum-tabanli yerel DB**'de (`data/db.json`) sorgulanir → php2shell risk notu.
4. Uzak API **yok**, auth **yok**, PostHog **yok**, CWS `key`/`update_url` **yok**.

## Kurulum (Load unpacked)

1. Chrome → `chrome://extensions`
2. Sag ustte **Developer mode**'u ac
3. **Load unpacked** → bu dizin: `<REPO_PATH>/local-checker-ext`
4. Bir PHP hedef sekmesindeyken (orn. `http://LAB_IP:18101`) toolbar ikonuna tikla → otomatik kontrol.

## Sertifika (ucertsiz)

- **Plain HTTP hedefler** (18101–18114, 18120): dogrudan calisir, sertifika gerekmez.
- **Self-signed HTTPS**: tarayici fetch'inde TLS dogrulamasi bypass edilemez → hata `http://` kullanmayi soyler.
- Gecerli sertifikali uzak hedefler calisir.

## Veri: `data/db.json` (tek duzenleme noktasi)

```jsonc
{
  "cve": "CVE-2026-109618/19 (php2shell)",
  "rules":  { "eolBefore": [8,2], "fixedBranch": null },   // map'te olmayan branch'ler icin fallback
  "versions": {                                            // branch (major.minor) -> durum
    "8.4": { "status": "POTENTIAL_RISK", "note": "..." },
    "8.6": { "status": "CONFIRMED_FIXED", "note": "..." }  // fixed branch dogrulaninca ekle
  }
}
```

- **Surum tespiti kurala bagimli degil** — her zaman dogru surumu canli gosterir.
- Risk etiketi `versions[branch]`'ten gelir; branch yoksa `rules` fallback'i devreye girer.
- `status` degerleri: `EOL_NO_PATCH`, `POTENTIAL_RISK`, `CONFIRMED_FIXED`, `DISTRO_BUILD`, `NO_KNOWN_INDICATORS`.

## Dosyalar

| Dosya | Gorev |
|---|---|
| `manifest.json` | MV3 — `storage` + `activeTab` + host `http/https://*/*` |
| `data/db.json` | **Surum-tabanli risk DB'si** (duzenlenecek yer) |
| `lib/version.js` | surum parse + rule skorlama (saf fonksiyonlar) |
| `lib/check.js` | hedef canli probe (timeout, hata mesajlari, probe path'leri) |
| `lib/lookup.js` | db.json surum sorgulama |
| `popup.html/css/js` | UI |

## Dogrulama (Node, gercek hedefler — 2026-10-24)

```
LAB_IP:18101 → PHP/5.4.45  (X-Powered-By) → EOL_NO_PATCH
LAB_IP:18113 → PHP/8.4.26  (X-Powered-By) → POTENTIAL_RISK (baseline)
LAB_IP:18120 → PHP/8.4.26  (Server header) → POTENTIAL_RISK
```
