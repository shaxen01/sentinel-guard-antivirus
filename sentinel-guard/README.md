# 🛡️ Sentinel Guard — Real Antivirus Engine

Python tabanlı gerçek antivirüs motoru. Signature-based ve heuristic tespit yöntemleri kullanır.

## Özellikler

### 🔍 Tarama Motoru
- **Signature-based tespit** — SHA256 hash veritabanı (SQLite)
- **Heuristic analiz** — Shannon entropy, şüpheli string taraması, PE dosya analizi
- **Dosya uzantı kontrolü** — Çift uzantı tespiti (`.pdf.exe`, `.jpg.scr`)
- **Extension mismatch** — İçeriği executable olan fake image/dosya tespiti
- **PE dosya analizi** — Şüpheli section'lar, anomali tespiti
- **Boyut analizi** — Anormal boyutlu dosyalar

### 🔒 Karantina Sistemi
- Enfekte dosyaları güvenli konuma taşır
- Orijinal dosyayı siler, karantinaya kopyalar
- Geri yükleme ve kalıcı silme desteği
- JSON metadata ile karantina takibi

### 👁️ Gerçek Zamanlı İzleme
- Dosya sistemi polling (harici bağımlılık yok)
- Yeni/modifye edilmiş dosyaları otomatik tarama
- Tehdit tespitinde otomatik karantina
- Thread-based arka plan çalışması

### 📡 İmza Güncelleme
- MalwareBazaar API'den otomatik imza çekme
- CSV/JSON imza dosyası import
- SQLite veritabanı yönetimi

### 📄 Raporlama
- TXT formatında detaylı tarama raporu
- Tehdit listesi, risk seviyeleri, heuristic flag'ler

## Kurulum

```bash
# Harici bağımlılık yok — sadece Python 3.8+
git clone https://github.com/shaxen01/sentinel-guard-antivirus.git
cd sentinel-guard-antivirus/sentinel-guard

# İsteğe bağlı: pip install -e .  (CLI komutu olarak kurar)
```

## Kullanım

```bash
# Dizin tara
python main.py scan ~/Downloads

# Otomatik karantina ile tara
python main.py scan ~/Downloads --auto-quarantine

# Tek dosya tara
python main.py scan ./suspicious.exe

# Gerçek zamanlı izleme başlat
python main.py monitor ~/Downloads --interval 1.0

# İmza veritabanını güncelle (MalwareBazaar)
python main.py update --limit 100

# Dosya hash'ini hesapla ve kontrol et
python main.py hash ./file.exe

# EICAR test dosyası oluştur ve motoru doğrula
python main.py eicar

# Karantina yönetimi
python main.py quarantine list
python main.py quarantine restore <id>
python main.py quarantine delete <id>
python main.py quarantine clear

# Veritabanı istatistikleri
python main.py stats
```

## Mimari

```
sentinel-guard/
├── main.py                # CLI giriş noktası
├── engine/
│   ├── scanner.py         # Çekirdek tarama motoru
│   ├── signatures.py      # SQLite imza veritabanı yöneticisi
│   ├── heuristics.py       # Heuristic analiz motoru
│   ├── quarantine.py       # Karantina yöneticisi
│   └── monitor.py         # Gerçek zamanlı dosya izleme
├── utils/
│   ├── hasher.py           # Dosya hash hesaplama (SHA256, MD5, SHA1)
│   └── logger.py           # Renkli log çıktısı
├── data/                   # Çalışma dizini (otomatik oluşur)
│   ├── signatures.db       # SQLite imza veritabanı
│   └── quarantine/         # Karantina klasörü
├── reports/                # Tarama raporları (otomatik oluşur)
├── requirements.txt
└── setup.py
```

## Tespit Yöntemleri

### 1. Signature-Based (Hash Eşleştirme)
Dosyanın SHA256 hash'i veritabanındaki bilinen malware hash'leri ile karşılaştırılır. Hızlı ve kesin tespit sağlar.

### 2. Heuristic Analiz
Bilinmeyen tehditleri tespit etmek için davranışsal analiz:
- **Shannon Entropy** — Yüksek entropy, packed/şifrelenmiş dosya işareti
- **Şüpheli String Tarama** — PowerShell injection, Meterpreter, keylogger, ransomware belirtileri
- **Extension Mismatch** — `.jpg` ama içerik executable gibi
- **Çift Uzantı** — `photo.pdf.exe` gibi sosyal mühendislik taktikleri
- **PE Analiz** — Şüpheli section isimleri (VMProtect, UPX, Themida)
- **Boyut Anomalisi** — Çok küçük executable'lar veya çok büyük script'ler

## EICAR Test

Motorun çalıştığını doğrulamak için:
```bash
python main.py eicar
```
Bu komut standart EICAR test dosyasını oluşturur ve motorun tespit edip etmediğini kontrol eder.

## İmza Güncelleme

```bash
# MalwareBazaar'dan son 100 imzayı çek
python main.py update --limit 100

# Kendi imza dosyanı import et (CSV)
python main.py import signatures.csv
```

## Gereksinimler
- Python 3.8+
- Harici bağımlılık yok (sadece standart kütüphane)

## Not
Bu motor gerçek malware tespiti yapar ancak ticari antivirüslerin milyonlarca imzasına sahip değildir. İmza veritabanını MalwareBazaar API ile güncelleyerek genişletebilirsiniz. YARA rule desteği eklenebilir.

## Lisans
MIT

---
Built with Base44 Superagent.
