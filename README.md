# 🛡️ Sentinel Guard — Antivirüs

Next-Gen tehdit koruması içeren interaktif antivirüs web uygulaması.

## Özellikler

### Ana Ekran
- **İnsansı Avatar** — Sağa sola şüpheli bakışlar atan, göz kırpıp kaş çatan animasyonlu yüz
- **Gizli Hareket** — Telefonu sallayınca başını iki yana sallar ve "başımı döndürdün dostum dikkatli ol" der
- **Güvenlik Skoru** — 0-100 arası halka gösterge
- **Firewall Görselleştirme** — Canlı trafik izleme barları
- **Gerçek Zamanlı Koruma** — Aç/kapa anahtarı

### Tarama
- 3 mod: Hızlı, Derin, Özel tarama
- Gerçek zamanlı log akışı + radar animasyonu
- Dosya sayacı ve ilerleme çubuğu

### Oyun — Uzay Savunması 🚀
- Tarama sırasında oynanabilir space shooter
- 5 farklı düşman tipi + Boss düşman (her 5. dalgada)
- Power-up'lar: Kalkan, Hızlı ateş, Üçlü atış, Ekstra can
- Combo sistemi ve dalga ilerlemesi
- Başarım rozetleri

### Sonuçlar
- Tehdit listesi (risk seviyesi, dosya yolu)
- "Temizlensin mi?" → Evet/Hayır butonları
- TXT rapor indirme
- Temizleme animasyonu (karantina, onarım)

### Ek Özellikler
- **Tarama Geçmişi** — localStorage ile saklanır
- **Karantina** — Temizlenen tehditler karantinaya alınır, tek tek silinebilir
- **Ayarlar** — Ses, titreşim, otomatik tarama, bulut koruması toggles
- **Ses Efektleri** — Web Audio API ile prosedürel sesler
- **Haptic Feedback** — Vibration API
- **Arka plan parçacıkları** — Animasyonlu dot grid

## Kullanım

Tek dosya — herhangi bir tarayıcıda aç. Mobil cihazda en iyi çalışır (sallama için).

## Teknoloji

Vanilla HTML/CSS/JS — bağımlılık yok. SVG avatar, Canvas game, Web Audio API, DeviceMotion API, localStorage.

---

Built with Base44 Superagent.
