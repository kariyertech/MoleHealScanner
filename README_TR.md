# MoleHealScanner - Gelişmiş Güvenlik Tarayıcısı

[![English](https://img.shields.io/badge/lang-English-blue.svg)](README.md) [![Turkish](https://img.shields.io/badge/lang-Türkçe-red.svg)](README_TR.md)
<p align="center">
  <img src="./mascot.png" alt="Logo">
</p>
MoleHealScanner, kod tabanlarında hassas veri desenlerini tespit etmek için tasarlanmış gelişmiş bir güvenlik tarama aracıdır. Paralel işleme yetenekleri ve güvenlik metrikleri ve görselleştirmeleri içeren ayrıntılı, etkileşimli HTML raporları sunar.

## Özellikler

### Tarama Yetenekleri
- Tüm CPU çekirdeklerini kullanan çok iş parçacıklı tarama
- Aşağıdakileri içeren 250+ hassas veri deseninin kapsamlı tespiti:
  - Kriptografik Anahtarlar (RSA, DSA, EC, PGP)
  - Bulut Hizmeti Kimlik Bilgileri (AWS, GCP, Azure)
  - API Anahtarları ve Erişim Jetonları
  - OAuth Kimlik Bilgileri
  - Ödeme Sistemi Anahtarları (Stripe, PayPal, Square)
  - Veritabanı Bağlantı Dizeleri
  - Platforma Özel Jetonlar (GitHub, GitLab, Slack)
- Akıllı dosya filtreleme (.ttf, .png gibi ikili dosyaları hariç tutar)
- Yanlış pozitifleri azaltmak için Shannon entropi analizi

### Güvenlik Raporlama
<div align="center">
<img src="https://i.imgur.com/8Wmgszn.png" align="center" style="width: 100%" alt="PNG" />
</div> 

<p></p>

- Şunları içeren etkileşimli HTML raporları:
  - Genel Güvenlik Puanı (0-100)
  - Risk Seviyesi Değerlendirmesi
  - Etkileşimli Veri Filtreleme
  - Önem Derecesi Dağılım Grafikleri
  - Kategorize Edilmiş Bulgu Görünümleri
  - Arama İşlevselliği
  - Ayrıntılı Kod Parçacıkları

### Önem Derecesi Sınıflandırması
- **Kritik** (Seviye 4): En yüksek risk taşıyan kimlik bilgileri (özel anahtarlar, ödeme jetonları)
- **Yüksek** (Seviye 3): Hizmet hesabı jetonları, platform erişim anahtarları
- **Orta** (Seviye 2): Genel API anahtarları, web kancaları
- **Düşük** (Seviye 1): Hassas olmayan URL'ler, genel desenler

### Yanlış Pozitif Azaltma
- **Entropi Analizi**: Her potansiyel sır için rastgeleliği ölçmek amacıyla Shannon entropisi hesaplar
- Düşük entropili eşleşmeleri elemek için entropi eşik filtreleme (varsayılan: 3.5)
- Daha yüksek entropi değerleri, gerçek sırlar olma olasılığı daha yüksek olan daha rastgele dizeleri gösterir

## Kullanım
```bash
go run main.go <dizin_yolu> --report
```
## Teşekkürler

@DevSecOps Team
