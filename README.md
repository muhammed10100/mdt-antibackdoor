# 🛡️ MDT Anti-Backdoor & Malware Scanner v5.0

Professional security solution for FiveM servers to detect backdoors, RATs, and malicious code snippets.

---

## 🇹🇷 Türkçe Açıklama

Bu script, FiveM sunucularındaki kaynak dosyalarını (resources) analiz ederek gizli arka kapıları ve zararlı yazılımları tespit eder.

### 🚀 Özellikler
* **Geniş Kapsamlı Tarama:** Lua, JS ve HTML dosyaları için özel pattern eşleşmeleri.
* **Gelişmiş Tehdit Algılama:** Cipher, KVAC, Blum Panel ve thedreamoffivem gibi bilinen malware imzaları.
* **Anlık İzleme:** Sunucu konsoluna düşen şüpheli çıktıları gerçek zamanlı takip eder (Runtime Scanner).
* **Discord Raporlama:** Tespit edilen tehditleri detaylı bir şekilde Discord kanalınıza iletir.
* **Esnek Yapılandırma:** Güvenilir scriptleri beyaz listeye (Whitelist) ekleme imkanı.

### 🛠️ Kurulum
1. `config.lua` dosyasındaki `Config.DiscordWebhook` kısmına kendi webhook adresinizi yapıştırın.
2. `Config.AdminSystem` ayarını sunucunuzda kullandığınız admin sistemiyle uyumlu hale getirin.
3. `/scanbackdoor` komutu ile tam tarama başlatın.

---

## 🇺🇸 English Description

A comprehensive security tool designed to protect FiveM servers from malicious resources and data-theft scripts.

### 🚀 Features
* **Multi-Language Support:** Deep scanning for Lua, JavaScript, and HTML files.
* **Signature-Based Detection:** Identifies signatures for Cipher, KVAC, Blum Panel, and other common RATs.
* **Runtime Protection:** Real-time monitoring of server console logs for malicious execution patterns.
* **Discord Alerts:** Detailed reports sent via Webhook including severity levels and code snippets.
* **Auto-Scanning:** Periodic and startup scan options to keep your server safe 24/7.

### 🛠️ Setup
1. Paste your Discord Webhook URL into the `Config.DiscordWebhook` field in `config.lua`.
2. Ensure `Config.AdminSystem` matches your server's administrative framework.
3. Use the `/scanbackdoor` command to perform a full system audit.

---

## 📋 Technical Details / Teknik Detaylar
* **Version:** 5.0
* **Author:** MDT10100
* **Requirements:** Lua 5.4 support enabled via fxmanifest.
* **Commands:** `/scanbackdoor`, `/scanresource [name]`

## ⚠️ Legal Note / Yasal Not
**TR:** Bu araç sadece güvenlik denetimi amaçlıdır.
**EN:** This tool is intended for security auditing purposes only.

---
*Developed by MDT Yazılım Hizmetleri*
