SELF_RESOURCE = GetCurrentResourceName()

Config = {}
Config.ScanOnStart = true
Config.ScanInterval = 3600
Config.AdminSystem = "stabil-admin"
Config.DiscordWebhook = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
Config.CheckSymbol = false -- @ sembolü kontrolünü açar/kapatır

Config.WhitelistResources = {
    ["[cfx-default]"] = true,
    ["[system]"] = true,
    ["[managers]"] = true,
    ["[builders]"] = true,
    ["monitor"] = true,
    ["sessionmanager"] = true,
    ["spawnmanager"] = true,
    ["mapmanager"] = true,
    ["hardcap"] = true,
    ["chat"] = true,
    ["yarn"] = true,
    ["runcode"] = true,
    ["oxmysql"] = true,
    ["ox_lib"] = true,
    ["cache"] = true,
    ["qb-core"] = true,
    ["qb-target"] = true,
    ["connectqueue"] = true,
    ["rconlog"] = true,
    ["meta_libsv2"] = true,
    ["baseevents"] = true,
    ["menuv"] = true,
    ["pma-voice"] = true,
    [SELF_RESOURCE] = true,
}

Config.WhitelistPaths = {
    "node_modules",
    "yarn_cli.js",
    "jquery",
    "materialize",
}

-- =============================
-- LUA PATTERN'LAR
-- =============================
Config.LUA_BAD_PATTERNS = {
    -- Dinamik kod calistirma
    { pattern = "loadstring",                                             severity = "KRITIK", desc = "loadstring ile dinamik kod calistirma", color = "^1" },
    { pattern = "assert%s*%(%s*load",                                     severity = "KRITIK", desc = "Cipher Panel imzasi: assert(load(d))", color = "^1" },
    { pattern = "pcall%s*%(%s*function%s*%(%s*%)%s*assert%s*%(%s*load",   severity = "KRITIK", desc = "Cipher Panel: pcall(function() assert(load(d))() end)", color = "^1" },
    { pattern = "pcall%s*%(%s*load",                                      severity = "YUKSEK", desc = "pcall ile korunan dinamik load", color = "^1" },
    { pattern = "load%s*%(\"",                                            severity = "YUKSEK", desc = "load() fonksiyonuna direkt string girisi", color = "^1" },
    { pattern = "load%s*%(base64",                                        severity = "KRITIK", desc = "Base64 kodlanmis load() cagrisi", color = "^1" },

    -- Cipher Panel spesifik imzalar
    { pattern = "cipher%-panel%.me",                                      severity = "KRITIK", desc = "Cipher Panel C2 sunucusu tespit edildi", color = "^1" },
    { pattern = "cipher%-panel%.xyz",                                     severity = "KRITIK", desc = "Cipher Panel domain tespit edildi", color = "^1" },
    { pattern = "blum%-panel",                                            severity = "KRITIK", desc = "Blum Panel RAT imzasi tespit edildi", color = "^1" },
    { pattern = "_i/i%?to=",                                              severity = "KRITIK", desc = "Cipher Panel benzersiz endpoint imzasi", color = "^1" },
    { pattern = "str_utf8%s*%()",                                         severity = "KRITIK", desc = "Cipher Panel hex decoder fonksiyonu", color = "^1" },
    { pattern = "enchanced_tabs",                                         severity = "KRITIK", desc = "Cipher Panel obfuscation tablo imzasi", color = "^1" },
    { pattern = "random_char%s*=%s*{",                                    severity = "KRITIK", desc = "Cipher Panel hex char array imzasi", color = "^1" },
    { pattern = "helpcode",                                               severity = "KRITIK", desc = "Bilinen RAT payload anahtar kelimesi", color = "^1" },
    { pattern = "inject%s*%(",                                            severity = "KRITIK", desc = "Inject fonksiyon cagrisi tespit edildi", color = "^1" },

    -- HTTP + load kombinasyonu (en tehlikeli)
    { pattern = "PerformHttpRequest.+function.+load",                     severity = "KRITIK", desc = "HTTP istegi + load() kombinasyonu (RAT pattern)", color = "^1" },
    { pattern = "PerformHttpRequest.+assert.+load",                       severity = "KRITIK", desc = "HTTP istegi + assert(load) kombinasyonu", color = "^1" },
    { pattern = "PerformHttpRequest.+pcall.+load",                        severity = "KRITIK", desc = "HTTP istegi + pcall(load) kombinasyonu", color = "^1" },

    -- Sistem erisimi
    { pattern = "os%.execute",                                            severity = "KRITIK", desc = "os.execute ile sistem komutu calistirma", color = "^1" },
    { pattern = "io%.popen",                                              severity = "KRITIK", desc = "io.popen ile sistem erisimi", color = "^1" },
    { pattern = "io%.open",                                               severity = "YUKSEK", desc = "io.open ile dosya sistemi erisimi", color = "^1" },
    { pattern = "os%.getenv",                                             severity = "YUKSEK", desc = "os.getenv ile sistem degiskeni okuma", color = "^1" },

    -- Ag olaylari
    { pattern = "PerformHttpRequest",                                     severity = "BILGI",  desc = "Disariya HTTP istegi gonderiliyor", color = "^5" },
    { pattern = "RegisterNetEvent",                                       severity = "DUSUK",  desc = "Ag olayi kaydediliyor", color = "^5" },
    { pattern = "TriggerServerEvent",                                     severity = "DUSUK",  desc = "Sunucu olayi tetikleniyor", color = "^5" },
    { pattern = "TriggerEvent",                                           severity = "DUSUK",  desc = "Olay tetikleniyor", color = "^5" },

    -- Webhook / veri sizintisi
    { pattern = "discord%.com/api/webhooks",                              severity = "ORTA",   desc = "Discord webhook URL tespit edildi", color = "^3" },
    { pattern = "hooks%.slack%.com",                                      severity = "KRITIK", desc = "Slack webhook URL tespit edildi", color = "^1" },
    { pattern = "t%.me/",                                                 severity = "YUKSEK", desc = "Telegram linki tespit edildi", color = "^1" },
    { pattern = "ngrok%.io",                                              severity = "KRITIK", desc = "ngrok tunel adresi tespit edildi", color = "^1" },
    { pattern = "requestbin%.com",                                        severity = "KRITIK", desc = "RequestBin veri yakalama servisi", color = "^1" },
    { pattern = "pipedream%.net",                                         severity = "KRITIK", desc = "Pipedream veri yakalama servisi", color = "^1" },
    { pattern = "webhook%.site",                                          severity = "KRITIK", desc = "Webhook.site veri yakalama servisi", color = "^1" },
    { pattern = "pastebin%.com",                                          severity = "KRITIK", desc = "Pastebin uzak kod kaynagi", color = "^1" },
    { pattern = "raw%.githubusercontent%.com",                            severity = "YUKSEK", desc = "GitHub raw dosya cagrisi (uzak kod yukleme riski)", color = "^1" },
    { pattern = "hastebin%.com",                                          severity = "YUKSEK", desc = "Hastebin uzak kod kaynagi", color = "^1" },

    -- Global tablo manipulasyonu
    { pattern = "rawget%s*%(%s*_G",                                       severity = "YUKSEK", desc = "Global tablo ham okuma islemi", color = "^1" },
    { pattern = "rawset%s*%(%s*_G",                                       severity = "YUKSEK", desc = "Global tabloya ham yazma islemi", color = "^1" },
    { pattern = "_G%s*%[",                                                severity = "ORTA",   desc = "Global tabloya kose parantez erisimi", color = "^3" },

    -- RCON sifre okuma
    { pattern = "GetConvar%s*%(%s*['\"]rcon_password",                    severity = "KRITIK", desc = "RCON sifresi okunuyor (veri hirsizligi)", color = "^1" },
    { pattern = "GetConvar%s*%(%s*['\"]sv_licensekey",                    severity = "KRITIK", desc = "Lisans anahtari okunuyor (veri hirsizligi)", color = "^1" },
    { pattern = "GetConvar",                                              severity = "ORTA",   desc = "Sunucu degiskeni okunuyor", color = "^3" },

    -- Obfuscation teknikleri
    { pattern = "string%.char",                                           severity = "ORTA",   desc = "Karakter kodu ile string olusturma", color = "^3" },
    { pattern = "\\x%x%x",                                                severity = "ORTA",   desc = "Hex kacis dizisi tespit edildi", color = "^3" },
    { pattern = "\\%d%d%d",                                               severity = "ORTA",   desc = "Ondalik kacis dizisi tespit edildi", color = "^3" },
    { pattern = "string%.rep%s*%(%s*string%.char",                        severity = "YUKSEK", desc = "Tekrarli char gizleme yontemi", color = "^1" },
    { pattern = "table%.concat.*string%.char",                            severity = "YUKSEK", desc = "Concat ile char gizleme yontemi", color = "^1" },
    { pattern = "gsub%s*%(.-%,.-function",                                severity = "YUKSEK", desc = "gsub ile dinamik fonksiyon ureten obfuscation", color = "^1" },
    { pattern = "tonumber%s*%(.-%,%s*16%s*%)",                            severity = "YUKSEK", desc = "Hex sayi donusumu (string decoder imzasi)", color = "^1" },

    -- Base64 / encode
    { pattern = "base64%.decode",                                         severity = "YUKSEK", desc = "Base64 cozme cagrisi yapiliyor", color = "^1" },
    { pattern = "mime%.b64",                                              severity = "YUKSEK", desc = "MIME base64 kullanimi tespit edildi", color = "^1" },

    -- Require ile tehlikeli modul
    { pattern = "require%s*%(%s*['\"]socket",                             severity = "YUKSEK", desc = "Socket modulu yukleniyor", color = "^1" },
    { pattern = "require%s*%(%s*['\"]http",                               severity = "YUKSEK", desc = "HTTP modulu yukleniyor", color = "^1" },
    { pattern = "require%s*%(%s*['\"]os",                                 severity = "YUKSEK", desc = "OS modulu yukleniyor", color = "^1" },

    -- fxmanifest / dosya sistemi manipulasyonu
    { pattern = "SaveResourceFile",                                       severity = "YUKSEK", desc = "Dosyaya yazma islemi (kendini inject edebilir)", color = "^1" },
    { pattern = "DeleteResourceFile",                                     severity = "YUKSEK", desc = "Kaynak dosyasi siliniyor", color = "^1" },

    -- Yeni Cipher / patched payload varyantlari (2024-2025)
    { pattern = "PerformHttpRequestInternalEx",                           severity = "KRITIK", desc = "Cipher patched payload: PerformHttpRequestInternalEx", color = "^1" },
    { pattern = "__cfx_internal:httpResponse",                            severity = "KRITIK", desc = "Cipher patched payload: dahili HTTP yanit dinleyici", color = "^1" },
    { pattern = "thedreamoffivem",                                        severity = "KRITIK", desc = "Bilinen RAT C2 domain: thedreamoffivem", color = "^1" },
    { pattern = "fivem%.kvac%.cz",                                        severity = "KRITIK", desc = "KVAC backdoor panel C2 sunucusu", color = "^1" },
    { pattern = "api%.ipify%.org",                                        severity = "YUKSEK", desc = "Harici IP tespiti (KVAC/RAT imzasi)", color = "^1" },

    -- Oyuncu veri hirsizligi (KVAC pattern'i)
    { pattern = "GetPlayerToken",                                         severity = "KRITIK", desc = "Oyuncu token'i cekiliyor (kimlik hirsizligi)", color = "^1" },
    { pattern = "GetPlayerIdentifiers",                                   severity = "BILGI",  desc = "Oyuncu kimlikleri toplu olarak okunuyor", color = "^5" },
    { pattern = "GetPlayerEndpoint",                                      severity = "YUKSEK", desc = "Oyuncu IP adresi okunuyor", color = "^1" },

    -- server.cfg okuma (KVAC pattern'i)
    { pattern = "io%.open%s*%(%s*['\"]server%.cfg",                       severity = "KRITIK", desc = "server.cfg dosyasi okunuyor (KVAC imzasi)", color = "^1" },
    { pattern = "endpoint_add_udp",                                       severity = "YUKSEK", desc = "server.cfg port bilgisi alinmaya calisiliyor", color = "^1" },
    { pattern = "f:read%s*%(%s*['\"]%*all['\"]",                          severity = "YUKSEK", desc = "Dosya tamami okunuyor (veri sizintisi riski)", color = "^1" },

    -- Benzersiz obfuscated degisken imzalari
    { pattern = "%a%x%x%x%x%x%x%x%x%x%x%x%x%x%x%xa%s*==%s*['\"]%x+['\"]", severity = "KRITIK", desc = "KVAC tipi benzersiz obfuscated degisken kontrol imzasi", color = "^1" },

    -- Powershell / sistem payload indirme
    { pattern = "powershell",                                             severity = "KRITIK", desc = "PowerShell cagrisi tespit edildi (sistem erisimi)", color = "^1" },
    { pattern = "cmd%.exe",                                               severity = "KRITIK", desc = "cmd.exe cagrisi tespit edildi", color = "^1" },
    { pattern = "wget%s+http",                                            severity = "KRITIK", desc = "wget ile dosya indirme komutu", color = "^1" },
    { pattern = "curl%s+http",                                            severity = "YUKSEK", desc = "curl ile HTTP istegi tespit edildi", color = "^1" },
    { pattern = "%.bat['\"%s]",                                           severity = "YUKSEK", desc = "Bat dosyasina referans tespit edildi", color = "^1" },
    { pattern = "%.sh['\"%s]",                                            severity = "YUKSEK", desc = "Shell script dosyasina referans tespit edildi", color = "^1" },

    -- Thread
    { pattern = "Citizen%.CreateThread%s*%(%s*function",                  severity = "DUSUK",  desc = "Yeni thread olusturuluyor", color = "^5" },

    -- Monitor.net.dll ve C# Backdoorlar (2024-2025)
    { pattern = "Monitor%.net%.dll",                                      severity = "KRITIK", desc = "Monitor.net.dll backdoor bileşeni (Cipher/KVAC)", color = "^1" },
    { pattern = "Credential%.dll",                                        severity = "KRITIK", desc = "Şüpheli .dll ismi: Credential.dll", color = "^1" },
    { pattern = "CipherPanel",                                            severity = "KRITIK", desc = "Cipher Panel izi bulundu", color = "^1" },
    { pattern = "%.net%.dll",                                             severity = "YUKSEK", desc = "Şüpheli .net.dll uzantılı C# bileşeni", color = "^1" },
    
    -- Eski V1 Patternleri
    { pattern = "latest_utils",                                           severity = "KRITIK", desc = "Bilinen malware dosya adi (latest_utils)", color = "^1" },
    { pattern = "cache_old",                                              severity = "KRITIK", desc = "Bilinen malware dosya adi (cache_old)", color = "^1" },
    { pattern = "beta_module",                                            severity = "KRITIK", desc = "Bilinen malware dosya adi (beta_module)", color = "^1" },
    { pattern = "vite%-env",                                              severity = "KRITIK", desc = "Bilinen malware dosya adi (vite-env)", color = "^1" },
    { pattern = "webpack%-runtime",                                       severity = "KRITIK", desc = "Bilinen malware dosya adi (webpack-runtime)", color = "^1" },
    { pattern = "setfenv",                                                severity = "YUKSEK", desc = "Ortam degistirme - Sandbox atlatma", color = "^1" },
    { pattern = "getfenv",                                                severity = "YUKSEK", desc = "Ortam okuma - Sandbox kesfetme", color = "^1" },
}

-- =============================
-- ŞÜPHELİ DOSYA İSİMLERİ & UZANTILAR
-- =============================
Config.SUSPICIOUS_NAMES = {
    ["monitor.net.dll"] = { severity = "KRITIK", desc = "Monitor.net.dll backdoor dosyası", color = "^1" },
    ["credential.dll"]  = { severity = "KRITIK", desc = "Şüpheli .dll ismi: Credential.dll", color = "^1" },
    ["cipherpanel.dll"] = { severity = "KRITIK", desc = "Cipher Panel binary dosyası", color = "^1" },
    ["kvac.dll"]        = { severity = "KRITIK", desc = "KVAC Backdoor binary dosyası", color = "^1" },
    ["system.core.dll"] = { severity = "ORTA",   desc = "Resource içinde System.Core.dll (Yanlış kullanım riski)", color = "^3" },
    ["server.rar"]      = { severity = "YUKSEK", desc = "Resource klasöründe sıkıştırılmış dosya (.rar)", color = "^1" },
    ["server.zip"]      = { severity = "YUKSEK", desc = "Resource klasöründe sıkıştırılmış dosya (.zip)", color = "^1" },
    ["latest_utils.lua"]= { severity = "KRITIK", desc = "Bilinen Malware Dosyası", color = "^1" },
    ["cache_old.lua"]   = { severity = "KRITIK", desc = "Bilinen Malware Dosyası", color = "^1" },
    ["beta_module.lua"] = { severity = "KRITIK", desc = "Bilinen Malware Dosyası", color = "^1" },
}

Config.SUSPICIOUS_EXTS = {
    ["dll"] = { severity = "YUKSEK", desc = "Resource içinde .dll dosyası tespit edildi (Sıradışı)", color = "^1" },
    ["exe"] = { severity = "KRITIK", desc = "Resource içinde yürütülebilir .exe dosyası bulundu!", color = "^1" },
    ["bat"] = { severity = "ORTA",   desc = "Resource içinde Batch scripti (.bat)", color = "^3" },
}

-- =============================
-- JAVASCRIPT PATTERN'LAR
-- =============================
Config.JS_BAD_PATTERNS = {
    { pattern = "[^a-zA-Z0-9]Function%s*%(",                                                     severity = "KRITIK", desc = "Function constructor ile dinamik kod çalistirma", color = "^1" },
    { pattern = "new%s+Function%s*%(",                                                            severity = "KRITIK", desc = "new Function() ile dinamik kod calistirma", color = "^1" },
    { pattern = "while%s*%(.+!==%-0x%x+%)%s*with",                                                severity = "KRITIK", desc = "Control Flow Flattening (Kod gizleme tekniği)", color = "^1" },
    { pattern = "%.push%s*%(%s*%a+%.shift%s*%(%s*%)%s*%)",                                        severity = "YUKSEK", desc = "Dizi kaydirma (Obfuskasyon imzasi)", color = "^1" },
    { pattern = "eval%s*%(%s*%a+%s*%(%s*%a+,%s*%a+%)%s*%)",                                       severity = "KRITIK", desc = "Dinamik dekoder ve eval() kullanımı (RAT imzası)", color = "^1" },
    { pattern = "%[%s*(%d+,%s*){20,}",                                                            severity = "YUKSEK", desc = "Büyük sayı dizisi tespit edildi (Obfuskasyon riski)", color = "^1" },
    { pattern = "String%.fromCharCode%s*%(.+%^",                                                  severity = "KRITIK", desc = "XOR tabanlı karakter çözme işlemi (Backdoor imzası)", color = "^1" },
    { pattern = "for%s*%(.-i%s*<%s*%a+%.length;%s*i%s*%+%+.-String%.fromCharCode%(%a+%[i%]%s*%^", severity = "KRITIK", desc = "Klasik XOR dekoder döngüsü tespit edildi", color = "^1" },
    { pattern = "setTimeout%s*%(%s*['\"]",                                                        severity = "YUKSEK", desc = "setTimeout string ile kullaniliyor", color = "^1" },
    { pattern = "setInterval%s*%(%s*['\"]",                                                       severity = "YUKSEK", desc = "setInterval string ile kullaniliyor", color = "^1" },
    { pattern = "document%.write%s*%(",                                                           severity = "YUKSEK", desc = "document.write() ile DOM enjeksiyonu", color = "^1" },
    { pattern = "\\x%x%x",                                                                        severity = "ORTA",   desc = "JS icerisinde hex kacis dizisi", color = "^3" },
    { pattern = "\\u%x%x%x%x",                                                                    severity = "ORTA",   desc = "Unicode kacis dizisi tespit edildi", color = "^3" },
    { pattern = "String%.fromCharCode",                                                           severity = "YUKSEK", desc = "Karakter kodu ile string olusturma", color = "^1" },
    { pattern = "atob%s*%(",                                                                      severity = "YUKSEK", desc = "atob() ile Base64 cozme islemi", color = "^1" },
    { pattern = "btoa%s*%(",                                                                      severity = "ORTA",   desc = "btoa() ile Base64 kodlama islemi", color = "^3" },
    { pattern = "%[%s*['\"]constructor['\"]%s*%]",                                                severity = "YUKSEK", desc = "Kose parantez ile constructor erisimi", color = "^1" },
    { pattern = "window%[.-%]%s*%(",                                                              severity = "YUKSEK", desc = "Dinamik window ozelligi cagrisi", color = "^1" },
    { pattern = "fetch%s*%(%s*['\"]https?://",                                                    severity = "ORTA",   desc = "Disariya fetch() istegi gonderiliyor", color = "^3" },
    { pattern = "XMLHttpRequest",                                                                 severity = "ORTA",   desc = "XHR kullanimi tespit edildi", color = "^3" },
    { pattern = "navigator%.sendBeacon",                                                          severity = "YUKSEK", desc = "sendBeacon ile disariya veri iletimi", color = "^1" },
    { pattern = "WebSocket%s*%(",                                                                 severity = "ORTA",   desc = "WebSocket baglantisi aciliyor", color = "^3" },
    { pattern = "discord%.com/api/webhooks",                                                      severity = "KRITIK", desc = "Discord webhook JS icerisinde tespit edildi", color = "^1" },
    { pattern = "ngrok%.io",                                                                      severity = "KRITIK", desc = "ngrok tunel adresi JS icerisinde", color = "^1" },
    { pattern = "innerHTML%s*=",                                                                  severity = "ORTA",   desc = "innerHTML atamasi (XSS riski)", color = "^3" },
    { pattern = "outerHTML%s*=",                                                                  severity = "ORTA",   desc = "outerHTML atamasi tespit edildi", color = "^3" },
    { pattern = "insertAdjacentHTML",                                                             severity = "ORTA",   desc = "insertAdjacentHTML kullanimi", color = "^3" },
    { pattern = "src%s*=%s*['\"]javascript:",                                                     severity = "YUKSEK", desc = "src icinde javascript: URI kullanimi", color = "^1" },
    { pattern = "fetch%s*%(%s*['\"]https://[^'\"]-['\"]",                                         severity = "ORTA",   desc = "NUI icerisinde disari URL fetch cagrisi", color = "^3" },
    { pattern = "PostMessage",                                                                    severity = "DUSUK",  desc = "PostMessage kullanimi tespit edildi", color = "^5" },
    { pattern = "window%.invokeNative",                                                           severity = "YUKSEK", desc = "invokeNative cagrisi tespit edildi", color = "^1" },
}

-- =============================
-- HTML PATTERN'LAR
-- =============================
Config.HTML_BAD_PATTERNS = {
    { pattern = "<script[^>]-src%s*=%s*['\"]https?://",          severity = "YUKSEK", desc = "Disaridan script dosyasi yukleniyor", color = "^1" },
    { pattern = "<script[^>]-src%s*=%s*['\"]//",                 severity = "YUKSEK", desc = "Protokolsuz disari script kaynagi", color = "^1" },
    { pattern = "javascript%s*:",                                severity = "YUKSEK", desc = "javascript: URI kullanimi tespit edildi", color = "^1" },
    { pattern = "on%a+%s*=%s*['\"]?%s*eval",                     severity = "KRITIK", desc = "Olay icerisinde eval kullanimi", color = "^1" },
    { pattern = "on%a+%s*=%s*['\"]?%s*fetch",                    severity = "YUKSEK", desc = "Olay icerisinde fetch kullanimi", color = "^1" },
    { pattern = "<iframe[^>]-src%s*=%s*['\"]https?://",          severity = "YUKSEK", desc = "Disaridan iframe yukleniyor", color = "^1" },
    { pattern = "<object[^>]-data%s*=%s*['\"]https?://",         severity = "YUKSEK", desc = "Disaridan object embed ediliyor", color = "^1" },
    { pattern = "<embed[^>]-src%s*=%s*['\"]https?://",           severity = "YUKSEK", desc = "Disaridan embed kaynagi yukleniyor", color = "^1" },
    { pattern = "<meta[^>]-http%-equiv%s*=%s*['\"]refresh['\"]", severity = "ORTA",   desc = "Meta refresh ile yonlendirme", color = "^3" },
    { pattern = "src%s*=%s*['\"]data:text/javascript",           severity = "KRITIK", desc = "Data URI icinde Base64 JS kodu", color = "^1" },
    { pattern = "src%s*=%s*['\"]data:application/javascript",    severity = "KRITIK", desc = "application/js turunde Base64 URI", color = "^1" },
    { pattern = "on%a+%s*=%s*['\"][^'\"]-\\x%x%x",               severity = "YUKSEK", desc = "Hex kodlanmis olay yoneticisi", color = "^1" },
    { pattern = "on%a+%s*=%s*['\"][^'\"]-String%.fromCharCode",  severity = "YUKSEK", desc = "Olay yoneticisinde char kodu kullanimi", color = "^1" },
    { pattern = "discord%.com/api/webhooks",                     severity = "KRITIK", desc = "Discord webhook HTML icerisinde tespit edildi", color = "^1" },
    { pattern = "ngrok%.io",                                     severity = "KRITIK", desc = "ngrok tunel adresi HTML icerisinde", color = "^1" },
}

Config.InvalidStreamExtensions = {
    [".lua"] = true,
    [".js"] = true,
    [".txt"] = true,
    [".md"] = true,
    [".html"] = true,
    [".css"] = true,
    [".json"] = true,
    [".rar"] = true,
    [".zip"] = true,
    [".7z"] = true,
    [".png"] = true,
    [".jpg"] = true,
    [".jpeg"] = true,
    [".gif"] = true,
    [".bmp"] = true,
    [".exe"] = true,
    [".bat"] = true,
    [".cmd"] = true,
    [".ps1"] = true,
    [".py"] = true,
    [".sh"] = true,
}

Config.extMap = {
    lua  = Config.LUA_BAD_PATTERNS,
    js   = Config.JS_BAD_PATTERNS,
    html = Config.HTML_BAD_PATTERNS,
    htm  = Config.HTML_BAD_PATTERNS,
}

Config.ScanResults = {
    totalFiles = 0,
    totalResources = 0,
    threats = {},
    scanTime = 0,
}
