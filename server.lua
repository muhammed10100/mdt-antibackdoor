-- ===========================================================================
--       MDT YAZILIM HİZMETLERİ ANTİ-BACKDOOR & MALWARE SCANNER v5.0
--               Lua + JS + HTML | Sessiz Tarama, Discord Raporu
--            Cipher Panel + Blum Panel + KVAC + thedreamoffivem RAT
-- ===========================================================================


local function ResetResults()
    Config.ScanResults = {
        totalFiles = 0,
        totalResources = 0,
        threats = {},
        scanTime = 0,
    }
end

local function IsWhitelisted(resourceName)
    if Config.WhitelistResources[resourceName] then return true end
    return false
end

local function IsPathWhitelisted(filePath)
    for _, wl in ipairs(Config.WhitelistPaths) do
        if filePath:find(wl, 1, true) then
            return true
        end
    end
    return false
end

local function GetFileExtension(filename)
    return filename:match("^.+%.(.+)$") or ""
end

local function ScanFileContent(resourceName, filePath, content, patterns, fileType)
    if not content or content == "" then return end
    
    local lines = {}
    local lineNum = 0
    for line in content:gmatch("[^\r\n]+") do
        lineNum = lineNum + 1
        lines[lineNum] = line
    end

    local lowerContent = content:lower()
    for _, entry in ipairs(patterns) do
        if lowerContent:find(entry.pattern) then
            -- Find the specific line for better reporting
            local foundLineNum = 0
            local snippet = ""
            for num, line in pairs(lines) do
                if line:lower():find(entry.pattern) then
                    foundLineNum = num
                    snippet = line:sub(1, 120)
                    if #line > 120 then snippet = snippet .. "..." end
                    break
                end
            end
            
            table.insert(Config.ScanResults.threats, {
                resource = resourceName,
                file = filePath,
                fileType = fileType,
                line = foundLineNum,
                severity = entry.severity,
                description = entry.desc,
                color = entry.color,
                snippet = snippet,
            })
        end
    end
end

local function ScanResource(resourceName)
    if IsWhitelisted(resourceName) then return end
    
    local resourcePath = GetResourcePath(resourceName)
    if not resourcePath then return end
    
    Config.ScanResults.totalResources = Config.ScanResults.totalResources + 1
    local scannedFiles = {}
    
    local function ScanFile(path)
        if not path or path == "" then return end
        if scannedFiles[path] then return end
        if IsPathWhitelisted(path) then return end
        scannedFiles[path] = true
        
        local lowerPath = path:lower()
        
        -- Şüpheli Dosya Adı Kontrolü
        if Config.SUSPICIOUS_NAMES[lowerPath] then
            table.insert(Config.ScanResults.threats, {
                resource = resourceName,
                file = path,
                fileType = "FILE",
                line = 0,
                severity = Config.SUSPICIOUS_NAMES[lowerPath].severity,
                description = Config.SUSPICIOUS_NAMES[lowerPath].desc,
                color = Config.SUSPICIOUS_NAMES[lowerPath].color,
                snippet = "Supheli dosya adi tespit edildi",
            })
        end

        -- Şüpheli Uzantı Kontrolü
        local ext = GetFileExtension(lowerPath)
        if Config.SUSPICIOUS_EXTS[ext] then
            table.insert(Config.ScanResults.threats, {
                resource = resourceName,
                file = path,
                fileType = "FILE",
                line = 0,
                severity = Config.SUSPICIOUS_EXTS[ext].severity,
                description = Config.SUSPICIOUS_EXTS[ext].desc,
                color = Config.SUSPICIOUS_EXTS[ext].color,
                snippet = "Supheli dosya uzantisi tespit edildi",
            })
        end

        -- İçerik Taraması (Sadece Desteklenen Uzantılar İçin)
        local patterns = Config.extMap[ext] or (ext == "" and Config.LUA_BAD_PATTERNS or nil)
        if patterns then
            local content = LoadResourceFile(resourceName, path)
            if content then
                Config.ScanResults.totalFiles = Config.ScanResults.totalFiles + 1
                ScanFileContent(resourceName, path, content, patterns, ext:upper() ~= "" and ext:upper() or "UNKNOWN")
            end
        end

        -- Manifest Analizi (@ imports)
        if Config.CheckSymbol and path:find("^@") then
            table.insert(Config.ScanResults.threats, {
                resource = resourceName,
                file = "fxmanifest.lua",
                fileType = "MANIFEST",
                line = 0,
                severity = "YUKSEK",
                description = "Baska bir kaynaktan dosya yukleniyor (@ enjeksiyonu riski): " .. path,
                color = "^1",
                snippet = path,
            })
        end
    end

    -- 1) Manifest dosyalarini tara
    ScanFile('fxmanifest.lua')
    ScanFile('__resource.lua')

    -- 2) Bilinen yollar
    local commonPaths = {
        'client.lua', 'server.lua', 'config.lua', 'shared.lua',
        'client/main.lua', 'server/main.lua', 'shared/main.lua',
        'client/client.lua', 'server/server.lua',
        'client.js', 'server.js',
        'src/client.lua', 'src/server.lua',
        'server/sv_main.lua', 'client/cl_main.lua',
        'client/utils.lua', 'server/utils.lua',
        'server/commands.lua', 'server/permissions.lua',
        'shared/utils.lua', 'shared/config.lua',
        'html/script.js', 'html/app.js', 'html/main.js',
    }
    for _, path in ipairs(commonPaths) do
        ScanFile(path)
    end

    -- 3) Metadata'dan Dosyaları Tara
    local allMetaKeys = { "file", "client_script", "server_script", "shared_script", "data_file", "ui_page" }
    for _, key in ipairs(allMetaKeys) do
        local i = 0
        while true do
            local file = GetResourceMetadata(resourceName, key, i)
            if not file then break end
            ScanFile(file)
            i = i + 1
        end
    end

    -- 2) Manifest'ten direk okuma garantisi (fallback)
    local manifest = LoadResourceFile(resourceName, 'fxmanifest.lua') or LoadResourceFile(resourceName, '__resource.lua')
    if manifest then
        Config.ScanResults.totalFiles = Config.ScanResults.totalFiles + 1
        ScanFileContent(resourceName, 'fxmanifest.lua', manifest, Config.LUA_BAD_PATTERNS, "LUA")
        
        for scriptPath in manifest:gmatch("[\"']([^\"']+%.[a-zA-Z0-9]+)[\"']") do
            if not scriptPath:find("%*") then
                ScanFile(scriptPath)
            end
        end
    end
end

local function PrintBanner()
    print("^4═══════════════════════════════════════════════════════════════^7")
    print("^4║  ^5STABİLİMBEN ANTİ-BACKDOOR SCANNER v5.0                      ^4║^7")
    print("^4║  ^7Sunucu Guvenlik Tarama Sistemi                             ^4║^7")
    print("^4═══════════════════════════════════════════════════════════════^7")
end

local function PrintResults()
    print("")
    print("^4═══════════════════════════════════════════════════════════════^7")
    print("^4║  ^5TARAMA SONUCLARI                                           ^4║^7")
    print("^4═══════════════════════════════════════════════════════════════^7")
    print(("^3  Taranan Resource: ^7%d"):format(Config.ScanResults.totalResources))
    print(("^3  Taranan Dosya:    ^7%d"):format(Config.ScanResults.totalFiles))
    print(("^3  Tarama Suresi:    ^7%.2f saniye"):format(Config.ScanResults.scanTime))
    print("^4───────────────────────────────────────────────────────────────^7")
    
    if #Config.ScanResults.threats == 0 then
        print("^2  ✓ HIC BIR TEHDIT BULUNAMADI! Sunucu temiz.^7")
    else
        local severityOrder = { KRITIK = 1, YUKSEK = 2, ORTA = 3, BILGI = 4, DUSUK = 5 }
        table.sort(Config.ScanResults.threats, function(a, b)
            return (severityOrder[a.severity] or 99) < (severityOrder[b.severity] or 99)
        end)
        
        local kCount, yCount, oCount, bCount, dCount = 0, 0, 0, 0, 0
        for _, t in ipairs(Config.ScanResults.threats) do
            if t.severity == "KRITIK" then kCount = kCount + 1
            elseif t.severity == "YUKSEK" then yCount = yCount + 1
            elseif t.severity == "ORTA" then oCount = oCount + 1
            elseif t.severity == "BILGI" then bCount = bCount + 1
            else dCount = dCount + 1 end
        end
        
        print(("^1  ✗ KRITIK: %d  ^3⚠ YUKSEK: %d  ^3○ ORTA: %d  ^5ℹ BILGI/DUSUK: %d^7"):format(kCount, yCount, oCount, bCount + dCount))
        print("^4───────────────────────────────────────────────────────────────^7")
        
        for i, t in ipairs(Config.ScanResults.threats) do
            print(("%s  [%s] [%s] ^7%s"):format(t.color or "^3", t.severity, t.fileType or "?", t.description))
            print(("^3    Resource: ^7%s"):format(t.resource))
            print(("^3    Dosya:    ^7%s : %d"):format(t.file, t.line))
            print(("^3    Kod:      ^7%s"):format(t.snippet))
            if i < #Config.ScanResults.threats then
                print("^4  ╎ ╎ ╎ ╎ ╎ ╎ ╎ ╎ ╎ ╎ ╎ ╎ ╎ ╎ ╎ ╎ ╎ ╎ ╎ ╎ ╎ ╎ ╎ ╎ ╎ ╎^7")
            end
        end
    end
    
    print("^4═══════════════════════════════════════════════════════════════^7")
    print("")
end

local function SendDiscordReport()
    if not Config.DiscordWebhook or Config.DiscordWebhook == "" then return end
    
    local kritikCount = 0
    local yuksekCount = 0
    local totalThreats = #Config.ScanResults.threats
    
    for _, t in ipairs(Config.ScanResults.threats) do
        if t.severity == "KRITIK" then kritikCount = kritikCount + 1
        elseif t.severity == "YUKSEK" then yuksekCount = yuksekCount + 1 end
    end
    
    local color = 3066993
    if kritikCount > 0 then
        color = 15158332
    elseif yuksekCount > 0 then
        color = 15105570
    elseif totalThreats > 0 then
        color = 16776960
    end
    
    local description = ("**Taranan Resource:** %d\n**Taranan Dosya:** %d\n**Tarama Suresi:** %.2f saniye\n\n"):format(
        Config.ScanResults.totalResources, Config.ScanResults.totalFiles, Config.ScanResults.scanTime
    )
    
    if totalThreats == 0 then
        description = description .. "✅ **HIC BIR TEHDIT BULUNAMADI!** Sunucu temiz."
    else
        description = description .. ("🔴 **KRITIK:** %d\n🟠 **YUKSEK:** %d\n🟡 **TOPLAM:** %d\n\n"):format(kritikCount, yuksekCount, totalThreats)
        
        local shown = 0
        for _, t in ipairs(Config.ScanResults.threats) do
            if shown >= 10 then
                description = description .. "\n... ve " .. (totalThreats - 10) .. " tehdit daha."
                break
            end
            description = description .. ("**[%s]** %s\n`%s` → `%s:%d`\n"):format(t.severity, t.description, t.resource, t.file, t.line)
            shown = shown + 1
        end
    end
    
    local embed = {
        {
            title = "🛡️ Anti-Backdoor Tarama Raporu (v5.0)",
            description = description,
            color = color,
            timestamp = os.date("!%Y-%m-%dT%H:%M:%S.000Z"),
            footer = { text = "Stabilimben Anti-Backdoor v5.0" }
        }
    }
    
    PerformHttpRequest(Config.DiscordWebhook, function() end, 'POST', json.encode({
        username = "Anti-Backdoor",
        embeds = embed
    }), { ['Content-Type'] = 'application/json' })
end

local isScanning = false

local function RunFullScan()
    if isScanning then
        print("^3[Anti-Backdoor] Tarama zaten devam ediyor...^7")
        return
    end
    
    isScanning = true
    ResetResults()
    PrintBanner()
    print("^3  Tarama baslatiliyor...^7")
    
    local startTime = os.clock()
    
    local numResources = GetNumResources()
    for i = 0, numResources - 1 do
        local resourceName = GetResourceByFindIndex(i)
        if resourceName then
            ScanResource(resourceName)
        end
    end
    
    Config.ScanResults.scanTime = os.clock() - startTime
    
    PrintResults()
    SendDiscordReport()
    
    isScanning = false
end

RegisterCommand('scanbackdoor', function(source)
    if source ~= 0 then
        local QBCore = exports['qb-core']:GetCoreObject()
        local Player = QBCore.Functions.GetPlayer(source)
        if not Player then return end
        
        local adminLevel = 0
        pcall(function()
            adminLevel = exports[Config.AdminSystem]:GetAdminLevel(source) or 0
        end)
        
        if adminLevel < 5 then
            TriggerClientEvent('chat:addMessage', source, { args = { '^1[HATA]', 'Bu komutu sadece Management kullanabilir!' }})
            return
        end
        
        TriggerClientEvent('chat:addMessage', source, { args = { '^2[Anti-Backdoor]', 'Tarama baslatildi... Sonuclar konsola yazilacak.' }})
    end
    
    CreateThread(function()
        RunFullScan()
    end)
end, false)

RegisterCommand('scanresource', function(source, args)
    if source ~= 0 then
        local adminLevel = 0
        pcall(function()
            adminLevel = exports[Config.AdminSystem]:GetAdminLevel(source) or 0
        end)
        if adminLevel < 5 then
            TriggerClientEvent('chat:addMessage', source, { args = { '^1[HATA]', 'Bu komutu sadece Management kullanabilir!' }})
            return
        end
    end
    
    local resourceName = args[1]
    if not resourceName or resourceName == "" then
        print("^1[Anti-Backdoor] Kullanim: /scanresource [resource_adi]^7")
        return
    end
    
    ResetResults()
    PrintBanner()
    print(("^3  Tek resource taramasi: %s^7"):format(resourceName))
    
    local startTime = os.clock()
    ScanResource(resourceName)
    Config.ScanResults.scanTime = os.clock() - startTime
    
    PrintResults()
end, false)

AddEventHandler('onResourceStart', function(resourceName)
    if resourceName == GetCurrentResourceName() then return end
    if IsWhitelisted(resourceName) then return end
    
    SetTimeout(2000, function()
        ResetResults()
        ScanResource(resourceName)
        if #Config.ScanResults.threats > 0 then
            PrintResults()
            SendDiscordReport()
        end
    end)
end)

-- ============================================================
-- RUNTIME PRINT DINLEYICI (v5.0 eklentisi)
-- ============================================================
local RUNTIME_PATTERNS = {}
for _, v in ipairs(Config.LUA_BAD_PATTERNS) do table.insert(RUNTIME_PATTERNS, v) end
for _, v in ipairs(Config.JS_BAD_PATTERNS) do table.insert(RUNTIME_PATTERNS, v) end
for _, v in ipairs(Config.HTML_BAD_PATTERNS) do table.insert(RUNTIME_PATTERNS, v) end

AddEventHandler('__cfx_internal:serverPrint', function(msg)
    if type(msg) ~= "string" then return end
    local lower = msg:lower()
    for _, entry in ipairs(RUNTIME_PATTERNS) do
        if lower:find(entry.pattern) then
            local color = entry.color or "^3"
            print("")
            print(color .. "--------------------------------------------------------------------^7")
            print(("%s  [RUNTIME TEHDIT] [%s]  %s^7"):format(color, entry.severity, entry.desc))
            print(("^7  >> %s"):format(msg:sub(1, 120)))
            print(color .. "--------------------------------------------------------------------^7")
            print("")
            -- Opsiyonel: Discord'a anlik runtime logu atilabilir
            break
        end
    end
end)

if Config.ScanOnStart then
    CreateThread(function()
        Wait(10000)
        RunFullScan()
    end)
end

if Config.ScanInterval and Config.ScanInterval > 0 then
    CreateThread(function()
        while true do
            Wait(Config.ScanInterval * 1000)
            print("^3[Anti-Backdoor] Periyodik tarama baslatiliyor...^7")
            RunFullScan()
        end
    end)
end

print("^2[Anti-Backdoor] ^7Stabilimben Anti-Backdoor v5.0 yuklendi!")
print("^2[Anti-Backdoor] ^7Komutlar: /scanbackdoor | /scanresource [isim]")

