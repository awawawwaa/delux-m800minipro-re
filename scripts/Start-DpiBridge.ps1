<#
.SYNOPSIS
    Bridge HTTP local para configurar o DPI do mouse Delux (VID 0x1d57 / PID 0xfa60)
    via HID Feature Report nativo do Windows, contornando o bloqueio do WebHID.

.DESCRIPTION
    O WebHID do navegador zera os reports de qualquer colecao HID com usage page
    "Generic Desktop / Mouse" (bloqueio de seguranca do proprio browser). O Feature
    Report vendor-especifico (ReportID 4) que carrega a config de DPI esta dentro
    dessa mesma colecao bloqueada. Este script fala direto com hid.dll/setupapi.dll
    (P/Invoke, sem passar pelo navegador) e expoe um servidor HTTP local simples
    que o webapp (webapp/index.html) chama via fetch().

    Rode este script e deixe a janela aberta enquanto usa o webapp. Ctrl+C para parar.

.EXAMPLE
    .\Start-DpiBridge.ps1
#>
param(
    [int]$Port = 8765
)

$ErrorActionPreference = "Stop"

$VendorId = 0x1d57
$ProductId = 0xfa60
$ReportId = 4

$hidSrc = Join-Path $PSScriptRoot "HidBridge.cs"
if (-not (Test-Path $hidSrc)) { throw "Nao encontrei $hidSrc" }
Add-Type -TypeDefinition (Get-Content $hidSrc -Raw) -Language CSharp

function Find-DpiDevicePath {
    $devices = [HidBridge]::EnumerateDevices($VendorId, $ProductId)
    $candidate = $devices | Where-Object { $_.FeatureReportByteLength -gt 0 } | Select-Object -First 1
    return $candidate
}

function Find-BatteryDevicePath {
    # Colecao "Ordinal" (usagePage 0x0A) - onde o ReportID 3 (heartbeat com bateria
    # e status de carregamento) realmente aparece, confirmado via Raw Input.
    $devices = [HidBridge]::EnumerateDevices($VendorId, $ProductId)
    $candidate = $devices | Where-Object { $_.UsagePage -eq 0x0A } | Select-Object -First 1
    return $candidate
}

function Build-DpiPayload {
    param(
        [bool[]]$Enabled, [int[]]$Dpi, [int]$Active,
        [bool]$RippleControl = $false,
        [bool]$Lod2mm = $false,
        [bool]$MotionSync = $false,
        [bool]$AngleSnapping = $false,
        [int]$ConnectionMode = 3   # 0=HP, 1=LP, 3=Corded (2 nunca observado)
    )

    # Template de 56 bytes capturado do software oficial (ReportID 4, "Performance").
    # offsets confirmados com multiplas amostras:
    #   3: bitmask  bit0=Ripple Control  bit4(0x10)=LOD(1=2mm,0=1mm)
    #   4: bitmask  bit0=Motion Sync     bit4(0x10)=Angle Snapping
    #   5: bitmask dos 6 estagios de DPI habilitados
    #   6: modo de conexao/sensor frame rate (0=HP, 1=LP, 3=Corded)
    #   8-13: tabela de DPI (6 slots, valor = (byte+1)*50)
    #   24: estagio de DPI ativo (1-based)
    #   51: checksum = soma(3,4,5,6,8,9,10,11,12,13,24) + 0x34, mod 256
    $bytes = [byte[]](
        0x04, 0x38, 0x01, 0x00, 0x00, 0x3f, 0x03, 0x00,
        0x07, 0x0f, 0x17, 0x1f, 0x3f, 0x63, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00,
        0x00, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00,
        0xff, 0xff, 0xff, 0xff, 0x40, 0x00, 0xff, 0xff,
        0xff, 0x03, 0x0f, 0x68, 0x00, 0x00, 0x00, 0x00
    )

    $b3 = 0
    if ($RippleControl) { $b3 = $b3 -bor 0x01 }
    if ($Lod2mm) { $b3 = $b3 -bor 0x10 }
    $bytes[3] = [byte]$b3

    $b4 = 0
    if ($MotionSync) { $b4 = $b4 -bor 0x01 }
    if ($AngleSnapping) { $b4 = $b4 -bor 0x10 }
    $bytes[4] = [byte]$b4

    $mask = 0
    for ($i = 0; $i -lt 6; $i++) { if ($Enabled[$i]) { $mask = $mask -bor (1 -shl $i) } }
    $bytes[5] = [byte]$mask

    $bytes[6] = [byte]$ConnectionMode

    for ($i = 0; $i -lt 6; $i++) {
        $b = [Math]::Round($Dpi[$i] / 50.0) - 1
        if ($b -lt 0) { $b = 0 }
        if ($b -gt 255) { $b = 255 }
        $bytes[8 + $i] = [byte]$b
    }

    $bytes[24] = [byte]($Active + 1)

    $sum = $bytes[2] + $bytes[3] + $bytes[4] + $bytes[5] + $bytes[6] + $bytes[8] + $bytes[9] + $bytes[10] + $bytes[11] + $bytes[12] + $bytes[13] + $bytes[24]
    $bytes[51] = [byte](($sum + 0x34) % 256)

    return $bytes
}

function Build-DebouncePayload {
    param([int]$DebounceMs)

    # Template de 15 bytes capturado do software oficial (ReportID 5, "Performance").
    # offset 10 = debounce time em ms puro (sem escala).
    # offset 12 = offset10 + 28 (0x1c) -- confirmado em 3 amostras independentes (13/7/1ms).
    # Demais bytes ainda nao identificados, mantidos fixos como capturados.
    $bytes = [byte[]](
        0x05, 0x0f, 0x01, 0x70, 0x03, 0xa8, 0x00, 0x00,
        0xff, 0x02, 0x0d, 0x02, 0x29, 0x00, 0x00
    )

    if ($DebounceMs -lt 0) { $DebounceMs = 0 }
    if ($DebounceMs -gt 255) { $DebounceMs = 255 }
    $bytes[10] = [byte]$DebounceMs
    $bytes[12] = [byte](($DebounceMs + 28) % 256)

    return $bytes
}

function Build-PollingRatePayload {
    param([int]$Hz)

    # Template de 9 bytes (ReportID 6). offset3 = enum da taxa; offset4 = 0xFF - offset3
    # (confirmado em 3 amostras: 1000/500/250Hz). 125Hz extrapolado, NAO confirmado.
    $table = @{ 1000 = 0x74; 500 = 0x73; 250 = 0x72; 125 = 0x71 }
    if (-not $table.ContainsKey($Hz)) { throw "Taxa de polling nao suportada: $Hz Hz" }

    $bytes = [byte[]](0x06, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    $bytes[3] = [byte]$table[$Hz]
    $bytes[4] = [byte]((0xff - $bytes[3]) % 256)

    return $bytes
}

function Write-JsonResponse {
    param($Context, $Object, [int]$StatusCode = 200)

    $json = $Object | ConvertTo-Json -Depth 6 -Compress
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)

    $Context.Response.StatusCode = $StatusCode
    $Context.Response.ContentType = "application/json; charset=utf-8"
    $Context.Response.Headers.Add("Access-Control-Allow-Origin", "*")
    $Context.Response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    $Context.Response.Headers.Add("Access-Control-Allow-Headers", "Content-Type")
    $Context.Response.ContentLength64 = $buffer.Length
    $Context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
    $Context.Response.OutputStream.Close()
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$Port/")
$listener.Start()

Write-Host "Delux DPI Bridge rodando em http://localhost:$Port/" -ForegroundColor Cyan
Write-Host "Deixe esta janela aberta. Ctrl+C para parar." -ForegroundColor DarkGray
Write-Host ""

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $req = $context.Request
        $path = $req.Url.AbsolutePath

        try {
            if ($req.HttpMethod -eq "OPTIONS") {
                Write-JsonResponse -Context $context -Object @{ ok = $true } -StatusCode 204
                continue
            }

            if ($path -eq "/status" -and $req.HttpMethod -eq "GET") {
                $dev = Find-DpiDevicePath
                if ($dev) {
                    Write-JsonResponse -Context $context -Object @{
                        found       = $true
                        path        = $dev.Path
                        productName = $dev.ProductName
                        usagePage   = $dev.UsagePage
                        usage       = $dev.Usage
                    }
                } else {
                    Write-JsonResponse -Context $context -Object @{
                        found = $false
                        error = "Nenhum dispositivo VID=0x1d57 PID=0xfa60 com Feature Report encontrado. O mouse esta conectado?"
                    }
                }
                continue
            }

            if ($path -eq "/apply" -and $req.HttpMethod -eq "POST") {
                $reader = New-Object System.IO.StreamReader($req.InputStream, $req.ContentEncoding)
                $body = $reader.ReadToEnd()
                $reader.Close()
                $state = $body | ConvertFrom-Json

                $enabled = @($state.enabled | ForEach-Object { [bool]$_ })
                $dpi = @($state.dpi | ForEach-Object { [int]$_ })
                $active = [int]$state.active
                $rippleControl = if ($null -ne $state.rippleControl) { [bool]$state.rippleControl } else { $false }
                $lod2mm = if ($null -ne $state.lod2mm) { [bool]$state.lod2mm } else { $false }
                $motionSync = if ($null -ne $state.motionSync) { [bool]$state.motionSync } else { $false }
                $angleSnapping = if ($null -ne $state.angleSnapping) { [bool]$state.angleSnapping } else { $false }
                $connectionMode = if ($null -ne $state.connectionMode) { [int]$state.connectionMode } else { 3 }

                if ($enabled.Count -ne 6 -or $dpi.Count -ne 6) {
                    Write-JsonResponse -Context $context -Object @{ ok = $false; error = "Esperado 6 slots de DPI." } -StatusCode 400
                    continue
                }

                $dev = Find-DpiDevicePath
                if (-not $dev) {
                    Write-JsonResponse -Context $context -Object @{ ok = $false; error = "Dispositivo nao encontrado." } -StatusCode 404
                    continue
                }

                $payload = Build-DpiPayload -Enabled $enabled -Dpi $dpi -Active $active `
                    -RippleControl $rippleControl -Lod2mm $lod2mm -MotionSync $motionSync `
                    -AngleSnapping $angleSnapping -ConnectionMode $connectionMode
                $result = [HidBridge]::SetFeatureReport($dev.Path, $payload)
                $hex = ($payload | ForEach-Object { $_.ToString("x2") }) -join " "

                Write-JsonResponse -Context $context -Object @{
                    ok      = ($result -eq "OK")
                    result  = $result
                    payload = $hex
                }
                continue
            }

            if ($path -eq "/apply-debounce" -and $req.HttpMethod -eq "POST") {
                $reader = New-Object System.IO.StreamReader($req.InputStream, $req.ContentEncoding)
                $body = $reader.ReadToEnd()
                $reader.Close()
                $state = $body | ConvertFrom-Json

                $debounceMs = [int]$state.debounceMs

                $dev = Find-DpiDevicePath
                if (-not $dev) {
                    Write-JsonResponse -Context $context -Object @{ ok = $false; error = "Dispositivo nao encontrado." } -StatusCode 404
                    continue
                }

                $payload = Build-DebouncePayload -DebounceMs $debounceMs
                $result = [HidBridge]::SetFeatureReport($dev.Path, $payload)
                $hex = ($payload | ForEach-Object { $_.ToString("x2") }) -join " "

                Write-JsonResponse -Context $context -Object @{
                    ok      = ($result -eq "OK")
                    result  = $result
                    payload = $hex
                }
                continue
            }

            if ($path -eq "/apply-pollingrate" -and $req.HttpMethod -eq "POST") {
                $reader = New-Object System.IO.StreamReader($req.InputStream, $req.ContentEncoding)
                $body = $reader.ReadToEnd()
                $reader.Close()
                $state = $body | ConvertFrom-Json

                $hz = [int]$state.hz

                $dev = Find-DpiDevicePath
                if (-not $dev) {
                    Write-JsonResponse -Context $context -Object @{ ok = $false; error = "Dispositivo nao encontrado." } -StatusCode 404
                    continue
                }

                try {
                    $payload = Build-PollingRatePayload -Hz $hz
                } catch {
                    Write-JsonResponse -Context $context -Object @{ ok = $false; error = $_.Exception.Message } -StatusCode 400
                    continue
                }
                $result = [HidBridge]::SetFeatureReport($dev.Path, $payload)
                $hex = ($payload | ForEach-Object { $_.ToString("x2") }) -join " "

                Write-JsonResponse -Context $context -Object @{
                    ok      = ($result -eq "OK")
                    result  = $result
                    payload = $hex
                }
                continue
            }

            if ($path -eq "/battery" -and $req.HttpMethod -eq "GET") {
                $dev = Find-BatteryDevicePath
                if (-not $dev) {
                    Write-JsonResponse -Context $context -Object @{ ok = $false; error = "Colecao de bateria nao encontrada." } -StatusCode 404
                    continue
                }

                $bytes = [HidBridge]::ReadFileWithTimeout($dev.Path, 5, 6000)
                if ($null -eq $bytes -or $bytes.Count -lt 5) {
                    Write-JsonResponse -Context $context -Object @{ ok = $false; error = "Timeout esperando o heartbeat do mouse (chega a cada poucos segundos quando ocioso)." } -StatusCode 504
                    continue
                }

                Write-JsonResponse -Context $context -Object @{
                    ok        = $true
                    battery   = [int]$bytes[4]
                    charging  = ([int]$bytes[3] -eq 3)
                    raw       = ($bytes | ForEach-Object { $_.ToString("x2") }) -join " "
                }
                continue
            }

            Write-JsonResponse -Context $context -Object @{ ok = $false; error = "Rota nao encontrada: $path" } -StatusCode 404
        }
        catch {
            Write-JsonResponse -Context $context -Object @{ ok = $false; error = $_.Exception.Message } -StatusCode 500
        }
    }
}
finally {
    $listener.Stop()
    $listener.Close()
}
