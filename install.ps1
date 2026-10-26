# ReConnICS-ng installer (Windows PowerShell): builds the jar and the two engine images, fetches the signed
# advisory index, then starts the console on http://127.0.0.1:8088/.   .\install.ps1 [-NoStart]
param([switch]$NoStart)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Need($cmd, $hint) { if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "missing: $cmd ($hint)" } }
function Run($exe) { & $exe @args; if ($LASTEXITCODE -ne 0) { throw "$exe failed (exit $LASTEXITCODE)" } }
Need java 'install a JDK 21+'; Need mvn 'install Apache Maven 3.9+'; Need docker 'install Docker Desktop'
docker info *> $null
if ($LASTEXITCODE -ne 0) { throw 'Docker is installed but not running: start Docker Desktop and run this again' }
$v = [int](((java -version 2>&1)[0] -replace '[^"]*"(\d+).*', '$1'))
if ($v -lt 21) { throw "Java 21+ is required (found $v)" }

Write-Host '[1/4] building the jar';                 Run mvn -q clean package -DskipTests
Write-Host '[2/4] building the Zeek + ICSNPP image'; Run docker build -q -t reconics-zeek docker/zeek
Write-Host '[3/4] building the tools image';         Run docker build -q -t reconics-tools docker/tools
Write-Host '[4/4] fetching the signed advisory index'
New-Item -ItemType Directory -Force data | Out-Null
$rel = 'https://github.com/Skoelle18/ReConnICS-ng/releases/download/advisory-index'
foreach ($f in 'index.json', 'index.json.sig') { if (-not (Test-Path "data/$f")) { Invoke-WebRequest "$rel/$f" -OutFile "data/$f" } }
Run java -jar target/reconnics-ng.jar verify --index data/index.json --pubkey keys/index-signing.pub

$serve = @('-jar', 'target/reconnics-ng.jar', 'serve', '--index', 'data/index.json', '--pubkey', 'keys/index-signing.pub', '--data', 'data/site')
if ($NoStart) { Write-Host "Installed. Start with: java $($serve -join ' ')"; return }
Write-Host 'Open http://127.0.0.1:8088/ and upload a .pcap'
java @serve
