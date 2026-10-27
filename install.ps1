# ReConnICS-ng installer (Windows PowerShell). One paste does everything:
#   irm https://raw.githubusercontent.com/Skoelle18/ReConnICS-ng/main/install.ps1 | iex
# Inside a clone:  .\install.ps1 [-NoStart]
# Checks the machine first, clones the repo when run from the pipe, builds the jar and the two engine images,
# fetches the signed advisory index, then starts the console on http://127.0.0.1:8088/.
param([switch]$NoStart)
$ErrorActionPreference = 'Stop'
$Repo = 'https://github.com/Skoelle18/ReConnICS-ng.git'
$NeedGb = 8   # ponytail: estimate (Zeek build layers + tools image + Maven cache); measure and adjust

# Run from the pipe ($PSScriptRoot is empty, no pom.xml here): get the repo, then run its own copy of this script.
if (-not $PSScriptRoot -and -not (Test-Path pom.xml)) {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'missing: git (install git, then paste the command again)' }
    if (Test-Path ReConnICS-ng/.git) { git -C ReConnICS-ng pull --ff-only } else { git clone $Repo }
    if ($LASTEXITCODE -ne 0) { throw 'git failed' }
    & ./ReConnICS-ng/install.ps1 @(if ($NoStart) { '-NoStart' })
    return
}
Set-Location $(if ($PSScriptRoot) { $PSScriptRoot } else { '.' })

function Run($exe) { & $exe @args; if ($LASTEXITCODE -ne 0) { throw "$exe failed (exit $LASTEXITCODE)" } }

# ---- checks: collect every problem, report them all at once
$bad = @()
foreach ($t in @(@('git', 'install git'), @('java', 'install a JDK 21+'), @('mvn', 'install Apache Maven 3.9+'), @('docker', 'install Docker Desktop'))) {
    if (-not (Get-Command $t[0] -ErrorAction SilentlyContinue)) { $bad += "$($t[0]) is not installed ($($t[1]))" }
}
$v = 0
if (Get-Command java -ErrorAction SilentlyContinue) {
    $v = [int](((cmd /c 'java -version 2>&1')[0]) -replace '[^"]*"(\d+).*', '$1')
    if ($v -lt 21) { $bad += "Java 21+ is required (found $v)" }
}
if (Get-Command docker -ErrorAction SilentlyContinue) {
    docker info *> $null
    if ($LASTEXITCODE -ne 0) { $bad += 'Docker is installed but not running (start Docker Desktop)' }
}
$freeGb = [int]((Get-Item .).PSDrive.Free / 1GB)
if ($freeGb -lt $NeedGb) { $bad += "only $freeGb GB free here, about $NeedGb GB are needed for the images and build" }
try { Invoke-WebRequest https://github.com -UseBasicParsing -TimeoutSec 10 | Out-Null } catch { $bad += 'cannot reach github.com (needed for the advisory index)' }
if (Get-NetTCPConnection -LocalPort 8088 -State Listen -ErrorAction SilentlyContinue) { $bad += 'port 8088 is already in use (is the console already running?)' }
if ($bad.Count) { Write-Host 'Cannot install yet:'; $bad | ForEach-Object { Write-Host "  - $_" }; throw 'fix the above and paste the command again' }
Write-Host "Checks passed: java $v, maven, docker running, $freeGb GB free, github reachable, port 8088 free"

# Each step streams the real output of its tool (maven goals, docker layers) so a long build never looks stuck, then prints how long it took.
function Step($n, $title) { Write-Host ''; Write-Host "==> [$n/4] $title"; $script:t = Get-Date }
function Done { Write-Host ("    done in {0:N0} s" -f ((Get-Date) - $script:t).TotalSeconds) }
Step 1 'building the jar (Maven)';                                                                          Run mvn -B -ntp clean package -DskipTests; Done
Step 2 'building the Zeek + ICSNPP image (Docker; the first build compiles Zeek and takes several minutes)'; Run docker build --progress=plain -t reconics-zeek docker/zeek; Done
Step 3 'building the tools image (Docker; tshark, Suricata, nDPI, p0f)';                                    Run docker build --progress=plain -t reconics-tools docker/tools; Done
Step 4 'fetching the signed advisory index'
New-Item -ItemType Directory -Force data | Out-Null
$rel = 'https://github.com/Skoelle18/ReConnICS-ng/releases/download/advisory-index'
foreach ($f in 'index.json', 'index.json.sig') { if (-not (Test-Path "data/$f")) { Invoke-WebRequest "$rel/$f" -OutFile "data/$f" } }
Run java -jar target/reconnics-ng.jar verify --index data/index.json --pubkey keys/index-signing.pub
Write-Host '    index verified'

$serve = @('-jar', 'target/reconnics-ng.jar', 'serve', '--index', 'data/index.json', '--pubkey', 'keys/index-signing.pub', '--data', 'data/site')
if ($NoStart) { Write-Host "Installed. Start with: java $($serve -join ' ')"; return }
Write-Host 'Open http://127.0.0.1:8088/ and upload a .pcap'
java @serve
