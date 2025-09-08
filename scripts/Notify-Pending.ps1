param(
  [Parameter(Mandatory=$true)][string]$Tunnel,
  [Parameter(Mandatory=$true)][string]$Webhook,
  [int]$Limit = 5
)

cd C:\Users\User\PycharmProjects\Phish
.\.venv\Scripts\Activate.ps1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$env:PUBLIC_BASE_URL   = $Tunnel
$env:SLACK_WEBHOOK_URL = $Webhook

python -m app.hunter.workers.notify --state pending --limit $Limit
