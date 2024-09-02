[CmdletBinding()]
param(
  [switch]$OPdgpeGw8aHVn7WA,
  [switch]$p53Lfo,
  [switch]$a97u10gzE0qzxiF5KZFrQYMg
)

function returnHotFixID {
  param(
    [string]$brXWR8u0QojLU2vm
  )
  if (($brXWR8u0QojLU2vm | Select-String -AllMatches -Pattern 'KB(\d{4,6})').Matches.Value) {
    return (($brXWR8u0QojLU2vm | Select-String -AllMatches -Pattern 'KB(\d{4,6})').Matches.Value)
  }
  elseif (($brXWR8u0QojLU2vm | Select-String -NotMatch -Pattern 'KB(\d{4,6})').Matches.Value) {
    return (($brXWR8u0QojLU2vm | Select-String -NotMatch -Pattern 'KB(\d{4,6})').Matches.Value)
  }
}

Function Start-ACLCheck {
  param(
    $Pll, $hQJEKSFHI5D1k3oN)
  if ($null -ne $Pll) {
    try {
      $Kz2 = Get-Acl $Pll -ErrorAction SilentlyContinue
    }
    catch { $null }
    
    if ($Kz2) { 
      $6wKxdfnCQ9TclstsbvIdm = @()
      $6wKxdfnCQ9TclstsbvIdm += "$FjTgcdZ:COMPUTERNAME\$FjTgcdZ:USERNAME"
      if ($Kz2.Owner -like $6wKxdfnCQ9TclstsbvIdm ) { Write-Host "$6wKxdfnCQ9TclstsbvIdm has ownership of $Pll" -ForegroundColor Red }
      whoami.exe /groups /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty 'group name' | ForEach-Object { $6wKxdfnCQ9TclstsbvIdm += $_ }
      $u3CFQi7l = $false
      foreach ($Ji6d0B3bU in $6wKxdfnCQ9TclstsbvIdm) {
        $6pCe7ZwrTMC = $Kz2.Access | Where-Object { $_.IdentityReference -like $Ji6d0B3bU }
        $o2DjX4iFCZr0qc = ""
        switch -WildCard ($6pCe7ZwrTMC.FileSystemRights) {
          "FullControl" { $o2DjX4iFCZr0qc = "FullControl"; $u3CFQi7l = $true }
          "Write*" { $o2DjX4iFCZr0qc = "Write"; $u3CFQi7l = $true }
          "Modify" { $o2DjX4iFCZr0qc = "Modify"; $u3CFQi7l = $true }
        }
        Switch ($6pCe7ZwrTMC.RegistryRights) {
          "FullControl" { $o2DjX4iFCZr0qc = "FullControl"; $u3CFQi7l = $true }
        }
        if ($o2DjX4iFCZr0qc) {
          if ($hQJEKSFHI5D1k3oN) { Write-Host "$hQJEKSFHI5D1k3oN found with permissions issue:" -ForegroundColor Red }
          Write-Host -ForegroundColor red  "Identity $($6pCe7ZwrTMC.IdentityReference) has '$o2DjX4iFCZr0qc' perms for $Pll"
        }
      }    
      if ($u3CFQi7l -eq $false) {
        if ($Pll.Length -gt 3) {
          $Pll = Split-Path $Pll
          Start-ACLCheck $Pll -ServiceName $hQJEKSFHI5D1k3oN
        }
      }
    }
    else {
      $Pll = Split-Path $Pll
      Start-ACLCheck $Pll $hQJEKSFHI5D1k3oN
    }
  }
}

Function UnquotedServicePathCheck {
  Write-Host "Fetching the list of services, this may take a while...";
  $T5CGimYjBPypxoOd6 = Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -inotmatch "`"" -and $_.PathName -inotmatch ":\\Windows\\" -and ($_.StartMode -eq "Auto" -or $_.StartMode -eq "Manual") -and ($_.State -eq "Running" -or $_.State -eq "Stopped") };
  if ($($T5CGimYjBPypxoOd6 | Measure-Object).Count -lt 1) {
    Write-Host "No unquoted service paths were found";
  }
  else {
    $T5CGimYjBPypxoOd6 | ForEach-Object {
      Write-Host "Unquoted Service Path found!" -ForegroundColor red
      Write-Host Name: $_.Name
      Write-Host PathName: $_.PathName
      Write-Host StartName: $_.StartName 
      Write-Host StartMode: $_.StartMode
      Write-Host Running: $_.State
    } 
  }
}

function TimeElapsed { Write-Host "Time Running: $($wtw.Elapsed.Minutes):$($wtw.Elapsed.Seconds)" }
Function Get-ClipBoardText {
  Add-Type -AssemblyName PresentationCore
  $gSVtnZivkSxljtrbR3S = [Windows.Clipboard]::GetText()
  if ($gSVtnZivkSxljtrbR3S) {
    Write-Host ""
    if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
    Write-Host -ForegroundColor Blue "=========:: ClipBoard text found:"
    Write-Host $gSVtnZivkSxljtrbR3S
    
  }
}

function Write-Color([String[]]$gSVtnZivkSxljtrbR3S, [ConsoleColor[]]$Zih2dr) {
  for ($Ji6d0B3bU = 0; $Ji6d0B3bU -lt $gSVtnZivkSxljtrbR3S.Length; $Ji6d0B3bU++) {
    Write-Host $gSVtnZivkSxljtrbR3S[$Ji6d0B3bU] -Foreground $Zih2dr[$Ji6d0B3bU] -NoNewline
  }
  Write-Host
}

$nsVlXCHyLvIq = $true
$XNYzWBd = $true
$9jbukfmsT = $true

$mGzJV8baDYoLX = @{}

if ($nsVlXCHyLvIq) {
  $mGzJV8baDYoLX.add("Simple Passwords1", "pass.*[=:].+")
  $mGzJV8baDYoLX.add("Simple Passwords2", "pwd.*[=:].+")
  $mGzJV8baDYoLX.add("Apr1 MD5", '\$9MbnTCrtRewgmJW\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}')
  $mGzJV8baDYoLX.add("Apache SHA", "\{SHA\}[0-9a-zA-Z/_=]{10,}")
  $mGzJV8baDYoLX.add("Blowfish", '\$CH9m[abxyz]?\$[0-9]{2}\$[a-zA-Z0-9_/\.]*')
  $mGzJV8baDYoLX.add("Drupal", '\$1ITDvI\$[a-zA-Z0-9_/\.]{52}')
  $mGzJV8baDYoLX.add("Joomlavbulletin", "[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}")
  $mGzJV8baDYoLX.add("Linux MD5", '\$xKUv6GlAVr2ML7DBa\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}')
  $mGzJV8baDYoLX.add("phpbb3", '\$3B\$[a-zA-Z0-9_/\.]{31}')
  $mGzJV8baDYoLX.add("sha512crypt", '\$1HA3rCHmf4upWuCb\$[a-zA-Z0-9_/\.]{16}\$[a-zA-Z0-9_/\.]{86}')
  $mGzJV8baDYoLX.add("Wordpress", '\$icVX0f4IYWZCOQ7J9tHU3aS\$[a-zA-Z0-9_/\.]{31}')
  $mGzJV8baDYoLX.add("md5", "(^|[^a-zA-Z0-9])[a-fA-F0-9]{32}([^a-zA-Z0-9]|$)")
  $mGzJV8baDYoLX.add("sha1", "(^|[^a-zA-Z0-9])[a-fA-F0-9]{40}([^a-zA-Z0-9]|$)")
  $mGzJV8baDYoLX.add("sha256", "(^|[^a-zA-Z0-9])[a-fA-F0-9]{64}([^a-zA-Z0-9]|$)")
  $mGzJV8baDYoLX.add("sha512", "(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)")  
  $mGzJV8baDYoLX.add("Base64", "(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[a-zA-Z0-9+\/]+={0,2}")

}
if ($XNYzWBd) {
  $mGzJV8baDYoLX.add("Usernames1", "username[=:].+")
  $mGzJV8baDYoLX.add("Usernames2", "user[=:].+")
  $mGzJV8baDYoLX.add("Usernames3", "login[=:].+")
  $mGzJV8baDYoLX.add("Emails", "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}")
  $mGzJV8baDYoLX.add("Net user add", "net user .+ /add")
}

if ($p53Lfo) {
  $mGzJV8baDYoLX.add("Artifactory API Token", "AKC[a-zA-Z0-9]{10,}")
  $mGzJV8baDYoLX.add("Artifactory Password", "AP[0-9ABCDEF][a-zA-Z0-9]{8,}")
  $mGzJV8baDYoLX.add("Adafruit API Key", "([a-z0-9_-]{32})")
  $mGzJV8baDYoLX.add("Adafruit API Key", "([a-z0-9_-]{32})")
  $mGzJV8baDYoLX.add("Adobe Client Id (Oauth Web)", "(adobe[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-f0-9]{32})['""]")
  $mGzJV8baDYoLX.add("Abode Client Secret", "(p8e-)[a-z0-9]{32}")
  $mGzJV8baDYoLX.add("Age Secret Key", "AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}")
  $mGzJV8baDYoLX.add("Airtable API Key", "([a-z0-9]{17})")
  $mGzJV8baDYoLX.add("Alchemi API Key", "(alchemi[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9-]{32})['""]")
  $mGzJV8baDYoLX.add("Artifactory API Key & Password", "[""']AKC[a-zA-Z0-9]{10,}[""']|[""']AP[0-9ABCDEF][a-zA-Z0-9]{8,}[""']")
  $mGzJV8baDYoLX.add("Atlassian API Key", "(atlassian[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{24})['""]")
  $mGzJV8baDYoLX.add("Binance API Key", "(binance[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9]{64})['""]")
  $mGzJV8baDYoLX.add("Bitbucket Client Id", "((bitbucket[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{32})['""])")
  $mGzJV8baDYoLX.add("Bitbucket Client Secret", "((bitbucket[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9_\-]{64})['""])")
  $mGzJV8baDYoLX.add("BitcoinAverage API Key", "(bitcoin.?average[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9]{43})['""]")
  $mGzJV8baDYoLX.add("Bitquery API Key", "(bitquery[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([A-Za-z0-9]{32})['""]")
  $mGzJV8baDYoLX.add("Bittrex Access Key and Access Key", "([a-z0-9]{32})")
  $mGzJV8baDYoLX.add("Birise API Key", "(bitrise[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9_\-]{86})['""]")
  $mGzJV8baDYoLX.add("Block API Key", "(block[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})['""]")
  $mGzJV8baDYoLX.add("Blockchain API Key", "mainnet[a-zA-Z0-9]{32}|testnet[a-zA-Z0-9]{32}|ipfs[a-zA-Z0-9]{32}")
  $mGzJV8baDYoLX.add("Blockfrost API Key", "(blockchain[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[0-9a-f]{12})['""]")
  $mGzJV8baDYoLX.add("Box API Key", "(box[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9]{32})['""]")
  $mGzJV8baDYoLX.add("Bravenewcoin API Key", "(bravenewcoin[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{50})['""]")
  $mGzJV8baDYoLX.add("Clearbit API Key", "sk_[a-z0-9]{32}")
  $mGzJV8baDYoLX.add("Clojars API Key", "(CLOJARS_)[a-zA-Z0-9]{60}")
  $mGzJV8baDYoLX.add("Coinbase Access Token", "([a-z0-9_-]{64})")
  $mGzJV8baDYoLX.add("Coinlayer API Key", "(coinlayer[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{32})['""]")
  $mGzJV8baDYoLX.add("Coinlib API Key", "(coinlib[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{16})['""]")
  $mGzJV8baDYoLX.add("Confluent Access Token & Secret Key", "([a-z0-9]{16})")
  $mGzJV8baDYoLX.add("Contentful delivery API Key", "(contentful[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9=_\-]{43})['""]")
  $mGzJV8baDYoLX.add("Covalent API Key", "ckey_[a-z0-9]{27}")
  $mGzJV8baDYoLX.add("Charity Search API Key", "(charity.?search[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{32})['""]")
  $mGzJV8baDYoLX.add("Databricks API Key", "dapi[a-h0-9]{32}")
  $mGzJV8baDYoLX.add("DDownload API Key", "(ddownload[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{22})['""]")
  $mGzJV8baDYoLX.add("Defined Networking API token", "(dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52})")
  $mGzJV8baDYoLX.add("Discord API Key, Client ID & Client Secret", "((discord[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-h0-9]{64}|[0-9]{18}|[a-z0-9=_\-]{32})['""])")
  $mGzJV8baDYoLX.add("Droneci Access Token", "([a-z0-9]{32})")
  $mGzJV8baDYoLX.add("Dropbox API Key", "sl.[a-zA-Z0-9_-]{136}")
  $mGzJV8baDYoLX.add("Doppler API Key", "(dp\.pt\.)[a-zA-Z0-9]{43}")
  $mGzJV8baDYoLX.add("Dropbox API secret/key, short & long lived API Key", "(dropbox[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{15}|sl\.[a-z0-9=_\-]{135}|[a-z0-9]{11}(AAAAAAAAAA)[a-z0-9_=\-]{43})['""]")
  $mGzJV8baDYoLX.add("Duffel API Key", "duffel_(test|live)_[a-zA-Z0-9_-]{43}")
  $mGzJV8baDYoLX.add("Dynatrace API Key", "dt0c01\.[a-zA-Z0-9]{24}\.[a-z0-9]{64}")
  $mGzJV8baDYoLX.add("EasyPost API Key", "EZAK[a-zA-Z0-9]{54}")
  $mGzJV8baDYoLX.add("EasyPost test API Key", "EZTK[a-zA-Z0-9]{54}")
  $mGzJV8baDYoLX.add("Etherscan API Key", "(etherscan[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([A-Z0-9]{34})['""]")
  $mGzJV8baDYoLX.add("Etsy Access Token", "([a-z0-9]{24})")
  $mGzJV8baDYoLX.add("Facebook Access Token", "EAACEdEose0cBA[0-9A-Za-z]+")
  $mGzJV8baDYoLX.add("Fastly API Key", "(fastly[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9=_\-]{32})['""]")
  $mGzJV8baDYoLX.add("Finicity API Key & Client Secret", "(finicity[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-f0-9]{32}|[a-z0-9]{20})['""]")
  $mGzJV8baDYoLX.add("Flickr Access Token", "([a-z0-9]{32})")
  $mGzJV8baDYoLX.add("Flutterweave Keys", "FLWPUBK_TEST-[a-hA-H0-9]{32}-X|FLWSECK_TEST-[a-hA-H0-9]{32}-X|FLWSECK_TEST[a-hA-H0-9]{12}")
  $mGzJV8baDYoLX.add("Frame.io API Key", "fio-u-[a-zA-Z0-9_=\-]{64}")
  $mGzJV8baDYoLX.add("Freshbooks Access Token", "([a-z0-9]{64})")
  $mGzJV8baDYoLX.add("Github", "github(.{0,20})?['""][0-9a-zA-Z]{35,40}")
  $mGzJV8baDYoLX.add("Github App Token", "(ghu|ghs)_[0-9a-zA-Z]{36}")
  $mGzJV8baDYoLX.add("Github OAuth Access Token", "gho_[0-9a-zA-Z]{36}")
  $mGzJV8baDYoLX.add("Github Personal Access Token", "ghp_[0-9a-zA-Z]{36}")
  $mGzJV8baDYoLX.add("Github Refresh Token", "ghr_[0-9a-zA-Z]{76}")
  $mGzJV8baDYoLX.add("GitHub Fine-Grained Personal Access Token", "github_pat_[0-9a-zA-Z_]{82}")
  $mGzJV8baDYoLX.add("Gitlab Personal Access Token", "glpat-[0-9a-zA-Z\-]{20}")
  $mGzJV8baDYoLX.add("GitLab Pipeline Trigger Token", "glptt-[0-9a-f]{40}")
  $mGzJV8baDYoLX.add("GitLab Runner Registration Token", "GR1348941[0-9a-zA-Z_\-]{20}")
  $mGzJV8baDYoLX.add("Gitter Access Token", "([a-z0-9_-]{40})")
  $mGzJV8baDYoLX.add("GoCardless API Key", "live_[a-zA-Z0-9_=\-]{40}")
  $mGzJV8baDYoLX.add("GoFile API Key", "(gofile[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9]{32})['""]")
  $mGzJV8baDYoLX.add("Google API Key", "AIza[0-9A-Za-z_\-]{35}")
  $mGzJV8baDYoLX.add("Google Cloud Platform API Key", "(google|gcp|youtube|drive|yt)(.{0,20})?['""][AIza[0-9a-z_\-]{35}]['""]")
  $mGzJV8baDYoLX.add("Google Drive Oauth", "[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com")
  $mGzJV8baDYoLX.add("Google Oauth Access Token", "ya29\.[0-9A-Za-z_\-]+")
  $mGzJV8baDYoLX.add("Google (GCP) Service-account", """type.+:.+""service_account")
  $mGzJV8baDYoLX.add("Grafana API Key", "eyJrIjoi[a-z0-9_=\-]{72,92}")
  $mGzJV8baDYoLX.add("Grafana cloud api token", "glc_[A-Za-z0-9\+/]{32,}={0,2}")
  $mGzJV8baDYoLX.add("Grafana service account token", "(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})")
  $mGzJV8baDYoLX.add("Hashicorp Terraform user/org API Key", "[a-z0-9]{14}\.atlasv1\.[a-z0-9_=\-]{60,70}")
  $mGzJV8baDYoLX.add("Heroku API Key", "[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}")
  $mGzJV8baDYoLX.add("Hubspot API Key", "['""][a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12}['""]")
  $mGzJV8baDYoLX.add("Instatus API Key", "(instatus[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{32})['""]")
  $mGzJV8baDYoLX.add("Intercom API Key & Client Secret/ID", "(intercom[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9=_]{60}|[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['""]")
  $mGzJV8baDYoLX.add("Ionic API Key", "(ionic[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""](ion_[a-z0-9]{42})['""]")
  $mGzJV8baDYoLX.add("JSON Web Token", "(ey[0-9a-z]{30,34}\.ey[0-9a-z\/_\-]{30,}\.[0-9a-zA-Z\/_\-]{10,}={0,2})")
  $mGzJV8baDYoLX.add("Kraken Access Token", "([a-z0-9\/=_\+\-]{80,90})")
  $mGzJV8baDYoLX.add("Kucoin Access Token", "([a-f0-9]{24})")
  $mGzJV8baDYoLX.add("Kucoin Secret Key", "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
  $mGzJV8baDYoLX.add("Launchdarkly Access Token", "([a-z0-9=_\-]{40})")
  $mGzJV8baDYoLX.add("Linear API Key", "(lin_api_[a-zA-Z0-9]{40})")
  $mGzJV8baDYoLX.add("Linear Client Secret/ID", "((linear[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-f0-9]{32})['""])")
  $mGzJV8baDYoLX.add("LinkedIn Client ID", "linkedin(.{0,20})?['""][0-9a-z]{12}['""]")
  $mGzJV8baDYoLX.add("LinkedIn Secret Key", "linkedin(.{0,20})?['""][0-9a-z]{16}['""]")
  $mGzJV8baDYoLX.add("Lob API Key", "((lob[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]((live|test)_[a-f0-9]{35})['""])|((lob[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]((test|live)_pub_[a-f0-9]{31})['""])")
  $mGzJV8baDYoLX.add("Lob Publishable API Key", "((test|live)_pub_[a-f0-9]{31})")
  $mGzJV8baDYoLX.add("MailboxValidator", "(mailbox.?validator[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([A-Z0-9]{20})['""]")
  $mGzJV8baDYoLX.add("Mailchimp API Key", "[0-9a-f]{32}-us[0-9]{1,2}")
  $mGzJV8baDYoLX.add("Mailgun API Key", "key-[0-9a-zA-Z]{32}'")
  $mGzJV8baDYoLX.add("Mailgun Public Validation Key", "pubkey-[a-f0-9]{32}")
  $mGzJV8baDYoLX.add("Mailgun Webhook signing key", "[a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8}")
  $mGzJV8baDYoLX.add("Mapbox API Key", "(pk\.[a-z0-9]{60}\.[a-z0-9]{22})")
  $mGzJV8baDYoLX.add("Mattermost Access Token", "([a-z0-9]{26})")
  $mGzJV8baDYoLX.add("MessageBird API Key & API client ID", "(messagebird[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{25}|[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['""]")
  $mGzJV8baDYoLX.add("Microsoft Teams Webhook", "https:\/\/[a-z0-9]+\.webhook\.office\.com\/webhookb2\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}\/IncomingWebhook\/[a-z0-9]{32}\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}")
  $mGzJV8baDYoLX.add("MojoAuth API Key", "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")
  $mGzJV8baDYoLX.add("Netlify Access Token", "([a-z0-9=_\-]{40,46})")
  $mGzJV8baDYoLX.add("New Relic User API Key, User API ID & Ingest Browser API Key", "(NRAK-[A-Z0-9]{27})|((newrelic[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([A-Z0-9]{64})['""])|(NRJS-[a-f0-9]{19})")
  $mGzJV8baDYoLX.add("Nownodes", "(nownodes[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([A-Za-z0-9]{32})['""]")
  $mGzJV8baDYoLX.add("Npm Access Token", "(npm_[a-zA-Z0-9]{36})")
  $mGzJV8baDYoLX.add("Nytimes Access Token", "([a-z0-9=_\-]{32})")
  $mGzJV8baDYoLX.add("Okta Access Token", "([a-z0-9=_\-]{42})")
  $mGzJV8baDYoLX.add("OpenAI API Token", "sk-[A-Za-z0-9]{48}")
  $mGzJV8baDYoLX.add("ORB Intelligence Access Key", "['""][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['""]")
  $mGzJV8baDYoLX.add("Pastebin API Key", "(pastebin[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{32})['""]")
  $mGzJV8baDYoLX.add("PayPal Braintree Access Token", 'access_token\$Gm6ta\$[0-9a-z]{16}\$[0-9a-f]{32}')
  $mGzJV8baDYoLX.add("Picatic API Key", "sk_live_[0-9a-z]{32}")
  $mGzJV8baDYoLX.add("Pinata API Key", "(pinata[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{64})['""]")
  $mGzJV8baDYoLX.add("Planetscale API Key", "pscale_tkn_[a-zA-Z0-9_\.\-]{43}")
  $mGzJV8baDYoLX.add("PlanetScale OAuth token", "(pscale_oauth_[a-zA-Z0-9_\.\-]{32,64})")
  $mGzJV8baDYoLX.add("Planetscale Password", "pscale_pw_[a-zA-Z0-9_\.\-]{43}")
  $mGzJV8baDYoLX.add("Plaid API Token", "(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
  $mGzJV8baDYoLX.add("Plaid Client ID", "([a-z0-9]{24})")
  $mGzJV8baDYoLX.add("Plaid Secret key", "([a-z0-9]{30})")
  $mGzJV8baDYoLX.add("Prefect API token", "(pnu_[a-z0-9]{36})")
  $mGzJV8baDYoLX.add("Postman API Key", "PMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34}")
  $mGzJV8baDYoLX.add("Private Keys", "\-\-\-\-\-BEGIN PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN RSA PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN OPENSSH PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN PGP PRIVATE KEY BLOCK\-\-\-\-\-|\-\-\-\-\-BEGIN DSA PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN EC PRIVATE KEY\-\-\-\-\-")
  $mGzJV8baDYoLX.add("Pulumi API Key", "pul-[a-f0-9]{40}")
  $mGzJV8baDYoLX.add("PyPI upload token", "pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}")
  $mGzJV8baDYoLX.add("Quip API Key", "(quip[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-zA-Z0-9]{15}=\|[0-9]{10}\|[a-zA-Z0-9\/+]{43}=)['""]")
  $mGzJV8baDYoLX.add("RapidAPI Access Token", "([a-z0-9_-]{50})")
  $mGzJV8baDYoLX.add("Rubygem API Key", "rubygems_[a-f0-9]{48}")
  $mGzJV8baDYoLX.add("Readme API token", "rdme_[a-z0-9]{70}")
  $mGzJV8baDYoLX.add("Sendbird Access ID", "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
  $mGzJV8baDYoLX.add("Sendbird Access Token", "([a-f0-9]{40})")
  $mGzJV8baDYoLX.add("Sendgrid API Key", "SG\.[a-zA-Z0-9_\.\-]{66}")
  $mGzJV8baDYoLX.add("Sendinblue API Key", "xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}")
  $mGzJV8baDYoLX.add("Sentry Access Token", "([a-f0-9]{64})")
  $mGzJV8baDYoLX.add("Shippo API Key, Access Token, Custom Access Token, Private App Access Token & Shared Secret", "shippo_(live|test)_[a-f0-9]{40}|shpat_[a-fA-F0-9]{32}|shpca_[a-fA-F0-9]{32}|shppa_[a-fA-F0-9]{32}|shpss_[a-fA-F0-9]{32}")
  $mGzJV8baDYoLX.add("Sidekiq Secret", "([a-f0-9]{8}:[a-f0-9]{8})")
  $mGzJV8baDYoLX.add("Sidekiq Sensitive URL", "([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)")
  $mGzJV8baDYoLX.add("Slack Token", "xox[baprs]-([0-9a-zA-Z]{10,48})?")
  $mGzJV8baDYoLX.add("Slack Webhook", "https://hooks.slack.com/services/T[a-zA-Z0-9_]{10}/B[a-zA-Z0-9_]{10}/[a-zA-Z0-9_]{24}")
  $mGzJV8baDYoLX.add("Smarksheel API Key", "(smartsheet[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{26})['""]")
  $mGzJV8baDYoLX.add("Square Access Token", "sqOatp-[0-9A-Za-z_\-]{22}")
  $mGzJV8baDYoLX.add("Square API Key", "EAAAE[a-zA-Z0-9_-]{59}")
  $mGzJV8baDYoLX.add("Square Oauth Secret", "sq0csp-[ 0-9A-Za-z_\-]{43}")
  $mGzJV8baDYoLX.add("Stytch API Key", "secret-.*-[a-zA-Z0-9_=\-]{36}")
  $mGzJV8baDYoLX.add("Stripe Access Token & API Key", "(sk|pk)_(test|live)_[0-9a-z]{10,32}|k_live_[0-9a-zA-Z]{24}")
  $mGzJV8baDYoLX.add("SumoLogic Access ID", "([a-z0-9]{14})")
  $mGzJV8baDYoLX.add("SumoLogic Access Token", "([a-z0-9]{64})")
  $mGzJV8baDYoLX.add("Telegram Bot API Token", "[0-9]+:AA[0-9A-Za-z\\-_]{33}")
  $mGzJV8baDYoLX.add("Travis CI Access Token", "([a-z0-9]{22})")
  $mGzJV8baDYoLX.add("Trello API Key", "(trello[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9a-z]{32})['""]")
  $mGzJV8baDYoLX.add("Twilio API Key", "SK[0-9a-fA-F]{32}")
  $mGzJV8baDYoLX.add("Twitch API Key", "(twitch[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{30})['""]")
  $mGzJV8baDYoLX.add("Twitter Client ID", "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['""][0-9a-z]{18,25}")
  $mGzJV8baDYoLX.add("Twitter Bearer Token", "(A{22}[a-zA-Z0-9%]{80,100})")
  $mGzJV8baDYoLX.add("Twitter Oauth", "[tT][wW][iI][tT][tT][eE][rR].{0,30}['""\\s][0-9a-zA-Z]{35,44}['""\\s]")
  $mGzJV8baDYoLX.add("Twitter Secret Key", "[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['""][0-9a-z]{35,44}")
  $mGzJV8baDYoLX.add("Typeform API Key", "tfp_[a-z0-9_\.=\-]{59}")
  $mGzJV8baDYoLX.add("URLScan API Key", "['""][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['""]")
  $mGzJV8baDYoLX.add("Vault Token", "[sb]\.[a-zA-Z0-9]{24}")
  $mGzJV8baDYoLX.add("Yandex Access Token", "(t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2})")
  $mGzJV8baDYoLX.add("Yandex API Key", "(AQVN[A-Za-z0-9_\-]{35,38})")
  $mGzJV8baDYoLX.add("Yandex AWS Access Token", "(YC[a-zA-Z0-9_\-]{38})")
  $mGzJV8baDYoLX.add("Web3 API Key", "(web3[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([A-Za-z0-9_=\-]+\.[A-Za-z0-9_=\-]+\.?[A-Za-z0-9_.+/=\-]*)['""]")
  $mGzJV8baDYoLX.add("Zendesk Secret Key", "([a-z0-9]{40})")
  $mGzJV8baDYoLX.add("Generic API Key", "((key|api|token|secret|password)[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9a-zA-Z_=\-]{8,64})['""]")
}

if ($9jbukfmsT) {
  $mGzJV8baDYoLX.add("Authorization Basic", "basic [a-zA-Z0-9_:\.=\-]+")
  $mGzJV8baDYoLX.add("Authorization Bearer", "bearer [a-zA-Z0-9_\.=\-]+")
  $mGzJV8baDYoLX.add("Alibaba Access Key ID", "(LTAI)[a-z0-9]{20}")
  $mGzJV8baDYoLX.add("Alibaba Secret Key", "(alibaba[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{30})['""]")
  $mGzJV8baDYoLX.add("Asana Client ID", "((asana[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9]{16})['""])|((asana[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([a-z0-9]{32})['""])")
  $mGzJV8baDYoLX.add("AWS Client ID", "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")
  $mGzJV8baDYoLX.add("AWS MWS Key", "amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
  $mGzJV8baDYoLX.add("AWS Secret Key", "aws(.{0,20})?['""][0-9a-zA-Z\/+]{40}['""]")
  $mGzJV8baDYoLX.add("AWS AppSync GraphQL Key", "da2-[a-z0-9]{26}")
  $mGzJV8baDYoLX.add("Basic Auth Credentials", "://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+")
  $mGzJV8baDYoLX.add("Beamer Client Secret", "(beamer[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""](b_[a-z0-9=_\-]{44})['""]")
  $mGzJV8baDYoLX.add("Cloudinary Basic Auth", "cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+")
  $mGzJV8baDYoLX.add("Facebook Client ID", "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['""][0-9]{13,17}")
  $mGzJV8baDYoLX.add("Facebook Oauth", "[fF][aA][cC][eE][bB][oO][oO][kK].*['|""][0-9a-f]{32}['|""]")
  $mGzJV8baDYoLX.add("Facebook Secret Key", "([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['""][0-9a-f]{32}")
  $mGzJV8baDYoLX.add("Jenkins Creds", "<[a-zA-Z]*>{[a-zA-Z0-9=+/]*}<")
  $mGzJV8baDYoLX.add("Generic Secret", "[sS][eE][cC][rR][eE][tT].*['""][0-9a-zA-Z]{32,45}['""]")
  $mGzJV8baDYoLX.add("Basic Auth", "//(.+):(.+)@")
  $mGzJV8baDYoLX.add("PHP Passwords", "(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass|pass').*[=:].+|define ?\('(\w*pass|\w*pwd|\w*user|\w*datab)")
  $mGzJV8baDYoLX.add("Config Secrets (Passwd / Credentials)", "passwd.*|creden.*|^kind:[^a-zA-Z0-9_]?Secret|[^a-zA-Z0-9_]env:|secret:|secretName:|^kind:[^a-zA-Z0-9_]?EncryptionConfiguration|\-\-encryption\-provider\-config")
  $mGzJV8baDYoLX.add("Generiac API tokens search", "(access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key| amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret| api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret| application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket| aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password| bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key| bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver| cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret| client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password| cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|conn.login| connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test| datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password| digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd| docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid| dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password| env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .,<\-]{0,25}(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9a-zA-Z_=\-]{8,64})['""]")
}

if($p53Lfo){$a97u10gzE0qzxiF5KZFrQYMg = $true}

$mGzJV8baDYoLX.add("IPs", "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
$HTK0fzo5N328LdJxAa = Get-PSDrive | Where-Object { $_.Root -like "*:\" }
$oQyLLaGfuDhnRObrF = @("*.xml", "*.txt", "*.conf", "*.config", "*.cfg", "*.ini", ".y*ml", "*.log", "*.bak", "*.xls", "*.xlsx", "*.xlsm")

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host "====================================::SYSTEM INFORMATION ::===================================="
"The following information is curated. To get a full list of system information, run the cmdlet get-computerinfo"

systeminfo.exe


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: WINDOWS HOTFIXES"
Write-Host "=| Check if windows is vulnerable with Watson https://github.com/rasta-mouse/Watson" -ForegroundColor Yellow
Write-Host "Possible exploits (https://github.com/codingo/OSCP-2/blob/master/Windows/WinPrivCheck.bat)" -ForegroundColor Yellow
$Pw4JnjBCeavZrKENSh0 = Get-HotFix | Sort-Object -Descending -Property InstalledOn -ErrorAction SilentlyContinue | Select-Object HotfixID, Description, InstalledBy, InstalledOn
$Pw4JnjBCeavZrKENSh0 | Format-Table -AutoSize

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: ALL UPDATES INSTALLED"

$3fvcuG6sn = (New-Object -ComObject 'Microsoft.Update.Session')
$DXGAokHshrkAmbGkKRX65x = $3fvcuG6sn.QueryHistory("", 0, 1000) | Select-Object ResultCode, Date, Title

$d = @()

$uwP8jIx = @()

for ($Ji6d0B3bU = 0; $Ji6d0B3bU -lt $DXGAokHshrkAmbGkKRX65x.Count; $Ji6d0B3bU++) {
  $2SpVUZoTTa59bNNJdUzwDl45j = returnHotFixID -title $DXGAokHshrkAmbGkKRX65x[$Ji6d0B3bU].Title
  if ($d -like $2SpVUZoTTa59bNNJdUzwDl45j) {
  }
  else {
    $d += $2SpVUZoTTa59bNNJdUzwDl45j
    $uwP8jIx += $Ji6d0B3bU
  }
}
$2AdCbISMmKURsX3zr57 = @()

$uwP8jIx | ForEach-Object {
  $Mps71e2BRzRCR = $DXGAokHshrkAmbGkKRX65x[$_]
  $AorkqneHqeFWRI22 = $Mps71e2BRzRCR.ResultCode
  switch ($AorkqneHqeFWRI22) {
    1 {
      $AorkqneHqeFWRI22 = "Missing/Superseded"
    }
    2 {
      $AorkqneHqeFWRI22 = "Succeeded"
    }
    3 {
      $AorkqneHqeFWRI22 = "Succeeded With Errors"
    }
    4 {
      $AorkqneHqeFWRI22 = "Failed"
    }
    5 {
      $AorkqneHqeFWRI22 = "Canceled"
    }
  }
  $2AdCbISMmKURsX3zr57 += [PSCustomObject]@{
    Result = $AorkqneHqeFWRI22
    Date   = $Mps71e2BRzRCR.Date
    Title  = $Mps71e2BRzRCR.Title
  }    
}
$2AdCbISMmKURsX3zr57 | Format-Table -AutoSize


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Drive Info"
Add-Type -AssemblyName System.Management

$fGBDO3zgoKW6HjULvE = New-Object System.Management.ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType = 3")

$883d2Obr5Qa2Fx1Ot0fct6AD = $fGBDO3zgoKW6HjULvE.Get()

foreach ($fB4da98APXwp in $883d2Obr5Qa2Fx1Ot0fct6AD) {
  $pLDZY1kuGUbg = $fB4da98APXwp.DeviceID
  $7acmS0A652 = $fB4da98APXwp.VolumeName
  $MFsL9YgN4X0ez2jkAy7 = [math]::Round($fB4da98APXwp.Size / 1GB, 2)
  $C36UXIIcLjG7bkGmZzuuY = [math]::Round($fB4da98APXwp.FreeSpace / 1GB, 2)

  Write-Output "Drive: $pLDZY1kuGUbg"
  Write-Output "Label: $7acmS0A652"
  Write-Output "Size: $MFsL9YgN4X0ez2jkAy7 GB"
  Write-Output "Free Space: $C36UXIIcLjG7bkGmZzuuY GB"
  Write-Output ""
}


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Antivirus Detection (attemping to read exclusions as well)"
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName
Get-ChildItem 'registry::HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions' -ErrorAction SilentlyContinue


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: NET ACCOUNTS Info"
net accounts

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: REGISTRY SETTINGS CHECK"

 
Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Audit Log Settings"

if ((Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\).Property) {
  Get-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\
}
else {
  Write-Host "No Audit Log settings, no registry entry found."
}

 
Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Windows Event Forward (WEF) registry"
if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager) {
  Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
}
else {
  Write-Host "Logs are not being fowarded, no registry entry found."
}

 
Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: LAPS Check"
if (Test-Path 'C:\Program Files\LAPS\CSE\Admpwd.dll') { Write-Host "LAPS dll found on this machine at C:\Program Files\LAPS\CSE\" -ForegroundColor Green }
elseif (Test-Path 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll' ) { Write-Host "LAPS dll found on this machine at C:\Program Files (x86)\LAPS\CSE\" -ForegroundColor Green }
else { Write-Host "LAPS dlls not found on this machine" }
if ((Get-ItemProperty HKLM:\Software\Policies\Microsoft Services\AdmPwd -ErrorAction SilentlyContinue).AdmPwdEnabled -eq 1) { Write-Host "LAPS registry key found on this machine" -ForegroundColor Green }


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: WDigest Check"
$gFpohNvASqOy = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest).UseLogonCredential
switch ($gFpohNvASqOy) {
  0 { Write-Host "Value 0 found. Plain-text Passwords are not stored in LSASS" }
  1 { Write-Host "Value 1 found. Plain-text Passwords may be stored in LSASS" -ForegroundColor red }
  Default { Write-Host "The system was unable to find the specified registry value: UesLogonCredential" }
}

 
Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: LSA Protection Check"
$KMbz84l0LAjOCS2e1GfyoYB = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\LSA).RunAsPPL
$ycpN3zh2dZvBsIJbq = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\LSA).RunAsPPLBoot
switch ($KMbz84l0LAjOCS2e1GfyoYB) {
  2 { Write-Host "RunAsPPL: 2. Enabled without UEFI Lock" }
  1 { Write-Host "RunAsPPL: 1. Enabled with UEFI Lock" }
  0 { Write-Host "RunAsPPL: 0. LSA Protection Disabled. Try mimikatz." -ForegroundColor red }
  Default { "The system was unable to find the specified registry value: RunAsPPL / RunAsPPLBoot" }
}
if ($ycpN3zh2dZvBsIJbq) { Write-Host "RunAsPPLBoot: $ycpN3zh2dZvBsIJbq" }

 
Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Credential Guard Check"
$un1OJfL3wGDGy = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\LSA).LsaCfgFlags
switch ($un1OJfL3wGDGy) {
  2 { Write-Host "LsaCfgFlags 2. Enabled without UEFI Lock" }
  1 { Write-Host "LsaCfgFlags 1. Enabled with UEFI Lock" }
  0 { Write-Host "LsaCfgFlags 0. LsaCfgFlags Disabled." -ForegroundColor red }
  Default { "The system was unable to find the specified registry value: LsaCfgFlags" }
}

 
Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Cached WinLogon Credentials Check"
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") {
  (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CACHEDLOGONSCOUNT").CACHEDLOGONSCOUNT
  Write-Host "However, only the SYSTEM user can view the credentials here: HKEY_LOCAL_MACHINE\SECURITY\Cache"
  Write-Host "Or, using mimikatz lsadump::cache"
}

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Additonal Winlogon Credentials Check"

(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultDomainName
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultUserName
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultPassword
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultDomainName
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultUserName
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultPassword


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: RDCMan Settings Check"

if (Test-Path "$FjTgcdZ:USERPROFILE\appdata\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings") {
  Write-Host "RDCMan Settings Found at: $($FjTgcdZ:USERPROFILE)\appdata\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings" -ForegroundColor Red
}
else { Write-Host "No RCDMan.Settings found." }


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: RDP Saved Connections Check"

Write-Host "HK_Users"
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | ForEach-Object {
  $ENkP5Huh2dDx40zysoWq9e = $_.Name.Replace('HKEY_USERS\', "")
  if (Test-Path "registry::HKEY_USERS\$ENkP5Huh2dDx40zysoWq9e\Software\Microsoft\Terminal Server Client\Default") {
    Write-Host "Server Found: $((Get-ItemProperty "registry::HKEY_USERS\$ENkP5Huh2dDx40zysoWq9e\Software\Microsoft\Terminal Server Client\Default" -Name MRU0).MRU0)"
  }
  else { Write-Host "Not found for $($_.Name)" }
}

Write-Host "HKCU"
if (Test-Path "registry::HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default") {
  Write-Host "Server Found: $((Get-ItemProperty "registry::HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default" -Name MRU0).MRU0)"
}
else { Write-Host "Terminal Server Client not found in HCKU" }

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Putty Stored Credentials Check"

if (Test-Path HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions) {
  Get-ChildItem HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions | ForEach-Object {
    $kZoscvLlG = Split-Path $_.Name -Leaf
    Write-Host "Key: $kZoscvLlG"
    @("HostName", "PortNumber", "UserName", "PublicKeyFile", "PortForwardings", "ConnectionSharing", "ProxyUsername", "ProxyPassword") | ForEach-Object {
      Write-Host "$_ :"
      Write-Host "$((Get-ItemProperty  HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions\$kZoscvLlG).$_)"
    }
  }
}
else { Write-Host "No putty credentials found in HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions" }


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: SSH Key Checks"
Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: If found:"
Write-Host "https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/" -ForegroundColor Yellow
Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Checking Putty SSH KNOWN HOSTS"
if (Test-Path HKCU:\Software\SimonTatham\PuTTY\SshHostKeys) { 
  Write-Host "$((Get-Item -Path HKCU:\Software\SimonTatham\PuTTY\SshHostKeys).Property)"
}
else { Write-Host "No putty ssh keys found" }

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Checking for OpenSSH Keys"
if (Test-Path HKCU:\Software\OpenSSH\Agent\Keys) { Write-Host "OpenSSH keys found. Try this for decryption: https://github.com/ropnop/windows_sshagent_extract" -ForegroundColor Yellow }
else { Write-Host "No OpenSSH Keys found." }


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Checking for WinVNC Passwords"
if ( Test-Path "HKCU:\Software\ORL\WinVNC3\Password") { Write-Host " WinVNC found at HKCU:\Software\ORL\WinVNC3\Password" }else { Write-Host "No WinVNC found." }


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Checking for SNMP Passwords"
if ( Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP" ) { Write-Host "SNMP Key found at HKLM:\SYSTEM\CurrentControlSet\Services\SNMP" }else { Write-Host "No SNMP found." }


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Checking for TightVNC Passwords"
if ( Test-Path "HKCU:\Software\TightVNC\Server") { Write-Host "TightVNC key found at HKCU:\Software\TightVNC\Server" }else { Write-Host "No TightVNC found." }


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: UAC Settings"
if ((Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA -eq 1) {
  Write-Host "EnableLUA is equal to 1. Part or all of the UAC components are on."
  Write-Host "https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#basic-uac-bypass-full-file-system-access" -ForegroundColor Yellow
}
else { Write-Host "EnableLUA value not equal to 1" }


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Recently Run Commands (WIN+R)"

Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | ForEach-Object {
  $ENkP5Huh2dDx40zysoWq9e = $_.Name.Replace('HKEY_USERS\', "")
  $rAp = (Get-Item "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue).Property
  $ENkP5Huh2dDx40zysoWq9e | ForEach-Object {
    if (Test-Path "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU") {
      Write-Host -ForegroundColor Blue "=========::HKU Recently Run Commands"
      foreach ($icVX0f4IYWZCOQ7J9tHU3aS in $rAp) {
        Write-Host "$((Get-Item "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"-ErrorAction SilentlyContinue).getValue($icVX0f4IYWZCOQ7J9tHU3aS))" 
      }
    }
  }
}

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========::HKCU Recently Run Commands"
$rAp = (Get-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue).Property
foreach ($icVX0f4IYWZCOQ7J9tHU3aS in $rAp) {
  Write-Host "$((Get-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"-ErrorAction SilentlyContinue).getValue($icVX0f4IYWZCOQ7J9tHU3aS))"
}

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Always Install Elevated Check"
 
Write-Host "Checking Windows Installer Registry (will populate if the key exists)"
if ((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue).AlwaysInstallElevated -eq 1) {
  Write-Host "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer).AlwaysInstallElevated = 1" -ForegroundColor red
  Write-Host "Try msfvenom msi package to escalate" -ForegroundColor red
  Write-Host "https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#metasploit-payloads" -ForegroundColor Yellow
}
 
if ((Get-ItemProperty HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue).AlwaysInstallElevated -eq 1) { 
  Write-Host "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer).AlwaysInstallElevated = 1" -ForegroundColor red
  Write-Host "Try msfvenom msi package to escalate" -ForegroundColor red
  Write-Host "https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#metasploit-payloads" -ForegroundColor Yellow
}


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: PowerShell Info"

(Get-ItemProperty registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine).PowerShellVersion | ForEach-Object {
  Write-Host "PowerShell $_ available"
}
(Get-ItemProperty registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine).PowerShellVersion | ForEach-Object {
  Write-Host  "PowerShell $_ available"
}


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: PowerShell Registry Transcript Check"

if (Test-Path HKCU:\Software\Policies\Microsoft\Windows\PowerShell\Transcription) {
  Get-Item HKCU:\Software\Policies\Microsoft\Windows\PowerShell\Transcription
}
if (Test-Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription) {
  Get-Item HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription
}
if (Test-Path HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription) {
  Get-Item HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
}
if (Test-Path HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription) {
  Get-Item HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
}
 

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: PowerShell Module Log Check"
if (Test-Path HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging) {
  Get-Item HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
}
if (Test-Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging) {
  Get-Item HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
}
if (Test-Path HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging) {
  Get-Item HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
}
if (Test-Path HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging) {
  Get-Item HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
}
 

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: PowerShell Script Block Log Check"
 
if ( Test-Path HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging) {
  Get-Item HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
}
if ( Test-Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging) {
  Get-Item HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
}
if ( Test-Path HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging) {
  Get-Item HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
}
if ( Test-Path HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging) {
  Get-Item HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
}


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: WSUS check for http and UseWAServer = 1, if true, might be vulnerable to exploit"
Write-Host "https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#wsus" -ForegroundColor Yellow
if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate) {
  Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
}
if ((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "USEWUServer" -ErrorAction SilentlyContinue).UseWUServer) {
  (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "USEWUServer").UseWUServer
}


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Internet Settings HKCU / HKLM"

$rAp = (Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).Property
foreach ($icVX0f4IYWZCOQ7J9tHU3aS in $rAp) {
  Write-Host "$icVX0f4IYWZCOQ7J9tHU3aS - $((Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"-ErrorAction SilentlyContinue).getValue($icVX0f4IYWZCOQ7J9tHU3aS))"
}
 
$rAp = (Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).Property
foreach ($icVX0f4IYWZCOQ7J9tHU3aS in $rAp) {
  Write-Host "$icVX0f4IYWZCOQ7J9tHU3aS - $((Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"-ErrorAction SilentlyContinue).getValue($icVX0f4IYWZCOQ7J9tHU3aS))"
}

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: RUNNING PROCESSES"


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Checking user permissions on running processes"
Get-Process | Select-Object Path -Unique | ForEach-Object { Start-ACLCheck -Target $_.path }


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: System processes"
Start-Process tasklist -ArgumentList '/v /fi "username eq system"' -Wait -NoNewWindow

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: SERVICE path vulnerable check"
Write-Host "Checking for vulnerable service .exe"

$6XJM2x358wiRZWTHbpr7htgd = @{}
Get-WmiObject Win32_Service | Where-Object { $_.PathName -like '*.exe*' } | ForEach-Object {
  $MCGw5335R5Rj = ($_.PathName -split '(?<=\.exe\b)')[0].Trim('"')
  $6XJM2x358wiRZWTHbpr7htgd[$MCGw5335R5Rj] = $_.Name
}
foreach ( $3B in ($6XJM2x358wiRZWTHbpr7htgd | Select-Object -Unique).GetEnumerator()) {
  Start-ACLCheck -Target $3B.Name -ServiceName $3B.Value
}


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Checking for Unquoted Service Paths"

UnquotedServicePathCheck

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Checking Service Registry Permissions"
Write-Host "This will take some time."

Get-ChildItem 'HKLM:\System\CurrentControlSet\services\' | ForEach-Object {
  $Pll = $_.Name.Replace("HKEY_LOCAL_MACHINE", "hklm:")
  Start-aclcheck -Target $Pll
}

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: SCHEDULED TASKS vulnerable check"


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Testing access to c:\windows\system32\tasks"
if (Get-ChildItem "c:\windows\system32\tasks" -ErrorAction SilentlyContinue) {
  Write-Host "Access confirmed, may need futher investigation"
  Get-ChildItem "c:\windows\system32\tasks"
}
else {
  Write-Host "No admin access to scheduled tasks folder."
  Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | ForEach-Object {
    $bfm9Qz63W = $_.Actions.Execute
    if ($bfm9Qz63W -ne $null) {
      foreach ($VYriHvzPGOf4B36StKWchoqsb in $bfm9Qz63W) {
        if ($VYriHvzPGOf4B36StKWchoqsb -like "%windir%*") { $VYriHvzPGOf4B36StKWchoqsb = $VYriHvzPGOf4B36StKWchoqsb.replace("%windir%", $FjTgcdZ:windir) }
        elseif ($VYriHvzPGOf4B36StKWchoqsb -like "%SystemRoot%*") { $VYriHvzPGOf4B36StKWchoqsb = $VYriHvzPGOf4B36StKWchoqsb.replace("%SystemRoot%", $FjTgcdZ:windir) }
        elseif ($VYriHvzPGOf4B36StKWchoqsb -like "%localappdata%*") { $VYriHvzPGOf4B36StKWchoqsb = $VYriHvzPGOf4B36StKWchoqsb.replace("%localappdata%", "$FjTgcdZ:UserProfile\appdata\local") }
        elseif ($VYriHvzPGOf4B36StKWchoqsb -like "%appdata%*") { $VYriHvzPGOf4B36StKWchoqsb = $VYriHvzPGOf4B36StKWchoqsb.replace("%localappdata%", $FjTgcdZ:Appdata) }
        $VYriHvzPGOf4B36StKWchoqsb = $VYriHvzPGOf4B36StKWchoqsb.Replace('"', '')
        Start-ACLCheck -Target $VYriHvzPGOf4B36StKWchoqsb
        Write-Host "`n"
        Write-Host "TaskName: $($_.TaskName)"
        Write-Host "-------------"
        [pscustomobject]@{
          LastResult = $(($_ | Get-ScheduledTaskInfo).LastTaskResult)
          NextRun    = $(($_ | Get-ScheduledTaskInfo).NextRunTime)
          Status     = $_.State
          Command    = $_.Actions.execute
          Arguments  = $_.Actions.Arguments 
        } | Write-Host
      } 
    }
  }
}

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: STARTUP APPLICATIONS Vulnerable Check"
"Check if you can modify any binary that is going to be executed by admin or if you can impersonate a not found binary"
Write-Host "https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#run-at-startup" -ForegroundColor Yellow

@("C:\Documents and Settings\All Users\Start Menu\Programs\Startup",
  "C:\Documents and Settings\$FjTgcdZ:Username\Start Menu\Programs\Startup", 
  "$FjTgcdZ:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", 
  "$FjTgcdZ:Appdata\Microsoft\Windows\Start Menu\Programs\Startup") | ForEach-Object {
  if (Test-Path $_) {
    Start-ACLCheck $_
    Get-ChildItem -Recurse -Force -Path $_ | ForEach-Object {
      $rjRGOV8Hvj7v = $_.FullName
      if (Test-Path $rjRGOV8Hvj7v) { 
        Start-ACLCheck -Target $rjRGOV8Hvj7v
      }
    }
  }
}
Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: STARTUP APPS Registry Check"

@("registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
  "registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
  "registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
  "registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce") | ForEach-Object {
  $FDXrfcAwiZjkxdPWHo = $_
  (Get-Item $_) | ForEach-Object {
    $UaWHRE = $_.property
    $UaWHRE | ForEach-Object {
      Start-ACLCheck ((Get-ItemProperty -Path $FDXrfcAwiZjkxdPWHo).$_ -split '(?<=\.exe\b)')[0].Trim('"')
    }
  }
}


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: INSTALLED APPLICATIONS"
Write-Host "Generating list of installed applications"

Get-CimInstance -class win32_Product | Select-Object Name, Version | 
ForEach-Object {
  Write-Host $("{0} : {1}" -f $_.Name, $_.Version)  
}


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: LOOKING FOR BASH.EXE"
Get-ChildItem C:\Windows\WinSxS\ -Filter "amd64_microsoft-windows-lxss-bash*" | ForEach-Object {
  Write-Host $((Get-ChildItem $_.FullName -Recurse -Filter "*bash.exe*").FullName)
}
@("bash.exe", "wsl.exe") | ForEach-Object { Write-Host $((Get-ChildItem C:\Windows\System32\ -Filter $_).FullName) }


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: LOOKING FOR SCCM CLIENT"
$AorkqneHqeFWRI22 = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * -ErrorAction SilentlyContinue | Select-Object Name, SoftwareVersion
if ($AorkqneHqeFWRI22) { $AorkqneHqeFWRI22 }
elseif (Test-Path 'C:\Windows\CCM\SCClient.exe') { Write-Host "SCCM Client found at C:\Windows\CCM\SCClient.exe" -ForegroundColor Cyan }
else { Write-Host "Not Installed." }


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: NETWORK INFORMATION"

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: HOSTS FILE"

Write-Host "Get content of etc\hosts file"
Get-Content "c:\windows\system32\drivers\etc\hosts"

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: IP INFORMATION"

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Ipconfig ALL"
Start-Process ipconfig.exe -ArgumentList "/all" -Wait -NoNewWindow


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: DNS Cache"
ipconfig /displaydns | Select-String "Record" | ForEach-Object { Write-Host $('{0}' -f $_) }
 
Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: LISTENING PORTS"

Start-Process NETSTAT.EXE -ArgumentList "-ano" -Wait -NoNewWindow


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: ARP Table"

Start-Process arp -ArgumentList "-A" -Wait -NoNewWindow

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Routes"

Start-Process route -ArgumentList "print" -Wait -NoNewWindow

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Network Adapter info"

Get-NetAdapter | ForEach-Object { 
  Write-Host "----------"
  Write-Host $_.Name
  Write-Host $_.InterfaceDescription
  Write-Host $_.ifIndex
  Write-Host $_.Status
  Write-Host $_.MacAddress
  Write-Host "----------"
} 


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Checking for WiFi passwords"

((netsh.exe wlan show profiles) -match '\s{2,}:\s').replace("    All User Profile     : ", "") | ForEach-Object {
  netsh wlan show profile name="$_" key=clear 
}


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Enabled firewall rules - displaying command only - it can overwrite the display buffer"
Write-Host -ForegroundColor Blue "=========:: show all rules with: netsh advfirewall firewall show rule dir=in name=all"

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: SMB SHARES"
Write-Host "Will enumerate SMB Shares and Access if any are available" 

Get-SmbShare | Get-SmbShareAccess | ForEach-Object {
  $QZOvhq7s3FGn64jgO085DzA = $_
  whoami.exe /groups /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty 'group name' | ForEach-Object {
    if ($QZOvhq7s3FGn64jgO085DzA.AccountName -like $_ -and ($QZOvhq7s3FGn64jgO085DzA.AccessRight -like "Full" -or "Change") -and $QZOvhq7s3FGn64jgO085DzA.AccessControlType -like "Allow" ) {
      Write-Host -ForegroundColor red "$($QZOvhq7s3FGn64jgO085DzA.AccountName) has $($QZOvhq7s3FGn64jgO085DzA.AccessRight) to $($QZOvhq7s3FGn64jgO085DzA.Name)"
    }
  }
}

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: USER INFO"
Write-Host "== :: Generating List of all Administrators, Users and Backup Operators (if any exist)"

@("ADMINISTRATORS", "USERS") | ForEach-Object {
  Write-Host $_
  Write-Host "-------"
  Start-Process net -ArgumentList "localgroup $_" -Wait -NoNewWindow
}
Write-Host "BACKUP OPERATORS"
Write-Host "-------"
Start-Process net -ArgumentList 'localgroup "Backup Operators"' -Wait -NoNewWindow


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: USER DIRECTORY ACCESS CHECK"
Get-ChildItem C:\Users\* | ForEach-Object {
  if (Get-ChildItem $_.FullName -ErrorAction SilentlyContinue) {
    Write-Host -ForegroundColor red "Read Access to $($_.FullName)"
  }
}

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: WHOAMI INFO"
Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Check Token access here: https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens" -ForegroundColor yellow
Write-Host -ForegroundColor Blue "=========:: Check if you are inside the Administrators group or if you have enabled any token that can be use to escalate privileges like SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebbugPrivilege"
Write-Host "https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#users-and-groups" -ForegroundColor Yellow
Start-Process whoami.exe -ArgumentList "/all" -Wait -NoNewWindow


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Cloud Credentials Check"
$ccnIeoXJQJi = (Get-ChildItem C:\Users).Name
$2Zu1HxVBRC = @(".aws\credentials",
  "AppData\Roaming\gcloud\credentials.db",
  "AppData\Roaming\gcloud\legacy_credentials",
  "AppData\Roaming\gcloud\access_tokens.db",
  ".azure\accessTokens.json",
  ".azure\azureProfile.json") 
foreach ($bMqQXMZGttpeyCbHSCbejMUP in $ccnIeoXJQJi) {
  $2Zu1HxVBRC | ForEach-Object {
    if (Test-Path "c:\$bMqQXMZGttpeyCbHSCbejMUP\$_") { Write-Host "$_ found!" -ForegroundColor Red }
  }
}


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: APPcmd Check"
if (Test-Path ("$FjTgcdZ:SystemRoot\System32\inetsrv\appcmd.exe")) {
  Write-Host "https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#appcmd.exe" -ForegroundColor Yellow
  Write-Host "$FjTgcdZ:SystemRoot\System32\inetsrv\appcmd.exe exists!" -ForegroundColor Red
}


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: OpenVPN Credentials Check"

$gfoqy1nRwlduN = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs" -ErrorAction SilentlyContinue
if ($gfoqy1nRwlduN) {
  Add-Type -AssemblyName System.Security
  $wDebheTTvue = $gfoqy1nRwlduN | ForEach-Object { Get-ItemProperty $_.PsPath }
  foreach ($oh21HjDRpuyevJwIrdE9Gl in $wDebheTTvue) {
    $x2FS = $oh21HjDRpuyevJwIrdE9Gl.'auth-data'
    $aswMlyQB = $oh21HjDRpuyevJwIrdE9Gl.'entropy'
    $aswMlyQB = $aswMlyQB[0..(($aswMlyQB.Length) - 2)]

    $d21YVNHD5E0MGJZom8 = [System.Security.Cryptography.ProtectedData]::Unprotect(
      $x2FS, 
      $aswMlyQB, 
      [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
 
    Write-Host ([System.Text.Encoding]::Unicode.GetString($d21YVNHD5E0MGJZom8))
  }
}


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: PowerShell History (Password Search Only)"

Write-Host "=:: PowerShell Console History"
Write-Host "=:: To see all history, run this command: Get-Content (Get-PSReadlineOption).HistorySavePath"
Write-Host $(Get-Content (Get-PSReadLineOption).HistorySavePath | Select-String pa)

Write-Host "=:: AppData PSReadline Console History "
Write-Host "=:: To see all history, run this command: Get-Content $FjTgcdZ:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
Write-Host $(Get-Content "$FjTgcdZ:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" | Select-String pa)


Write-Host "=:: PowesRhell default transrcipt history check "
if (Test-Path $FjTgcdZ:SystemDrive\transcripts\) { "Default transcripts found at $($FjTgcdZ:SystemDrive)\transcripts\" }


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: ENVIRONMENT VARIABLES "
Write-Host "Maybe you can take advantage of modifying/creating a binary in some of the following locations"
Write-Host "PATH variable entries permissions - place binary or DLL to execute instead of legitimate"
Write-Host "https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dll-hijacking" -ForegroundColor Yellow

Get-ChildItem env: | Format-Table -Wrap


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Sticky Notes Check"
if (Test-Path "C:\Users\$FjTgcdZ:USERNAME\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite") {
  Write-Host "Sticky Notes database found. Could have credentials in plain text: "
  Write-Host "C:\Users\$FjTgcdZ:USERNAME\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite"
}

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Cached Credentials Check"
Write-Host "https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#windows-vault" -ForegroundColor Yellow 
cmdkey.exe /list


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Checking for DPAPI RPC Master Keys"
Write-Host "Use the Mimikatz 'dpapi::masterkey' module with appropriate arguments (/rpc) to decrypt"
Write-Host "https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dpapi" -ForegroundColor Yellow

$9Msg3m = "C:\Users\$FjTgcdZ:USERNAME\AppData\Roaming\Microsoft\"
$zcx79VKrN5waJ1tYk0CIHZpLD = "C:\Users\$FjTgcdZ:USERNAME\AppData\Local\Microsoft\"
if ( Test-Path "$9Msg3m\Protect\") {
  Write-Host "found: $9Msg3m\Protect\"
  Get-ChildItem -Path "$9Msg3m\Protect\" -Force | ForEach-Object {
    Write-Host $_.FullName
  }
}
if ( Test-Path "$zcx79VKrN5waJ1tYk0CIHZpLD\Protect\") {
  Write-Host "found: $zcx79VKrN5waJ1tYk0CIHZpLD\Protect\"
  Get-ChildItem -Path "$zcx79VKrN5waJ1tYk0CIHZpLD\Protect\" -Force | ForEach-Object {
    Write-Host $_.FullName
  }
}


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Checking for DPAPI Cred Master Keys"
Write-Host "Use the Mimikatz 'dpapi::cred' module with appropriate /masterkey to decrypt" 
Write-Host "You can also extract many DPAPI masterkeys from memory with the Mimikatz 'sekurlsa::dpapi' module" 
Write-Host "https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dpapi" -ForegroundColor Yellow

if ( Test-Path "$9Msg3m\Credentials\") {
  Get-ChildItem -Path "$9Msg3m\Credentials\" -Force
}
if ( Test-Path "$zcx79VKrN5waJ1tYk0CIHZpLD\Credentials\") {
  Get-ChildItem -Path "$zcx79VKrN5waJ1tYk0CIHZpLD\Credentials\" -Force
}


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Current Logged on Users"
try { quser }catch { Write-Host "'quser' command not not present on system" } 


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Remote Sessions"
try { qwinsta } catch { Write-Host "'qwinsta' command not present on system" }


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Kerberos tickets (does require admin to interact)"
try { klist } catch { Write-Host "No active sessions" }


Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Printing ClipBoard (if any)"
Get-ClipBoardText

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Unattended Files Check"
@("C:\Windows\sysprep\sysprep.xml",
  "C:\Windows\sysprep\sysprep.inf",
  "C:\Windows\sysprep.inf",
  "C:\Windows\Panther\Unattended.xml",
  "C:\Windows\Panther\Unattend.xml",
  "C:\Windows\Panther\Unattend\Unattend.xml",
  "C:\Windows\Panther\Unattend\Unattended.xml",
  "C:\Windows\System32\Sysprep\unattend.xml",
  "C:\Windows\System32\Sysprep\unattended.xml",
  "C:\unattend.txt",
  "C:\unattend.inf") | ForEach-Object {
  if (Test-Path $_) {
    Write-Host "$_ found."
  }
}

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: SAM / SYSTEM Backup Checks"

@(
  "$FjTgcdZ:windir\repair\SAM",
  "$FjTgcdZ:windir\System32\config\RegBack\SAM",
  "$FjTgcdZ:windir\System32\config\SAM",
  "$FjTgcdZ:windir\repair\system",
  "$FjTgcdZ:windir\System32\config\SYSTEM",
  "$FjTgcdZ:windir\System32\config\RegBack\system") | ForEach-Object {
  if (Test-Path $_ -ErrorAction SilentlyContinue) {
    Write-Host "$_ Found!" -ForegroundColor red
  }
}

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Group Policy Password Check"

$2eUITt9O5bYXQ7qlNf = @("Groups.xml", "Services.xml", "Scheduledtasks.xml", "DataSources.xml", "Printers.xml", "Drives.xml")
if (Test-Path "$FjTgcdZ:SystemDrive\Microsoft\Group Policy\history") {
  Get-ChildItem -Recurse -Force "$FjTgcdZ:SystemDrive\Microsoft\Group Policy\history" -Include @GroupPolicy
}

if (Test-Path "$FjTgcdZ:SystemDrive\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history" ) {
  Get-ChildItem -Recurse -Force "$FjTgcdZ:SystemDrive\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history"
}

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Recycle Bin TIP:"
Write-Host "if credentials are found in the recycle bin, tool from nirsoft may assist: http://www.nirsoft.net/password_recovery_tools.html" -ForegroundColor Yellow

Write-Host ""
if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========::  Password Check in Files/Folders"

if ($OPdgpeGw8aHVn7WA) { TimeElapsed }
Write-Host -ForegroundColor Blue "=========:: Password Check. Starting at root of each drive. This will take some time. Like, grab a coffee or tea kinda time."
Write-Host -ForegroundColor Blue "=========:: Looking through each drive, searching for $oQyLLaGfuDhnRObrF"
try { New-Object -ComObject Excel.Application | Out-Null; $VN7OYFCOwxD3dsAR6OPErvYPJ = $true }catch {$VN7OYFCOwxD3dsAR6OPErvYPJ = $false; if($a97u10gzE0qzxiF5KZFrQYMg){
  Write-Host -ForegroundColor Yellow "Host does not have Excel COM object, will still point out excel files when found."
}}
$HTK0fzo5N328LdJxAa.Root | ForEach-Object {
  $fB4da98APXwp = $_
  Get-ChildItem $fB4da98APXwp -Recurse -Include $oQyLLaGfuDhnRObrF -ErrorAction SilentlyContinue -Force | ForEach-Object {
    $MCGw5335R5Rj = $_
    if ($MCGw5335R5Rj.FullName | select-string "(?i).*lang.*") {
      #Write-Host "$($_.FullName) found!" -ForegroundColor red
    }
    if($MCGw5335R5Rj.FullName | Select-String "(?i).:\\.*\\.*Pass.*"){
      write-host -ForegroundColor Blue "$($MCGw5335R5Rj.FullName) contains the word 'pass'"
    }
    if($MCGw5335R5Rj.FullName | Select-String ".:\\.*\\.*user.*" ){
      Write-Host -ForegroundColor Blue "$($MCGw5335R5Rj.FullName) contains the word 'user' -excluding the 'users' directory"
    }
    elseif ($MCGw5335R5Rj.FullName | Select-String ".*\.xls",".*\.xlsm",".*\.xlsx") {
      if ($VN7OYFCOwxD3dsAR6OPErvYPJ -and $a97u10gzE0qzxiF5KZFrQYMg) {
        Search-Excel -Source $MCGw5335R5Rj.FullName -SearchText "user"
        Search-Excel -Source $MCGw5335R5Rj.FullName -SearchText "pass"
      }
    }
    else {
      if ($MCGw5335R5Rj.Length -gt 0) {
        # Write-Host -ForegroundColor Blue "Path name matches extension search: $MCGw5335R5Rj"
      }
      if ($MCGw5335R5Rj.FullName | Select-String "(?i).*SiteList\.xml") {
        Write-Host "Possible MCaffee Site List Found: $($_.FullName)"
        Write-Host "Just going to leave this here: https://github.com/funoverip/mcafee-sitelist-pwd-decryption" -ForegroundColor Yellow
      }
      $mGzJV8baDYoLX.keys | ForEach-Object {
        $soY1JU = Get-Content $MCGw5335R5Rj.FullName -ErrorAction SilentlyContinue -Force | Select-String $mGzJV8baDYoLX[$_] -Context 1, 1
        if ($soY1JU) {
          Write-Host "Possible Password found: $_" -ForegroundColor Yellow
          Write-Host $MCGw5335R5Rj.FullName
          Write-Host -ForegroundColor Blue "$_ triggered"
          Write-Host $soY1JU -ForegroundColor Red
        }
      }
    }  
  }
} 