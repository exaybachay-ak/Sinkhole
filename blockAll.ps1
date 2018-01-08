clear

#Set error action to silent, to suppress info
$ErrorActionPreference = "SilentlyContinue"

#Notify user that we are downloading blacklists
write-output "Downloading blacklists... please wait..."

#Retreive blacklist hosts from various sources
$greensnow = (invoke-webrequest -URI "blocklist.greensnow.co/greensnow.txt" -UseBasicParsing -TimeoutSec 60)
$bambenek = (invoke-webrequest -URI "osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt" -UseBasicParsing -TimeoutSec 60)
$alienvault = (invoke-webrequest -URI "https://reputation.alienvault.com/reputation.unix" -UseBasicParsing -TimeoutSec 60)


#Echo all ip addresses out into a full blacklist file
$greensnow.rawcontent > blacklist.txt
$banbenek.rawcontent >> blacklist.txt
$alientvault.rawcontent >> blacklist.txt

#Filter out non-ip addresses from list
$blacklist = get-content blacklist.txt | select-string -pattern "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"

$blacklist | %{
  New-NetRoute -DestinationPrefix $_/32 -InterfaceIndex 1 -NextHop 0.0.0.0
}