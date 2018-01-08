<#    

      #Powershell blackhole script
          Just run this script and it will re-route potentially malicious traffic to null
          In order to verify this, try run a to traceroute to 64.182.208.181 (<-- update this address later)
            Your traceroute should route to null because this software has configured a rule to force specific outbound
            traffic to the localhost bitbucket
          If you want to un-do the changes, select the reverse changes option and it will roll things back.  If something
          went wrong and the rules are "stuck" on, then re-run this script with the -undo switch.  This will go in and
          remove any settings that the script would have implemented, basically by running the script in reverse.
  
      NOTE: At least half of the credit should go to Dave Kennedy and @BinaryDefense for making GoatRider.  
             Although the main component is the idea of re-routing to null, and the ease of use, GoatRider was what brought it all together
  
      #Program flow:
      To bounce malicious inbound/outbound traffic:  Run bounce.ps1
      To undo change made previously by this script: Run bounce.ps1 -undo
      #Primary powershell command
      New-NetRoute -DestinationPrefix "152.195.54.20/32" -InterfaceIndex 1 -NextHop 127.0.0.1
      #OSINT Threat Sources:
      https://www.esentire.com/news-and-events/press-releases/esentire-launches-largest-open-source-threat-intelligence-aggregator/
      https://github.com/hslatman/awesome-threat-intelligence
      http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt
      http://blocklist.greensnow.co/greensnow.txt
      https://intel.criticalstack.com/user/sign_up
      https://github.com/BinaryDefense/goatrider/blob/master/goatrider.py
      *more to be added later*
      #Known hosting platform IP blocks
      http://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html
      http://www.senderbase.org/lookup/org/?search_string=OVH%20SAS
      
#>

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

#Notify user that setup tasks are done
write-output "Done downloading and setting up blacklist files"

#Set up functions for blocking and unblocking
function Block-Hosts
{
  $blacklist | %{
    New-NetRoute -DestinationPrefix $_/32 -InterfaceIndex 1 -NextHop 0.0.0.0
  }
}

function Unblock-Hosts
{
  $blacklist | %{
    Remove-NetRoute -NextHop "0.0.0.0" -Confirm:$false 2>&1 | out-null
  }
}

function blockOneHost
{
  $hosttemp = Read-host -prompt 'Host to block:'
  New-NetRoute -DestinationPefix "$hosttemp/32" -InterfaceIndex 1 -NextHop 0.0.0.0
  pause
}

function displayRoutes
{
  Get-NetRoute
}

function displayMenu
{
  clear
  write-host "What would you like to do?"
  write-host ""
  write-host "1. Blacklist everything!"
  write-host "2. Crap I messed everything up, UNBLOCK IT ALL!!!"
  write-host "3. Just add one host to block"
  write-host "4. Black a comma separated list of hosts"
  write-host "5. Show me the current routing table"
  write-host "6. Exit"
  write-host "============================================="

  $userresponse = Read-Host -Prompt 'Your Choice:'  


  if($userresponse -eq "1"){
    Block-Hosts
    displayMenu
  }

  if($userresponse -eq "2"){
    Unblock-Hosts
    displayMenu
  }

  if($userresponse -eq "3"){
    blockOneHost
    displayMenu
  }

  if($userresponse -eq "4"){
    $hosts = (Read-host -Prompt 'Enter a list of hosts:').split(',') | ForEach-Object {$_.trim()}
    $hosts | %{
      New-NetRoute -DestinationPrefix $_/32 -InterfaceIndex 1 -NextHop 0.0.0.0
    }
    displayMenu
  }

  if($userresponse -eq "5"){
    Get-NetRoute
    pause
    displayMenu
  }

  if($userresponse -eq "6"){
    write-output "Attempting to kill the script NOW"
    return
    exit
  }

  else{
    write-host "You did something weird, try again"
    displayMenu
  }
}


#Clear the screen and make sure user is root
clear
write-host "please indicate you understand by typing 'OKAY'"
$warning = Read-Host -Prompt "YOU MUST BE RUNNING THIS AS ROOT!!!"

#Display the menu
displayMenu