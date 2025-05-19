# Powershell Script inWebo Syslog Synchro (IWSS) v1.0
# (c)2023 inWebo - v1.0
# DISCLAIMER : This script is provided "AS IS" WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES of any kind
#              You use this script at your know risk
# Help with -help option command line. Implemented at the end of the script

#region Parameters
# CommandLine Args management
[CmdletBinding(DefaultParameterSetName='noloop')]
Param (										
    # Show help
    [Parameter(ParameterSetName='help')]
    [Alias('?','h')][switch]$help=$false,
    # Bearer token for authentication. Can be either a string or the content of file within script folder with '@file.txt'
	[Parameter(ParameterSetName='noloop')]
    [Alias('t','tok')][string]$token='',
    # if sec is set the bearer tokenf file will be secure on the storage for the current user use only
	[Parameter(ParameterSetName='noloop')]
    [Alias('st','sec')][switch]$SecureToken=$false,
    # Fetch logs since startdate (if present override lastid from iwss.json)
	[Parameter(ParameterSetName='noloop')]
    [Alias('sd')][datetime]$startdate,
    # Fetch logs since n days (if present override -startdate or lastid from iwss.json)
	[Parameter(ParameterSetName='noloop')]
    [Alias('d')][int]$days,
    # syslog server (if present override server from iwss.json)
	[Parameter(ParameterSetName='noloop')]
    [Alias('s')][string]$server,
    # syslog server port (if present override port from iwss.json)
	[Parameter(ParameterSetName='noloop')]
    [Alias('p')][string]$port,
    # syslog server transport (if present override transport from iwss.json)
	[Parameter(ParameterSetName='noloop')]
    [ValidateSet("UDP","TCP","TCPwithTLS")]
    [Alias('trsp')][string]$transport='UDP',
    # syslog logentry severity (if present override severity from iwss.json)
	[Parameter(ParameterSetName='noloop')]
    [Alias('sev')][string]$severity,
    # syslog logentry facility (if present override facility from iwss.json)
	[Parameter(ParameterSetName='noloop')]
    [Alias('f')][string]$facility,
    # syslog logentry appname (if present override facility from iwss.json)
	[Parameter(ParameterSetName='noloop')]
    [Alias('a','appname')][string]$applicationname,
    # syslog logentry hostname (if present override facility from iwss.json)
	[Parameter(ParameterSetName='noloop')]
    [Alias('host','hn')][string]$hostname,
    # Save current config (-server -port -severity -facility -appname -hostname)
	[Parameter(ParameterSetName='noloop')]
    [switch]$save=$false,
    # Count Size and number of logs, output in syslog end message
	[Parameter(ParameterSetName='noloop')]
    [Alias('c')][switch]$count=$false,
    # endless run recursive call
	[Parameter(ParameterSetName='loop')]
    [Alias('l')][switch]$loop,
    # time value for loop betwen each run (default 5 min);
    [Parameter(ParameterSetName='loop')]
    [int]$time=300,
    # Send script information to syslog also
    [Parameter(ParameterSetName='loop')]
    [Parameter(ParameterSetName='noloop')]
    [Alias('nss')][switch]$noscriptsyslog,
    # do not send syslog, show them locally, lastid in iwss.json not writed
    [Parameter(ParameterSetName='loop')]
    [Parameter(ParameterSetName='noloop')]
    [Alias('sim','simul')][switch]$simulate
)
#endregion

Write-Verbose ( "Start timestamp " + (get-date -f "yyyyMMddHHmmssfff") )

#region settings
# Version
$name="IWSS"
$version="1.0"
# Script variables for various things (log file, token file,  ...)
$ScriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
Set-Location $ScriptPath
$ScriptName = $MyInvocation.MyCommand.Name
$RootScriptName = $ScriptName.Split('.')[0]
# Don't show Invoke-WebRequest progress
$progressPreference = 'silentlyContinue'
$global:progressPreference = 'silentlyContinue'
$APIEndpoint='https://kiwi.myinwebo.com'

# Set these for verbose/debug messages appear
if ( [bool]$debug   = [bool]$PSCmdlet.MyInvocation.BoundParameters[“Debug”].IsPresent   ) { $DebugPreference   = “Continue” }
if ( [bool]$verbose = [bool]$PSCmdlet.MyInvocation.BoundParameters[“Verbose”].IsPresent ) { $VerbosePreference = “Continue” }

$configfile= (Join-Path $ScriptPath "iwss.json")
$newlastid=''
[uint32]$logcount=0
[uint64]$logsize=0

# Use posh-syslog for sending syslog. Provided here locally for convenience
# Can be installed also with 'Install-Module -Name Posh-SYSLOG' if access to PowershellGallery is available
if (!(Get-Module Posh-SYSLOG)) { Import-Module -Force ( Join-Path $scriptpath '.\Posh-SYSLOG\Posh-SYSLOG.psd1') }

# Show help recursive call
#if ($help) { get-help (Join-Path $ScriptPath $ScriptName) -Detailed ; return }
if ($help) { Get-Help -Name $PSCommandPath -Detailed ; return }

#endregion

#region Manage Token
$tokenfile=''
# if token option start with '@' and file exist retrieve content as token
if ($token.IndexOf("@") -eq 0 ) { $tokenfile = $token.trim('@'); if (!(Test-Path -Path $tokenfile -PathType Leaf)) { Write-Error "token file not found, exiting ..."; exit(1) } }

# if token not on command line try file 'token.txt' in same folder as current .ps1
if (!$token -And (Test-Path -Path (Join-Path $ScriptPath "token.txt") -PathType Leaf) ) { $tokenfile = (Join-Path $ScriptPath "token.txt") }

# Read token file
if ($tokenfile -and (Test-Path -Path $tokenfile -PathType Leaf)) { $token = Get-Content $tokenfile }

# Test token and decypher it if needed 
if ($token -and ($token.SubString(0,3) -ne 'eyJ') ) { $token =([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR(($token | ConvertTo-SecureString)))) }

# Cypher and overwrite tokenfile if needed (-sec)
if ($token -and $securetoken -and $tokenfile) { Set-Content -Path $tokenfile -value ($token | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString) }

# if no token exiting 
if (!$token) { Write-Error "No authentication token, exiting ..."; exit(1)  }
if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token, exiting ..."; exit (1) }

# Decode Token for Service nb
$tokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/')
#Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
while ($tokenPayload.Length % 4) { $tokenPayload += "=" }
$tokenArray = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($tokenPayload))  | ConvertFrom-Json
$ServiceID = $tokenArray.sub.split("/")[0]
$User = $tokenArray.sub.split("/")[1]

# Set the header with the token for REST API requests
$rest=@{
    Header = @{'authorization' = 'Bearer ' + $token }
    Method = "GET"
    Uri = $APIEndpoint
    }
# Set the hashtable for pour own syslog events
$log=@{
    timestamp = ''
    serviceID = $ServiceID
    user = $User
    lastid = ''
    log = ''
    }

#endregion

#region Manage configuration
# Get config from file in script folder
if (Test-Path -Path $configfile -PathType Leaf) { $conf = Get-Content $configfile | ConvertFrom-Json | % {$_} }
if ($server   ) { $conf.server   =$server   }
if ($port     ) { $conf.port     =$port     }
if ($severity ) { $conf.severity =$severity }
if ($facility ) { $conf.facility =$facility }
if ($applicationname  ) { $conf.appname  =$applicationname  }
if ($hostname ) { $conf.hostname =$hostname }
if ($transport) { $conf.transport=$transport}
if ($save     ) { $conf | ConvertTo-Json | set-content "iwss.json"; exit(0) }
if ($startdate) { $conf.lastid  = Get-Date $startdate -f "yyyyMMddHHmmss00000" }
if ($days     ) { $conf.lastid  = Get-Date (Get-Date).AddDays(-$days) -f "yyyyMMddHHmmss00000" }

#define hashtable parameters for Send-syslogMessage
$SyslogParameters = @{}
$conf.psobject.properties | % { $SyslogParameters[$_.Name] = $_.Value }
$SyslogParameters.Remove('lastid')
Write-Verbose ("Syslog parameters : " + [pscustomobject]$SyslogParameters)
#endregion

# Get last ID from conf and increment one to not get the old last one
$lastid=([uint64]($conf.lastid)+1).tostring()
Write-Verbose ( $name + " version " + $version )
Write-Verbose ( "Fetch logs from serviceID : " + $serviceid + " with user : " + $user )
Write-Verbose ( "Start sending logs from ID : " + $lastid )

# own syslog
if (!$noscriptsyslog) {
    $log.log = ($conf.appname + ' start')
    $log.lastid = $lastid
    $log.timestamp = (get-date -f "yyyyMMddHHmmssfff")
    if ($loop) {$log.log = ($conf.appname + ' loop start')}
    #Send-SyslogMessage -ApplicationName $conf.appname -hostname $conf.hostname -Server $conf.server -port $conf.port -Severity $conf.severity -Facility $conf.facility -Message ($log | ConvertTo-Json)
    if (!$simulate) {Send-SyslogMessage @SyslogParameters -Message ($log | ConvertTo-Json)}
    }

# Online logs start 5 weeks ago
$lastarchivelogid =Get-Date (Get-Date).AddDays(-35) -f "yyyyMMddHHmmss99999"

# if lastid older than 5 weeks use archive log first
# Get Archive logs (from $lastid to -5 weeks) , 
if ([uint64]$lastid -lt [uint64]$lastarchivelogid) {
    $hasmore=$true
    $rest.uri = $APIEndpoint + "/audit/v2/customer/export/archive?limit=10000&fromId=" + $lastid
    Write-Verbose "Sending archive logs to syslog" 
    while ($hasmore) {
        $VerbosePreference = “SilentlyContinue”
        $resp=Invoke-RestMethod @rest
        if ($verbose) {$VerbosePreference = “Continue”}
        
        $resp.content | % {
            $message = ($_ | Convertto-Json)
            if ($count) {$logsize += $message.length}
            if (!$simulate) {Send-SyslogMessage @SyslogParameters -Message $Message}
            if ($simulate) { $_.psobject.properties.value -join ',' }
            }
        
        $hasmore=$resp.hasMore
        if ($hasmore) { $rest.uri= $APIEndpoint + $resp.nextPage ; Write-Verbose "More    archive logs to syslog"}
        # compute highest id
        if (($resp.content.count -gt 0) -and ([uint64]($resp.content.id | sort | select -last 1) -gt [uint64]$newlastid)) {$newlastid=($resp.content.id | sort | select -last 1)}
        if ($count) {$logcount += $resp.size}
    }
}

# Start fetching events in online from last one from archive (archive logs can overlap online logs if there is less than 13 months logs) if archive was used before
if ($newlastid -ne '') { $lastid=([uint64]($newlastid)+1).tostring() }

# Get Online logs (from -5 weeks to now)
$hasmore=$true
$Paging=0
$rest.uri=$APIEndpoint + "/audit/v2/customer/export/online?limit=10000&fromId=" + $LastId + "&page=" + $Paging

while ($hasmore) {
    Write-Verbose "Sending online logs to syslog" 
    $VerbosePreference = “SilentlyContinue”
    $resp=Invoke-RestMethod @rest
    if ($verbose) {$VerbosePreference = “Continue”}
    
    $resp.content | % {
        $message = ($_ | Convertto-Json)
        if ($count) {$logsize += $message.length}
        if (!$simulate) {Send-SyslogMessage @SyslogParameters -Message $Message}
        if ($simulate) { $_.psobject.properties.value -join ',' }

        }
    
    $hasmore=$resp.hasMore
    if ($hasmore) { $rest.uri=$APIEndpoint + "/audit/v2/customer/export/online?limit=10000&fromId=" + $LastId + "&page=" + ++$Paging  ; Write-Verbose "More    online logs to syslog" }
    # compute highest id
    if (($resp.content.count -gt 0) -and ([uint64]($resp.content.id | sort | select -last 1) -gt [uint64]$newlastid)) {$newlastid=($resp.content.id | sort | select -last 1)}
    if ($count) {$logcount += $resp.size}
}

# Show counters
if ($count -and $logcount) {Write-verbose ("Nb events : {0}  Size : {1} Average Size/Log : {2:n0}" -f $logcount,$logsize ,($logsize/$logcount) )}
    
# Write new last id to config file as lastid
if (!$simulate -and ($newlastid -ne '')) {
    $conf.lastid=$newlastid
    $conf | ConvertTo-Json | set-content $configfile
    Write-verbose ("Events Sent to syslog until ID : " + $newlastid )
    
}
else { Write-verbose " -- No new events --" }
# own syslog
if (!$noscriptsyslog) {
    $log.log = ($conf.appname + ' end')
    $log.timestamp = (get-date -f "yyyyMMddHHmmssfff")
    $log.lastid=$newlastid
    if ($count) {
        $log.count = $logcount
        $log.size = $logsize
        $log.avgsize = "{0:n0}" -f ($logsize / $logcount)
        }
    if ($loop) {$log.log = ($conf.appname + ' loop end')}
    if (!$simulate) {Send-SyslogMessage @SyslogParameters -Message ($log | ConvertTo-Json)}
    }

#region recursive call for loop
if ($loop) {  Write-verbose ("Loop, waiting "+ $time +" secondes ...") ; sleep $time; Invoke-Expression -Command $PSCmdlet.MyInvocation.Line}
#endregion

Write-Verbose ( "End timestamp " + (get-date -f "yyyyMMddHHmmssfff") )

<#
.SYNOPSIS
inWebo Syslog Synchro (IWSS)
(c)2023 inWebo - v1.0
DISCLAIMER : This script is provided "AS IS" WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES of any kind. You use this script at your know risk

.DESCRIPTION
This script can be use to sent inWebo Audit trail to a syslog server
The use of this script required:
    * A valid Bearer Token for REST API from the inWebo service console
    * Powershell at least v5.1 must be available (Windows 10)
	* .Net 4.5 must be installed to support TLS 1.2 and 1.3

This script use a local, already provided version (4.1.5), module posh-SYSLOG
https://github.com/poshsecurity/Posh-SYSLOG

This script use and keep a configuration file 'iwss.json' in same folder as the script
You can manually edit this file and/or use the provided command line parameters described below

inWebo audit trail are updated every 5 minutes, so there is no need/reason to run this script with a lower period
The recommanded run frequency is the default loop value or a scheduled task every 5 minutes (or more, every 10 minutes, every 15 minutes, ...)

You need to run first the following to set the configuration, or manually edit the "iwss.json" file
.\iwss.ps1 -server <syslogserver> -port <port> -facility "local0" -severity "info" -appname "iwss-1.0" -hostname <hostname> -save

If you wish to send all available logs from inWebo audit trail use the following (recommended as first run to retrieve all past logs) :
.\iwss.ps1 -days 395


Versions history :	
v1.0 - 2023.02.10	- Internal ALPHA Version

.INPUTS
None. You cannot pipe objects to this script

.OUTPUTS
None

.PARAMETER  help
Show this detailed help

.PARAMETER  token
Optional, default to "token.txt" in script folder
Aliases : t, tok
Administrator Bearer Token from inwebo Service console
can be provided inline with  "-token 'value_of_the_token'"
or within a file with "-token '@c:\tmp\file.txt'" (relative or absolute path)
without value, if a file 'token.txt' is found in the script folder it's content will be used as token's value

.PARAMETER securetoken
Optional, default is false
Aliases : s, sec
Option to encrypt the provided token file (either @file.txt or default token.txt) for future uses for the current user

.PARAMETER startdate <DateTime>
    Fetch logs since startdate (if present override lastid from iwss.json)
        
.PARAMETER days
    Fetch logs since n days (if present override -startdate or lastid from iwss.json)
        
.PARAMETER server
    syslog server (if present override server from iwss.json)
        
.PARAMETER port
    syslog server port (if present override port from iwss.json)

.PARAMETER transport
    syslog server transport (if present override port from iwss.json)
    'UDP' or 'TCPwithTLS'
        
.PARAMETER severity
    syslog logentry severity (if present override severity from iwss.json)
        
.PARAMETER facility
    syslog logentry facility (if present override facility from iwss.json)
        
.PARAMETER appname
    syslog logentry appname (if present override facility from iwss.json)
        
.PARAMETER hostname
    syslog logentry hostname (if present override facility from iwss.json)
        
.PARAMETER save
    Save current config (-server -port -severity -facility -appname -hostname)
        
.PARAMETER loop
    Optional, no default
        
.PARAMETER time
    Optional, default 300 seconds (5mins)
        
.PARAMETER noscriptsyslog
    do not send script informations to syslog also

.PARAMETER simulate
    do not send events to syslog. Do not update lastid in iwss.json

.EXAMPLE
PS> .\iwss.ps1 -server <syslogserver> -port <port> -facility "local0" -severity "info" -appname "iwss-1.0" -hostname <hostname> -save
save configuration in file  "iwss.json" in script folder

.EXAMPLE
PS> .\iwss.ps1 -days 395 -sec
Send all available logs from inWebo audit trail (recommended as first run to retrieve all past logs)
using default token ".\mytoken.txt" as token and secure it for current user and future uses
Be aware that can be huge

.EXAMPLE
PS> .\iwss.ps1
Send new logs since last synchro 

.EXAMPLE
PS> .\iwss.ps1 -loop -time 600 -token "@c:\inwebo\mytoken.txt"
Send new logs continously every 10minutes, using "c:\inwebo\mytoken.txt" as token

.EXAMPLE
PS> .\iwss.ps1 -verbose -count -days 100
Send logs from the last 100 days, verbose output with counters (count, totalsize, avg size/log)
Be aware that if you already sent logs, this will be sent them again

.EXAMPLE
PS> .\iwss.ps1 -count -verbose -simul -d 395
Retrieve locally all logs and show counters (count, totalsize, avg size/log)
Be aware that can be huge


#>