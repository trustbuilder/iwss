# Object

This powershell script provide a way to send inWebo MFA audit log to a syslog server or a SIEM

# Requirements

*   Powershell 5.1
*   .NET 4.5 framework
*   A valid API token from inWebo tenant for the ServiceID
*   The main script use a powershell module called ‘Posh-SYSLOG’ shipped for convenience within a folder. This folder must be in the same folder as the main script.  
    Alternatively this module can be installed from Powershell Galery with the command  ‘Install-Module -Name Posh-SYSLOG’  
    See details here : [https://github.com/poshsecurity/Posh-SYSLOG](https://github.com/poshsecurity/Posh-SYSLOG)

# Known limitations

*   There is no real error handling (especially for REST APIs requests), but in practice errors should not occur
*   There is no proxy implementation for inWebo API requests nor for syslog request

# Usage

This script use a json config file (‘iwss.json’) in the same folder. This config file retain syslog configuration and the last event id already sent to syslog, for starting from this one at the next run.

You can manually edit the file for the settings if you need.

*   First run for settings syslog parameters :  
    PS> .\\iwss.ps1 -server <syslogserver> -port <port> -facility "local0" -severity "info" -appname "iwss-1.0" -hostname <hostname> -save
*   Second run for retrieve all inwebo audit logs and sent them to syslog/siem (395 days, inwebo retain only 13 months max of data) using default token ".\\mytoken.txt" as token and secure it for current user and future uses (Be aware that can be huge:  
    PS> .\\iwss.ps1 -days 395 -sec
*   Further periodic run to periodically update events to syslog/SIEM, either with
    *   a scheduled task every 5minutes, with the command (preferred method):  
        PS> .\\iwss.ps1
    *   or internal loop command (the powershell script will run indefinitely ) :  
        PS> .\\iwss.ps1 -loop -time 300

NB. : 5 minutes is the minimum delay between 2 updates of inWebo audit trail updates. There is no need to set less

## Other examples :

PS> .\\iwss.ps1 -verbose -count -days 100

Send logs from the last 100 days, verbose output with counters (count, totalsize, avg size/log)  
Be aware that if you already sent logs, this will be sent them again

 PS> .\\iwss.ps1 -count -verbose -simul -d 395

Retrieve locally all logs and show counters (count, totalsize, avg size/log)  
Be aware that can be huge

# Command line

## PARAMETER  help

Show this detailed help

## PARAMETER  token

Optional, default to “token.txt” in script folder  
Aliases : t, tok  
Administrator Bearer Token from inWebo Service console  
Can be provided inline with  -token 'raw value\_of\_the\_token'  
or within a file with -token “@c:\\tmp\\file.txt” (relative or absolute path)  
without value, if a file ‘token.txt’ is found in the script folder it's content will be used as token's value  
It’s possible to secure the content of token file for current windows user using the -secureToken parameter

## PARAMETER securetoken

Optional, default is false  
Aliases : st, sec  
Option to encrypt the provided token file (either ‘@file.txt’ or default ‘token.txt’) for future uses for the current user only  
This use PowerShell SecureString

##  PARAMETER startdate

Optional, no default  
Aliases : sd  
Fetch logs since startdate (if present override lastid from iwss.json)

## PARAMETER days

Optional, no default  
Aliases : d  
Fetch logs since n days (if present override -startdate or lastid from iwss.json)

## PARAMETER server

Optional, no default  
Value from ‘iwss.json’  
Syslog server  
If present override server from ‘iwss.json’

## PARAMETER port

Optional, no default  
Value from ‘iwss.json’  
Syslog server port  
If present override port from iwss.json

##  PARAMETER transport

Optional, no default  
Value from ‘iwss.json’  
Possible values : 'UDP', 'TCP' or 'TCPwithTLS'  
Syslog server transport  
If present override transport from ‘iwss.json’

## PARAMETER severity

Optional, no default  
Value from ‘iwss.json’  
Syslog logentry severity  
If present override severity from ‘iwss.json’

## PARAMETER facility

Optional, no default  
Value from ‘iwss.json’  
Syslog logentry facility  
If present override facility from ‘iwss.json’

## PARAMETER applicationname

Optional, no default  
Value from ‘iwss.json’  
Syslog logentry applicationname  
If present override applicationname from ‘iwss.json’

## PARAMETER hostname

Optional, no default  
Value from ‘iwss.json’  
Syslog logentry hostname  
If present override hostname from ‘iwss.json’

## PARAMETER save

Optional, no default  
Save current config (-server -port -severity -facility -applicationname -hostname)

## PARAMETER loop

Optional, no default  
Do not close the script but run indefinitely, run each time define by parameter time

## PARAMETER time

 Optional, default 300 seconds (5mins)

## PARAMETER noscriptsyslog

Optional, no default  
Do not send script informations to syslog also

## PARAMETER simulate

Optional, no default

Do not send events to syslog  
Do not update lastid in iwss.json
