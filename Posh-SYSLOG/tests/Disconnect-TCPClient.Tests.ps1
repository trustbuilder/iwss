$script:ModuleName = 'Posh-SYSLOG'

# Removes all versions of the module from the session before importing
Get-Module $ModuleName | Remove-Module

$ModuleBase = Split-Path -Parent $MyInvocation.MyCommand.Path

# For tests in .\Tests subdirectory
if ((Split-Path $ModuleBase -Leaf) -eq 'Tests') {
    $ModuleBase = Split-Path $ModuleBase -Parent
}

## This variable is for the VSTS tasks and is to be used for referencing any mock artifacts
$Env:ModuleBase = $ModuleBase

Import-Module $ModuleBase\$ModuleName.psd1 -PassThru -ErrorAction Stop | Out-Null

# InModuleScope runs the test in module scope.
# It creates all variables and functions in module scope.
# As a result, test has access to all functions, variables and aliases
# in the module even if they're not exported.
InModuleScope $script:ModuleName {
    Describe "Basic function unit tests" -Tags Build , Unit{
        # Open TCP 514 so we can test TCP connections (without hitting the network)
        $TCPEndpoint = New-Object System.Net.IPEndPoint ([IPAddress]::Loopback,514)
        $TCPListener = New-Object System.Net.Sockets.TcpListener $TCPEndpoint
        $TCPListener.start()

        $TCPClient = Connect-TCPClient -Server '127.0.0.1' -port 514

        It 'disconnects the TCP client' {
            Disconnect-TCPClient $TCPClient
            $TCPClient.Client | should be $null
        }

        $TCPListener.stop()
    }

}
