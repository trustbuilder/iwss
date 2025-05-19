﻿Function Disconnect-TCPClient
{
    <#
            .SYNOPSIS
            Disconnects/Closes a TCPClient Object

            .DESCRIPTION
            Internal function.

            Disconnects/closes an open TCPClient.

            .EXAMPLE
            Disconnect-TCPClient -TcpClient $Client
            Closes the client $client.

            .OUTPUTS
            None
    #>

    [CmdletBinding()]
    param
    (
        # TCP Client that is connected to an endpoint
        [Parameter(Mandatory   = $true,
                   HelpMessage = 'TCP Client that is connected to an endpoint')]
        [ValidateNotNullOrEmpty()]
        [Net.Sockets.TcpClient]
        $TcpClient
    )

    Try
    {
        $TcpClient.Close()
        Write-Debug -message ('Connection Closed')
    }
    Catch
    {
        Throw $_
    }
}