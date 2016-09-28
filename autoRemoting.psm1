function WorkerRemoveApplication {
    [CmdletBinding()]
    Param (
        # ComputerName Specify the computer names to connect to. 
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [string]$ComputerName,

        # ApplicationName Specify the name of the application to remove
        [Parameter(Mandatory=$true,
                    ValueFromPipelinebyPropertyName=$false,
                    Position=2)]
        [string]$ApplicationName,

        # Credential Specify a credential (optional)
        [Parameter(Mandatory=$false,
                    ValueFromPipelinebyPropertyName=$false,
                    Position=3)]
        [System.Management.Automation.PSCredential]$Credential=$null,

        # AsJob
        [switch]$AsJob
    )

    Try {
        $args = @{'ComputerName' = $ComputerName;
                  'ArgumentList' = $ApplicationName, $ComputerName;
                  'ErrorAction'  = 'Stop'}
                  
        if($Credential -ne $null){
            $args.Add('Credential',$Credential)
        }

        if($AsJob){
            $args.Add('JobName',$ComputerName)
        }
            
        Invoke-Command @args -AsJob:$AsJob {
            param($app=$ApplicationName, $com=$ComputerName)
            $out = New-Object -TypeName PSObject
            $out | Add-Member -MemberType NoteProperty -Name ComputerName -Value $com
            $out | Add-Member -MemberType NoteProperty -Name ApplicationName -Value $app
            $out | Add-Member -MemberType NoteProperty -Name Connected -Value $true
            $out | Add-Member -MemberType NoteProperty -Name Result -Value 0
            $out | Add-Member -MemberType NoteProperty -Name MatchesFound -Value 0
            Try {
                $allsoftware = Get-WmiObject -Namespace "root\cimv2" -Class Win32_Product -ErrorAction Stop
                $matches = $allsoftware | Where-Object {$_.Name -eq $app}
                $measure = $matches | Measure-Object
                $count = $measure.count
                $out.MatchesFound = $count
                if($count -gt 0) {
                    $matches | Foreach-Object {
                        $rv = $_.Uninstall().ReturnValue
                        if($rv -ne 0) {
                             $out.Result = $rv
                        }
                    }
                } 
            } Catch {
                $out.Result = $_.Exception.Message
            } Finally {
                $out | Select ComputerName, ApplicationName, Connected, Result, MatchesFound | Write-Output             
            }
            
        } | Out-Null
    } Catch {

    } Finally {
        
    }
}

<#
.Synopsis
  Removes applications from computers
.DESCRIPTION
  Can accept collection of computer names, and one application (can support wildcards).  Uses Jobs to execute.  Returns the job numbers.
.EXAMPLE
  Remove-Application -ComputerName "host1" -ApplicationName "Apple*" -Credential $PSCredential
#>
function Remove-Application {
    [CmdletBinding()]
    Param (
        # ComputerName Specify the computer names to connect to. 
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [string[]]$ComputerName,

        # ApplicationName Specify the name of the application to remove
        [Parameter(Mandatory=$true,
                    ValueFromPipelinebyPropertyName=$false,
                    Position=2)]
        [string]$ApplicationName,

        # Credential Specify a credential (optional)
        [Parameter(Mandatory=$false,
                    ValueFromPipelinebyPropertyName=$false,
                    Position=3)]
        [System.Management.Automation.PSCredential]$Credential=$null,

        # AsJob
        [switch]$AsJob
    )
    Begin {}
    Process {
        $ComputerName | ForEach-Object {
            $args = @{'ComputerName'    = $_;
                      'ApplicationName' = $ApplicationName}

            if($Credential -ne $null){
                $args.Add('Credential',$Credential)
            }
            
            $outRow = WorkerRemoveApplication @args -AsJob:$AsJob

            if(!$AsJob){ Write-Output $out }
        }

    }
    End {} 
}

function Remove-ApplicationFromCSV {
    [CmdletBinding()]
    Param (
        # CSV
        [Parameter(Mandatory=$true,
                   ValueFromPipelinebyPropertyName=$false,
                   Position=1)]
        [string]$CSV,

        # ApplicationName
        [Parameter(Mandatory=$true,
                   ValueFromPipelinebyPropertyName=$false,
                   Position=2)]
        [string]$ApplicationName,

        # Credential Specify a credential (optional)
        [Parameter(Mandatory=$false,
                    ValueFromPipelinebyPropertyName=$false,
                    Position=3)]
        [System.Management.Automation.PSCredential]$Credential=$null,

        # Keep - Keep the results of the jobs created by this function
        [switch]$Keep
    )
    Begin {}
    Process {
        $data = Import-Csv $CSV

        #If the "STATUS" column doesn't exist, create it.
        if(($data | Get-Member -Name STATUS).Count -eq 0) {
            $data | Add-Member -MemberType NoteProperty -Name STATUS -Value ""
        }

        $computers = $data | Where-Object {$_.STATUS -eq ""} | Select ComputerName

        $args = @{'ApplicationName' = $ApplicationName}
        if($Credential -ne $null){
            $args.Add('Credential',$Credential)
        }

        $computers | Remove-Application @args -AsJob | Out-Null

        While((Get-Job -State 'Running').Count -ge 2) {
            Start-Sleep -Milliseconds 10
        }

        $jobs = Get-Job -IncludeChildJob | Receive-Job -ErrorAction SilentlyContinue -Keep:$Keep
        $jobs | Where-Object {$_.Connected -eq $true -and $_.Result -eq 0} | ForEach-Object { 
            $job = $_
            $data | Where-Object {$job.COMPUTERNAME -eq $_.ComputerName} | ForEach-Object {
                $_.STATUS = "FINISHED"
            }
        }
        $data | Export-Csv -Path $csv -NoTypeInformation 
    }
    End {
  
    }
}
