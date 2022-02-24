    # Set File Log Output Path:
    $outputPath = "C:\users\USERNAME\desktop\"
    # Output variable
    $output = New-Object system.collections.generic.list[object]
    # Get all computers in AD
    $computers = (Get-ADComputer -Filter *).Name
    # Clear DNS cache to make sure we don't have any stale IPs cached
    Clear-DnsClientCache
    # Loop through each computer in "parallel" (adjust -Count as needed)
    $computers | Split-Pipeline -Variable output -Count 32 {process{
        # Store computer name
        $varComp = $_
        # Check if it's online
        if ((Test-Connection -computername $varComp -Quiet -Count 1)) {
        # Check if the admin share is accessible
        if ((Test-Path "\\$varComp\c$\users")) {
            $detection = @()
            # NOTE: This scan **WILL** return a bunch of false-positives.  I would manually add additional exclusions as I ran across them... or delete 
            # the .exes as they were detected, as most were just temp files for a 1-time install... but because of how little info we had at the time,
            # I wanted to see _everything_ and make a decision as to whether it was legitimate or not.
            # Detect files on the root of C:\
            (Get-ChildItem "\\$varComp\c$\*.exe").FullName | % { $detection += $_ }
            # Look for .exes in AppData\(Local|Roaming)\Microsoft for each user on the machine
            # Ignores OneDrive
            foreach ($user in ((Get-ChildItem "\\$varComp\c$\users").BaseName) ) {
                # Search locations for affected .exes
                (Get-ChildItem "\\$varComp\c$\users\$user\appdata\local\microsoft\*\*.exe").FullName | ? { $_ -and $_ -notlike "*OneDrive*" } | % { $detection += $_ }
                (Get-ChildItem "\\$varComp\c$\users\$user\appdata\roaming\microsoft\*\*.exe").FullName | ? { $_ -and $_ -notlike "*OneDrive*" } | % { $detection += $_ }
                (Get-ChildItem "\\$varComp\c$\users\$user\appdata\roaming\microsoft\*.exe").FullName | ? { $_ -and $_ -notlike "*OneDrive*" } | % { $detection += $_ }
                (Get-ChildItem "\\$varComp\c$\users\$user\appdata\roaming\*.exe").FullName | ? { $_ -and $_ -notlike "*OneDrive*" } | % { $detection += $_ }
                (Get-ChildItem "\\$varComp\c$\users\$user\appdata\local\microsoft\*.exe").FullName | ? { $_ -and $_ -notlike "*OneDrive*" } | % { $detection += $_ }
                (Get-ChildItem "\\$varComp\c$\users\$user\appdata\local\*.exe").FullName | ? { $_ -and $_ -notlike "*OneDrive*" } | % { $detection += $_ }
            }
            if ($detection.Count -gt 0) {
                # Write to the console for a real-time update
                write-output ([pscustomobject]@{'Computer'=$varComp;'Online'=$true;'FilesFound'=$detection;}) | Select -ExpandProperty FilesFound
                # Store output
                $output.Add(([pscustomobject]@{'Computer'=$varComp;'Online'=$true;'FilesFound'=$detection;}))
            } else {
                # Store output
                $output.Add(([pscustomobject]@{'Computer'=$varComp;'Online'=$true;'FilesFound'=$null;}))
            }
        }
        } else {
            # Store output
            $output.Add(([pscustomobject]@{'Computer'=$varComp;'Online'=$false;'FilesFound'=$null;}))
        } 
    }
    }
    # Create a timestamp
    $timestamp = (Get-Date).ToString('MMddyyyy_ffffff')
    # Output log to path specified at top of file
    $output | Select Computer,Online,@{N='FilesFound';E={$_.FilesFound -join ',' -replace '\\\\',''}} | Export-Csv "$outputPath\scan_$timestamp.csv" -NoTypeInformation