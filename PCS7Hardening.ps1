<#
Developed by OTORIO LTD. - www.otorio.com
Licensed under GPL V3
#>

<#
    .SYNOPSIS
    Tests SIMATIC PCS 7 security 

    .DESCRIPTION
    Please run the script as Administrator
    Collects data from the following sources:
        * Windows Management Instrumentation (WMI)
        * Windows registry
        * Resultant Set of Policy (RsoP)
        * Security get-
        * PCS7 WebNavigator and Information server config files
        * Running services

    Analyzes the collected data in order to alert on security misconfigurations
#>

# Constants

$PASSWORD_MIN_LENGTH = 14

$POLICIES = @{'Turn off Application Telemetry'="Enabled";
            'Turn off Inventory Collector'="Enabled";
            'Do not sync'="Enabled";
            'Do not sync app settings'="Enabled";
            'Do not sync password'="Enabled";
            'Do not sync personalize'="Enabled";
            'Do not sync Apps'="Enabled";
            'Do not sync other Windows settings'="Enabled";
            'Do not sync desktop personalization'="Enabled";
            'Do not sync browser settings'="Enabled";
            'Do not sync on metered connections'="Enabled";
            'Do not sync start settings'="Enabled";
            'Turn off Automatic Root Certificates Update'="Enabled";
            'Turn off printing over HTTP'="Enabled";
            'Turn off downloading of print drivers over HTTP'="Enabled";
            'Turn off Windows Update device driver searching'="Enabled";
            'Turn off Windows Error Reporting'="Enabled";
            'Turn off access to the Store'="Enabled";
            'Turn off the Windows Messenger Customer Experience Improvement Program'="Enabled";
            'Turn off Windows Customer Experience Improvement Program'="Enabled";
            'Prevent the usage of OneDrive for file storage'="Enabled";
            'Turn off location'="Enabled";
            'Turn off Windows Location Provider'="Enabled";
            'Turn off downloading of game information'="Enabled";
            'Turn off game updates'="Enabled";
            'Allow Cortana'="Disabled";
            'Allow search and Cortana to use location'="Disabled";
            'Do not allow Web search'="Enabled";
            'Do not search the Web or display Web results in Search'="Enabled";
            'Allow indexing of encrypted files'="Disabled"}



$REGISTRY_KEYS = @("HKLM\SOFTWARE\Wow6432Node\SIEMENS\SCS\Discovery\Security",
                "HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters")

$WMI_HT = @{"Win32_LogicalShareAccess"=@("SecuritySetting","Trustee","AccessMask","Type")}

$UNNECESSARY_SERVICES=@("Certificate distribution",
                         "Diagnostic Policy Service",
                         "Diagnostic Service Host",
                          "Windows Color System",
                          "Windows Connect Now - Config Registrar",
                          "Performance Logs and Alerts",
                          "Windows Presentation Foundation Font Cache")

$WEB_CONFIG_PATHS=@("C:\Program Files (x86)\Siemens\WinCC\Webnavigator\Server\Web\web.config",
                    "C:\inetpub\wwwroot\Siemens\InformationServer\web\web.config")


# If these XPaths are not defined, we'll create an alert
$WEB_POLICIES_ALERTS = @{
    '//httpRuntime[@enableVersionHeader="false"]'='Version header is not disabled';
    '//httpCookies[@httpOnlyCookies="true"][@requireSSL="true"]'= 'Unsecure cookies configuration';
    '//customErrors[@mode="RemoteOnly"][@defaultRedirect="~/Error.aspx"]'='Unsecure errors configuration';
    '//customHeaders/add[@name="X-Frame-Options"][@value="DENY"]'="X-Frame-Options header is not enabled";
    '//customHeaders/add[@name="X-XSS-Protection"][@value="1; mode=block"]'="X-XSS-Protection header is not enabled";
    '//customHeaders/add[@name="Content-Security-Policy"][@value="default-src ''none''; script-src ''self''; connect-src ''self''; img-src ''self''; style-src ''self'';"]'="Content Security Policy header is not enabled";
    '//customHeaders/remove[@name="X-Powered-By"]'="X-Powered-By header is enabled"
}


# Global variables which will contain the alerts we find
$alerts = [System.Collections.ArrayList]@()
$complex_alerts = [System.Collections.Hashtable]@{}


Function Get-RegistryValues{
    Param(
        [Parameter(Mandatory=$true)]
        [Array]$registry_keys)

    $registry_results = @{}
    foreach($key in $registry_keys){
        try{
        $result = Get-ItemProperty -Path REGISTRY::$key -ErrorAction stop
        }
        catch{
            Write-Host "$($_.Exception.Message)"
        }
        
        $registry_results.Add($key, $result)
    }
    return $registry_results
}

Function Get-RunningServices{
    
    $services = Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object -Property DisplayName
    return $services
}

Function Get-WMI{
     Param(
        [Parameter(Mandatory=$true)]
        [System.Collections.Hashtable]$wmi_ht)

    $wmi_results = @{}
    foreach($wmi_query in $wmi_ht.keys){
        $result= Get-WmiObject -Class $wmi_query -Property $wmi_ht.$wmi_query
        $wmi_results.add($wmi_query, $result)
    }
    return $wmi_results

}

# https://devblogs.microsoft.com/scripting/use-powershell-to-work-with-any-ini-file/
Function Get-IniContent{
    Param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath)
    
    $ini = @{}
    switch -regex -file $FilePath
    {
        "^\[(.+)\]" # Section
        {
            $section = $matches[1]
            $ini[$section] = @{}
            $CommentCount = 0
        }
        "^(;.*)$" # Comment
        {
            $value = $matches[1]
            $CommentCount = $CommentCount + 1
            $name = “Comment” + $CommentCount
            $ini[$section][$name] = $value
        }
        "(.+?)\s*= (.*)" # Key
        {
            $name,$value = $matches[1..2]
            $ini[$section][$name] = $value
        }
    }
    return $ini
}

Function Get-Secpol{
    Param(
    [Parameter(Mandatory=$true)]
    [string]$path)

    $out = secedit /export /cfg $path 2>&1
    if($out -match "The task has completed successfully*"){
        $secpol = Get-IniContent -filepath $path
        Remove-Item $path
        return $secpol
    }
    Write-Warning "Error running secedit: $out"
    return $false
    
}


Function Get-RegistryRSoP{
    Param(
    [Parameter(Mandatory=$true)]
    [string]$path)

    $error = gpresult /Scope Computer /X $path 2>&1
    if ($error -ne $null){
        Write-Warning "Error collecting RSoP data: $error"
        return $false
    }
    [xml]$rsop = Get-File -Path $path
    Remove-Item $path
    if($rsop -eq $null){
        Write-Host "Couldn't get RSoP data"
        return $null
    }
    $rsop_registry = Select-Xml -Xml $rsop -XPath '//q6:Policy' -Namespace @{'q6'='http://www.microsoft.com/GroupPolicy/Settings/Registry'} | Select-Object -Property Node
    return $rsop_registry
}


Function Get-File{
    Param(
    [Parameter(Mandatory=$true)]
    [String] $path)
    $file = $null
    try{
        $file = Get-Content -Path $path -ErrorAction stop
    }
    catch{
        Write-Host "$($_.Exception.Message)"
    }
    return $file

}


Function Test-ShareAuthentication{
    Param(
    [Parameter(Mandatory=$true)]
    [System.Collections.Hashtable]$wmi_results)

    $shares = $wmi_results["Win32_LogicalShareAccess"]
    if($shares -eq $null){
        return $null
    }
    $complex_alerts.Add("Folders shared with everyone", [System.Collections.ArrayList]@())
    foreach($share in $shares){

        # The share is a folder, and Everyone account SID is in the Trustee attribute
        if(($share.Trustee -match '(.+)(\"S-1-1-0\")') -and $share.Type -eq 0){
            if($share.SecuritySetting -match '.*Name="(?<name>.*)".*'){
                $name = $matches["name"]
                $complex_alerts["Folders shared with everyone"].Add($name) | Out-Null
            }
        }
    }

}



Function Test-PasswordMinimumLength{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$secpol,

    [Parameter(Mandatory=$true)]
    [int]$length

    )
    if($secpol["System Access"] -ne $null){
        $min_length = $secpol["System Access"]["MinimumPasswordLength"]
        if($min_length -ne $null){
            if($min_length -as [int] -lt $length){
               $alerts.Add("Minimum number of characters in password is $min_length, while $length is recommended") | out-null
            }
        else{
            $alerts.Add("Minimum number of characters in password is not defined") | out-null

            }
        }

    }
}

Function Test-PCS7Hardening{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$policies,

    [Parameter(Mandatory=$true)]
    [AllowNull()]
    $rsop_registry
    )
    $complex_alerts.add("Undefined policies",[System.Collections.ArrayList]@())
    $complex_alerts.add("Misconfigured policies",[System.Collections.ArrayList]@())
    foreach($policy in $policies.keys){

        # There are no configured policies
        if($rsop_registry -eq $null){
            $matched_policy = $null
        }
        else{
            $matched_policy = $rsop_registry.Node | Where-Object {$_.Name -eq $policy}
        }
        
        # This policy is not configured
        if($matched_policy -eq $null){
            $complex_alerts["Undefined policies"].add($policy) | Out-Null
        }
        else{

            # The policy's state doesn't match the recommended state
            if($matched_policy.State -ne $policies[$policy]){
                $complex_alerts["Misconfigured policies"].Add($policy) | Out-Null
            }
        }

    
    }

    # Allow telemetry policy is relevant for NT 10.0 or above
    if([Environment]::OSVersion.Version -ge (new-object 'Version' 10,0)){
         $policy = "Allow Telemetry"
         $matched_policy = $rsop_registry.Node | Where-Object {$_.Name -eq $policy}
         if($matched_policy -eq $null){
            $complex_alerts["Undefined policies"].add($policy) | Out-Null
         }
         elseif ($matched_policy.state -eq "Enabled" -and $matched_policy.DropDownList.Value.Name -ne "0 - Security [Enterprise Only]"){
            $complex_alerts["Misconfigured policies"].Add($policy) | Out-Null
         }

    }

    # Check autoplay
    $policy = "Turn off Autoplay"
    $matched_policy = $rsop_registry.Node | Where-Object {$_.Name -eq $policy}
    if($matched_policy -eq $null){
            $complex_alerts["Undefined policies"].add($policy) | Out-Null
         }
    elseif ($matched_policy.state -eq "Disabled" -or $matched_policy.DropDownList.Value.Name -ne "All drives"){
        $complex_alerts["Misconfigured policies"].Add($policy) | Out-Null
    }
}


Function Test-PasswordComplexity{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$secpol
    )
    if($secpol["System Access"] -ne $null){
        $complexity = $secpol["System Access"]["PasswordComplexity"]
        if($complexity -eq $null -or ($complexity -ne "1")){
            $alerts.Add("Password complexity is not enforced") | out-null
        }

    }

}

Function Test-PasswordClearText{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$secpol
    )
    if($secpol["System Access"] -ne $null){
        $complexity = $secpol["System Access"]["ClearTextPassword"]

        # Cleartext password is enabled
        if ($complexity -eq $null -or $complexity -ne "0"){
            $alerts.Add("Cleartext password is enabled")
        }
    }

}


Function Test-PCS7EncryptedCommunication{
   param(
   [Parameter(Mandatory=$true)]
   [Hashtable]$registry_results
   )

   if($registry_results["HKLM\SOFTWARE\Wow6432Node\SIEMENS\SCS\Discovery\Security"] -ne $null){
        $security_level = $registry_results["HKLM\SOFTWARE\Wow6432Node\SIEMENS\SCS\Discovery\Security"].Level
        if($security_level -eq 0){
            $alerts.Add("Encrypted communication between OS systems is not enabled")
    }
   }
    
}

Function Test-PCS7RunningWithNonAdmin{

    # Get the user running WinCC Runtime
    $proc = Get-WmiObject -Filter 'name="pdlrt.exe"' win32_process | Select-Object Name,@{n='Owner';e={$_.GetOwner().Domain + '\' + $_.GetOwner().User}};

    # The process is running
    If ($proc -ne $null) {
        $owner = $proc.Owner 
        $admins = Get-localadmin
        $match = $admins | Where {$_ -eq $owner}

        # An administrator account is running the process
        If ($match -ne $null) {
            $alerts.Add("WinCC runtime running with admin user: $owner") | Out-Null
        }
    }
}

Function Test-PCS7UnnecessaryServices{
    param(
    [Parameter(Mandatory=$true)]
    $services
    )

    $complex_alerts.add("Unneccessary services running",[System.Collections.ArrayList]@())

    foreach($service in $UNNECESSARY_SERVICES){
        if($services | Where {$_.DisplayName.Contains($service)}){
                $complex_alerts["Unneccessary services running"].Add($service) | Out-Null
        }
    }
}


Function Write-Results{
    
    foreach($alert in $alerts){
        Write-Host "* $alert"
    }
    foreach($alert in $complex_alerts.Keys){
        if($complex_alerts[$alert].Count -gt 0){
            Write-Host "`n* $alert :"
            foreach($subalert in $complex_alerts[$alert]){
                Write-Host "`t$subalert"
            }

    }
    }
}

Function Test-WebHardening{
    param(
    [Parameter(Mandatory=$true)]
    [Hashtable]$web_ht,
    
    [Parameter(Mandatory=$true)]
    [Hashtable]$registry_results)

    if($registry_results["HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"] -eq $null -or
        $registry_results["HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"].DisableServerHeader -eq 0){
        $alerts.add("Server header is not disabled") | out-null
    }

    foreach($webpath in $web_ht.keys){
        $webconfig = [xml]$web_ht[$webpath]
        $web_alerts = [System.Collections.ArrayList]@()
        foreach($policy in $WEB_POLICIES_ALERTS.keys){
            $info = select-xml -Xml $webconfig -XPath $policy
            if($info -eq $null){
               $web_alerts.add($web_policies_alerts[$policy]) | out-null
               }
        }

        # Found some alerts, update complex_alerts 
        if($web_alerts.Count -gt 0){
            $complex_alerts.Add($webpath, $web_alerts)
        }
    }
}

Function Get-LocalAdmin{

    $admins = [System.Collections.ArrayList]@()
    $admin_groups = get-wmiobject -query "select * from win32_groupuser where GroupComponent=""Win32_Group.Domain='$env:computername',Name='administrators'"""
    $admin_groups | ForEach-Object {$_.partcomponent -match ".+Domain\=(.+)\,Name\=(.+)$" > $null
    $admins.add($matches[1].trim('"') + "\" + $matches[2].trim('"')) | out-null
    }
    return $admins
}
Write-Host "`n"
Write-Host "##################################"
Write-Host "SIMATIC PCS 7 Hardening Tool"
Write-Host "Created by OTORIO - www.otorio.com"
Write-Host "##################################"
Write-Host "`n"

write-host "Fetching RSoP data"
$rsop_registry = Get-RegistryRSoP "\\localhost\admin$\gpresult.xml"

Write-Host "Fetching registry data"
$registry_results = Get-RegistryValues -registry_keys $REGISTRY_KEYS

Write-host "Fetching service information"
$services = Get-RunningServices

Write-Host "Fetching WMI data, may take a while"
$wmi_results = Get-WMI -wmi_ht $WMI_HT

Write-host "Fetching security policy data"
$secpol = Get-Secpol -path "\\localhost\admin$\seccfg.conf"

Write-Host "Fetching web server configuration"
$web_files = [System.Collections.HashTable]@{}
foreach ($path in $WEB_CONFIG_PATHS){
    $file = Get-File -path $path
    if ($file -ne $null){
        $web_files.Add($path, $file)
    }
}


Write-Host "Analyzing data`n"
Write-Host "Found issues: `n"

# Get-RegistryRsop was successful
if ($rsop_registry -ne $false){
    Test-PCS7Hardening -policies $POLICIES -rsop_registry $rsop_registry
}
Test-ShareAuthentication -wmi_results $wmi_results

# Get-SecPol was successful
if ($secpol -ne $false){
    Test-PasswordMinimumLength -secpol $secpol -length $PASSWORD_MIN_LENGTH
    Test-PasswordComplexity -secpol $secpol
    Test-PasswordClearText $secpol
    }

Test-PCS7EncryptedCommunication $registry_results
Test-PCS7RunningWithNonAdmin
Test-PCS7UnnecessaryServices -services $services
Test-WebHardening -web_ht $web_files -registry_results $registry_results
Write-Results


