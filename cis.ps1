<#
.SYNOPSIS
    Audits critical high-impact CIS Benchmark controls for Windows 11.
.DESCRIPTION
    This script provides a framework to audit system configurations against CIS standards.
    It checks high-severity controls like SMBv1, Credential Guard, LSA Protection, RDP NLA, and UAC.
#>

# Array to hold the final audit results
$AuditReport = @()

Write-Host "Starting Windows 11 CIS Benchmark Audit..." -ForegroundColor Cyan
Write-Host "--------------------------------------------" -ForegroundColor Cyan

# ============================================================================
# 1. REGISTRY-BASED CONTROLS (The vast majority of CIS Benchmarks)
# You can add the rest of your 50 controls to this array.
# ============================================================================
$registryControls = @(
    # Network / Attack Surface Reduction
    [pscustomobject]@{ Control="18.8.21.1"; Name="Ensure 'SMBv1 server' is disabled"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Property="SMB1"; Expected=0 }
    [pscustomobject]@{ Control="18.9.72.1"; Name="Ensure 'Require NLA for RDP' is enabled"; Path="HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Property="UserAuthentication"; Expected=1 }
    
    # Credential & Memory Protection (Virtualization-Based Security)
    [pscustomobject]@{ Control="18.4.1"; Name="Ensure 'LSA Protection' is enabled"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Property="RunAsPPL"; Expected=1 }
    [pscustomobject]@{ Control="18.8.41.1"; Name="Ensure 'Credential Guard' is enabled"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Property="LsaCfgFlags"; Expected=1 }
    [pscustomobject]@{ Control="18.8.41.2"; Name="Ensure 'Virtualization Based Security' is enabled"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Property="EnableVirtualizationBasedSecurity"; Expected=1 }
    
    # Identity & Access Control
    [pscustomobject]@{ Control="18.3.1"; Name="Ensure 'UAC: Admin Approval Mode' is enabled"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Property="EnableLUA"; Expected=1 }
    [pscustomobject]@{ Control="18.3.2"; Name="Ensure 'AutoAdminLogon' is disabled"; Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Property="AutoAdminLogon"; Expected="0" }
    
    # OS Defenses
    [pscustomobject]@{ Control="18.9.47.1"; Name="Ensure 'Windows Defender Antivirus' is enabled"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Property="DisableAntiSpyware"; Expected=0 }
    [pscustomobject]@{ Control="18.8.28.1"; Name="Ensure 'Turn off Autoplay' is enabled"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Property="NoAutoplayfornonVolume"; Expected=1 }
)

foreach ($rule in $registryControls) {
    # Attempt to read the registry value
    $actual = (Get-ItemProperty -Path $rule.Path -Name $rule.Property -ErrorAction SilentlyContinue).($rule.Property)
    
    # Handle missing keys (which often means the policy is not configured)
    if ($null -eq $actual) {
        $status = "FAIL (Not Configured)"
        $actual = "Null"
    } elseif ($actual -eq $rule.Expected -or $actual -match $rule.Expected) {
        $status = "PASS"
    } else {
        $status = "FAIL"
    }
    
    $AuditReport += [pscustomobject]@{
        "CIS Control" = $rule.Control
        "Description" = $rule.Name
        "Status"      = $status
        "Expected"    = $rule.Expected
        "Actual"      = $actual
    }
}

# ============================================================================
# 2. LOCAL ACCOUNT CHECKS (WMI / Cmdlet based)
# ============================================================================

# Ensure the built-in Guest account is disabled
$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($guest) {
    $status = if ($guest.Enabled -eq $false) { "PASS" } else { "FAIL" }
    $AuditReport += [pscustomobject]@{ 
        "CIS Control" = "2.3.1"
        "Description" = "Ensure 'Guest' account is disabled"
        "Status"      = $status
        "Expected"    = "False"
        "Actual"      = $guest.Enabled 
    }
}

# Ensure the built-in Administrator account is disabled (LAPS should be used instead)
$admin = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
if ($admin) {
    $status = if ($admin.Enabled -eq $false) { "PASS" } else { "FAIL" }
    $AuditReport += [pscustomobject]@{ 
        "CIS Control" = "2.3.2"
        "Description" = "Ensure built-in 'Administrator' is disabled"
        "Status"      = $status
        "Expected"    = "False"
        "Actual"      = $admin.Enabled 
    }
}

# ============================================================================
# 3. OUTPUT & REPORTING
# ============================================================================

# Display in the console with a clean table format
$AuditReport | Sort-Object "CIS Control" | Format-Table -AutoSize

# Calculate summary statistics
$total = $AuditReport.Count
$passed = ($AuditReport | Where-Object { $_.Status -eq "PASS" }).Count
$failed = $total - $passed

Write-Host "Audit Complete." -ForegroundColor Cyan
Write-Host "Total Controls Checked: $total"
Write-Host "Passed: $passed" -ForegroundColor Green
Write-Host "Failed/Missing: $failed" -ForegroundColor Red

# Optional: Export to CSV
# $AuditReport | Export-Csv -Path ".\CIS_Windows11_Audit_$((Get-Date).ToString('yyyyMMdd')).csv" -NoTypeInformation
