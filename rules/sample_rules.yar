/*
    Sample YARA rules for ARES - Anti-Malware
    Add your custom rules here (.yar or .yara files)
*/

rule Suspicious_PowerShell_Encoded {
    meta:
        description = "Detects encoded PowerShell commands"
        author = "ARES - Anti-Malware"
        severity = "high"
        date = "2026"
    strings:
        $ps1 = "powershell" nocase
        $ps2 = "-encodedcommand" nocase
        $ps3 = "-enc " nocase
        $ps4 = "-WindowStyle Hidden" nocase
        $b64 = /[A-Za-z0-9+\/]{50,}={0,2}/
    condition:
        $ps1 and ($ps2 or $ps3) and $b64
}

rule Common_Packer_UPX {
    meta:
        description = "Detects UPX packed executable"
        author = "ARES - Anti-Malware"
        severity = "medium"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx2 = "UPX!"
    condition:
        any of them
}

rule Suspicious_Registry_Persistence {
    meta:
        description = "Detects registry-based persistence mechanisms"
        author = "ARES - Anti-Malware"
        severity = "high"
    strings:
        $reg1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg3 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
    condition:
        any of them
}

rule Mimikatz_Strings {
    meta:
        description = "Detects Mimikatz credential dumping tool"
        author = "ARES - Anti-Malware"
        severity = "critical"
    strings:
        $m1 = "mimikatz" nocase
        $m2 = "sekurlsa::logonpasswords" nocase
        $m3 = "lsadump::sam" nocase
        $m4 = "kerberos::golden" nocase
    condition:
        2 of them
}
