# Splunk Detections – Malicious PowerShell

Splunk SPL searches for spotting malicious PowerShell: encoded commands, download cradles, obfuscation,
AMSI and Defender tampering, credential dumping, ransomware-style encryption, and persistence.
Each one can be saved as an alert.

---

## 0. Prerequisites (do this first or most detections see nothing)

| Log source | Event | How to enable | Typical sourcetype |
|---|---|---|---|
| PowerShell Script Block Logging | 4104 | GPO: *Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging* | `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational` |
| PowerShell Module Logging | 4103 | Same GPO folder, *Turn on Module Logging* (module names = `*`) | same as above |
| Sysmon | 1 (process), 3 (network), 11 (file create), 13 (registry), 23/26 (file delete) | Install Sysmon with a config such as SwiftOnSecurity or olafhartong/sysmon-modular | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| Windows Security process creation | 4688 + command line | GPO: *Audit Process Creation* + *Include command line in process creation events* | `XmlWinEventLog:Security` |

Install the **Splunk Add-on for Microsoft Windows** and the **Splunk Add-on for Sysmon** so field names
(`ScriptBlockText`, `CommandLine`, `Image`, `ParentImage`, ...) get extracted.

> Change `index=wineventlog` / `index=sysmon` below to your own index names. A simple way is to create macros:
> `` `powershell_logs` `` = `index=wineventlog source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"`
> `` `sysmon` `` = `index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`

### 0.1 Check that the logs are arriving (run before saving any alert)

```spl
| tstats count where index=* (source=*PowerShell* OR sourcetype=*PowerShell* OR source=*Sysmon* OR sourcetype=*Sysmon*) earliest=-24h by index sourcetype source
```

```spl
index=* (source="*PowerShell*" OR sourcetype="*PowerShell*") earliest=-24h
| stats count dc(host) as hosts by index sourcetype EventCode
```

You want to see EventCode **4104** (script block), plus 4103 (module logging) and 400/800 (classic log).
Then check the fields are extracted, because the detections depend on `ScriptBlockText`:

```spl
index=* EventCode=4104 earliest=-24h | head 10 | table _time host index sourcetype ScriptBlockText
```

End-to-end test: on a Windows machine run `Write-Output "splunk-test-12345"`, wait 1–2 minutes, then
`index=* "splunk-test-12345"`.

Find machines that are not sending PowerShell logs:

```spl
| tstats count where index=* earliest=-24h by host
| join type=left host [| tstats count as ps_events where index=* (source=*PowerShell* OR sourcetype=*PowerShell*) earliest=-24h by host]
| fillnull value=0 ps_events
| where ps_events=0
```

If nothing comes back: on the endpoint open Event Viewer > *Applications and Services Logs > Microsoft > Windows >
PowerShell > Operational* and look for 4104. If it's there, the forwarder isn't collecting it. Add this to
`inputs.conf` on the Universal Forwarder and restart it:

```ini
[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
renderXml = true
index = wineventlog
```

If it's not in Event Viewer either, script block logging is off (see the GPO above, or set registry
`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` `EnableScriptBlockLogging` = `1`).

---

## 1. Encoded PowerShell command (`-enc`, `-EncodedCommand`)

Attackers base64-encode commands to hide them. PowerShell accepts every prefix of `-EncodedCommand`
(`-e`, `-en`, `-enc`, `-encod` ...) and also `/` instead of `-`.

```spl
index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR OriginalFileName="PowerShell.EXE")
| regex CommandLine="(?i)\s[-/]e(n(c(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?)?)?)?)?)?)?)?\s+[A-Za-z0-9+/=]{20,}"
| rex field=CommandLine "(?i)\s[-/]e\w*\s+(?<encoded_payload>[A-Za-z0-9+/=]{20,})"
| table _time host User ParentImage Image CommandLine encoded_payload
| sort - _time
```

Same idea using Security 4688 (if you don't have Sysmon):

```spl
index=wineventlog EventCode=4688 New_Process_Name="*\\powershell.exe"
| regex Process_Command_Line="(?i)\s[-/]e(n(c(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?)?)?)?)?)?)?)?\s+[A-Za-z0-9+/=]{20,}"
| table _time host Account_Name Creator_Process_Name Process_Command_Line
```

**Decoding the payload:** the decoded text is already in event 4104 (script block logging logs the *decoded*
script), so pivot on `host` + `_time` to see what it actually ran. To decode in SPL, install the
**DECRYPT2** app from Splunkbase:
`| decrypt field=encoded_payload b64 unwrap emit('decoded')` (the payload is UTF-16LE, so
remove the `\x00` bytes after decoding).

---

## 2. Suspicious script content (scored) – main detection

Scores each 4104 script block by how many malicious indicators it contains. Alert on `score >= 3`
to keep noise low; lower the threshold to hunt.

```spl
index=wineventlog source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| eval s=lower(ScriptBlockText)
| eval score=0
| eval score=score + if(match(s, "iex\s*\(|invoke-expression"), 1, 0)
| eval score=score + if(match(s, "downloadstring|downloadfile|downloaddata|invoke-webrequest|iwr\s|invoke-restmethod|net\.webclient|start-bitstransfer"), 1, 0)
| eval score=score + if(match(s, "frombase64string|\[convert\]::"), 1, 0)
| eval score=score + if(match(s, "reflection\.assembly\]::load|\[system\.reflection\.assembly\]|add-type.*dllimport"), 2, 0)
| eval score=score + if(match(s, "virtualalloc|createthread|writeprocessmemory|getprocaddress|getdelegateforfunctionpointer"), 2, 0)
| eval score=score + if(match(s, "amsiutils|amsiinitfailed|amsiscanbuffer|amsicontext"), 3, 0)
| eval score=score + if(match(s, "invoke-mimikatz|sekurlsa|kerberos::|invoke-shellcode|invoke-reflectivepeinjection|powersploit|empire|invoke-bloodhound|sharphound|rubeus|invoke-kerberoast"), 3, 0)
| eval score=score + if(match(s, "-bxor|\[char\]\s*\d+\s*\+\s*\[char\]|-join\s*\(|\.replace\(|\"\s*\+\s*\"|`[a-z]"), 1, 0)
| eval score=score + if(match(s, "io\.compression\.(gzip|deflate)stream|system\.io\.memorystream"), 1, 0)
| eval score=score + if(match(s, "net\.sockets\.tcpclient|getstream\(\)"), 2, 0)
| where score>=3
| eval ScriptBlockText=substr(ScriptBlockText, 1, 1000)
| table _time host UserID ScriptBlockId Path score ScriptBlockText
| sort - score
```

> Long scripts are split over several 4104 events (`MessageNumber` / `MessageTotal`). To rebuild one:
> `... | stats values(ScriptBlockText) as script by ScriptBlockId host`

---

## 3. Download cradle (download + execute in one line)

```spl
index=wineventlog source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| regex ScriptBlockText="(?i)(iex|invoke-expression).{0,100}(downloadstring|invoke-webrequest|iwr|invoke-restmethod|irm|net\.webclient)|(downloadstring|invoke-webrequest|iwr|irm|net\.webclient).{0,200}(iex|invoke-expression)"
| rex field=ScriptBlockText "(?i)(?<url>https?://[^\s'\"\)]+)"
| table _time host UserID url ScriptBlockText
```

Process-creation version (catches it even if script block logging is off):

```spl
index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| regex CommandLine="(?i)(downloadstring|downloadfile|invoke-webrequest|iwr |invoke-restmethod|irm |net\.webclient|start-bitstransfer)"
| table _time host User ParentImage CommandLine
```

---

## 4. Suspicious launch flags (hidden window, bypass, no profile)

```spl
index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| eval c=lower(CommandLine)
| eval flags=mvappend(
    if(match(c, "\s[-/]w(i(n(d(o(w(s(t(y(l(e)?)?)?)?)?)?)?)?)?)?\s+(h|hidden|1)"), "hidden", null()),
    if(match(c, "\s[-/]ex(e(c(u(t(i(o(n(p(o(l(i(c(y)?)?)?)?)?)?)?)?)?)?)?)?)?\s+(bypass|unrestricted)"), "bypass", null()),
    if(match(c, "\s[-/]nop(r(o(f(i(l(e)?)?)?)?)?)?\b"), "noprofile", null()),
    if(match(c, "\s[-/]noni(n(t(e(r(a(c(t(i(v(e)?)?)?)?)?)?)?)?)?)?\b"), "noninteractive", null()),
    if(match(c, "\s[-/]e(n(c(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?)?)?)?)?)?)?)?\s"), "encoded", null()))
| eval flag_count=mvcount(flags)
| where flag_count>=2
| table _time host User ParentImage CommandLine flags flag_count
```

---

## 5. Office / browser / script host spawning PowerShell (phishing)

```spl
index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
  (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\powerpnt.exe"
   OR ParentImage="*\\outlook.exe" OR ParentImage="*\\mshta.exe" OR ParentImage="*\\wscript.exe"
   OR ParentImage="*\\cscript.exe" OR ParentImage="*\\rundll32.exe" OR ParentImage="*\\regsvr32.exe"
   OR ParentImage="*\\w3wp.exe" OR ParentImage="*\\sqlservr.exe")
| table _time host User ParentImage ParentCommandLine CommandLine
```

---

## 6. AMSI bypass / Defender tampering

```spl
index=wineventlog source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| regex ScriptBlockText="(?i)(amsiutils|amsiinitfailed|amsiscanbuffer|amsicontext|set-mppreference\s.*-disable(realtimemonitoring|behaviormonitoring|ioavprotection|scriptscanning)\s+\$?(true|1)|add-mppreference\s.*-exclusion(path|process|extension)|set-mppreference\s.*-exclusion)"
| table _time host UserID ScriptBlockText
```

Defender also logs real-time protection being turned off:

```spl
index=wineventlog source="XmlWinEventLog:Microsoft-Windows-Windows Defender/Operational" (EventCode=5001 OR EventCode=5007 OR EventCode=5010 OR EventCode=5012)
| table _time host EventCode Message
```

---

## 7. Ransomware behaviour – PowerShell encrypting files

### 7a. Encryption code inside a PowerShell script

```spl
index=wineventlog source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| eval s=lower(ScriptBlockText)
| where match(s, "security\.cryptography") AND match(s, "aesmanaged|aescryptoserviceprovider|\[.*aes\]::create|rijndaelmanaged|createencryptor|cryptostream|protectedtext|rsacryptoserviceprovider")
| eval touches_files=if(match(s, "get-childitem|gci\s|\[io\.file\]::(readallbytes|writeallbytes|openread)|set-content|out-file|remove-item|rename-item|-recurse"), "yes", "no")
| eval ransom_note=if(match(s, "readme|decrypt|bitcoin|btc|ransom|your files"), "yes", "no")
| where touches_files="yes"
| table _time host UserID touches_files ransom_note ScriptBlockText
```

### 7b. PowerShell writing / renaming lots of files quickly (Sysmon 11)

```spl
index=sysmon EventCode=11 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| bin _time span=5m
| rex field=TargetFilename "\.(?<ext>[^\.\\\\]+)$"
| stats dc(TargetFilename) as files_written dc(ext) as extensions values(ext) as ext_list by _time host User Image
| where files_written > 100
| sort - files_written
```

### 7c. Shadow copy / backup deletion (almost always comes before encryption)

```spl
index=sysmon EventCode=1
| eval c=lower(CommandLine)
| where match(c, "vssadmin(\.exe)?\s+delete\s+shadows|vssadmin(\.exe)?\s+resize\s+shadowstorage|wmic(\.exe)?\s+shadowcopy\s+delete|win32_shadowcopy.*(delete|remove)|get-wmiobject\s+win32_shadowcopy|get-ciminstance\s+win32_shadowcopy|wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup)|bcdedit.*recoveryenabled\s+no|bcdedit.*bootstatuspolicy\s+ignoreallfailures")
| table _time host User ParentImage Image CommandLine
```

---

## 8. Credential dumping from PowerShell

```spl
index=sysmon EventCode=1
| eval c=lower(CommandLine)
| where match(c, "comsvcs(\.dll)?.*minidump|rundll32.*comsvcs|procdump.*lsass|out-minidump|invoke-mimikatz|sekurlsa|reg(\.exe)?\s+save\s+hklm\\\\(sam|security|system)")
| table _time host User ParentImage Image CommandLine
```

Process access to LSASS by PowerShell (Sysmon 10):

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe" (SourceImage="*\\powershell.exe" OR SourceImage="*\\pwsh.exe")
| table _time host SourceImage TargetImage GrantedAccess CallTrace
```

---

## 9. PowerShell downgrade attack (version 2 bypasses logging & AMSI)

```spl
index=sysmon EventCode=1 (Image="*\\powershell.exe")
| regex CommandLine="(?i)\s[-/]v(e(r(s(i(o(n)?)?)?)?)?)?\s+2"
| table _time host User ParentImage CommandLine
```

```spl
index=wineventlog source="WinEventLog:Windows PowerShell" EventCode=400
| rex field=Message "EngineVersion=(?<engine_version>[\d\.]+)"
| where like(engine_version, "2.%")
| table _time host engine_version Message
```

---

## 10. PowerShell talking to the internet

```spl
index=sysmon EventCode=3 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe") Initiated=true
| where NOT cidrmatch("10.0.0.0/8", DestinationIp) AND NOT cidrmatch("172.16.0.0/12", DestinationIp)
    AND NOT cidrmatch("192.168.0.0/16", DestinationIp) AND NOT cidrmatch("127.0.0.0/8", DestinationIp)
| stats count values(DestinationIp) as dest_ips values(DestinationHostname) as dest_hosts values(DestinationPort) as ports by host User Image
| sort - count
```

---

## 11. Persistence created by PowerShell

```spl
index=sysmon (EventCode=1 OR EventCode=13)
| eval c=lower(coalesce(CommandLine, "") . " " . coalesce(TargetObject, "") . " " . coalesce(Details, ""))
| where (match(lower(Image), "powershell\.exe|pwsh\.exe") OR match(lower(ParentImage), "powershell\.exe|pwsh\.exe"))
    AND match(c, "register-scheduledtask|new-scheduledtask|schtasks.*/create|\\\\currentversion\\\\run|\\\\currentversion\\\\runonce|new-service|sc(\.exe)?\s+create|register-wmievent|__eventfilter|commandlineeventconsumer")
| table _time host User EventCode Image CommandLine TargetObject Details
```

---

## 12. Someone turning off logging / clearing logs (cover tracks)

```spl
(index=wineventlog (EventCode=1102 source="XmlWinEventLog:Security") OR (EventCode=104 source="XmlWinEventLog:System"))
OR (index=sysmon EventCode=13 TargetObject="*\\PowerShell\\ScriptBlockLogging\\EnableScriptBlockLogging" Details="DWORD (0x00000000)")
| table _time host EventCode user TargetObject Details Message
```

---

## 13. Rare / long command lines (hunting, not alerting)

Very long command lines and base64 blobs are rare in normal admin work.

```spl
index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| eval cmd_len=len(CommandLine)
| where cmd_len > 1000 OR match(CommandLine, "[A-Za-z0-9+/]{200,}={0,2}")
| stats count min(_time) as first_seen max(_time) as last_seen values(host) as hosts by CommandLine ParentImage
| where count < 5
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

---

## Turning a search into an alert

1. Run the search, then **Save As > Alert**.
2. **Alert type:** Scheduled, e.g. *Run on Cron Schedule* `*/5 * * * *` with time range *Last 10 minutes*
   (overlapping windows so nothing is missed), or *Real-time* for the high-severity ones (AMSI bypass, shadow copy deletion).
3. **Trigger when:** Number of Results `> 0`.
4. **Trigger:** *For each result* (one alert per host) and enable **Throttle** on `host` for 1 hour so you don't get flooded.
5. **Actions:** Send email, add to Triggered Alerts, Slack/Teams webhook, or create a notable event if you use Splunk ES.

Suggested severity:

| Detection | Severity |
|---|---|
| 6 AMSI bypass / Defender off, 7 Ransomware, 7c Shadow copy delete, 8 Credential dumping | Critical |
| 2 Scored script (score ≥ 5), 3 Download cradle, 5 Office spawns PowerShell, 9 Downgrade, 12 Logs cleared | High |
| 1 Encoded command, 4 Suspicious flags, 11 Persistence, 2 (score 3–4) | Medium |
| 10 Internet connections, 13 Long command lines | Hunting / dashboard |

## Reducing false positives

Legit tools (SCCM, Intune, monitoring agents, your own admin scripts) also use `-enc` and `-ExecutionPolicy Bypass`.
After a week of baselining, exclude them with a lookup instead of hard-coding:

```spl
... | lookup powershell_allowlist.csv CommandLine OUTPUT allowed
| where isnull(allowed)
```

or exclude known parents, e.g. `NOT ParentImage="*\\CcmExec.exe" NOT ParentImage="*\\IntuneManagementExtension.exe"`.

## Testing safely

Run these harmless commands on a **test** machine and confirm the alerts fire:

```powershell
# Detection 1 + 4: encoded, hidden, bypass  (decodes to: Write-Output 'splunk test')
powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAHMAcABsAHUAbgBrACAAdABlAHMAdAAnAA==

# Detection 2 + 3: download cradle pattern (fetches a harmless page)
powershell.exe -c "IEX ((New-Object Net.WebClient).DownloadString('https://example.com')) 2>$null"

# Detection 7a: AES code touching files (encrypts a single throwaway file)
New-Item C:\temp\splunktest.txt -Value 'test' -Force | Out-Null
$aes=[System.Security.Cryptography.Aes]::Create(); $enc=$aes.CreateEncryptor()
Get-ChildItem C:\temp\splunktest.txt | % { $b=[IO.File]::ReadAllBytes($_.FullName); [IO.File]::WriteAllBytes($_.FullName+'.locked', $enc.TransformFinalBlock($b,0,$b.Length)) }
```

For broader testing use **Atomic Red Team** (`T1059.001` PowerShell, `T1027` obfuscation,
`T1486` data encrypted for impact, `T1490` inhibit system recovery).

## MITRE ATT&CK mapping

| # | Technique |
|---|---|
| 1, 4, 13 | T1059.001 PowerShell, T1027 Obfuscated Files |
| 2, 3 | T1059.001, T1105 Ingress Tool Transfer, T1620 Reflective Code Loading |
| 5 | T1566.001 Spearphishing Attachment, T1204.002 User Execution |
| 6, 9, 12 | T1562.001 Disable Tools, T1562.010 Downgrade Attack, T1070.001 Clear Event Logs |
| 7 | T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery |
| 8 | T1003.001 LSASS Memory, T1003.002 SAM |
| 10 | T1071.001 Web Protocols |
| 11 | T1053.005 Scheduled Task, T1547.001 Run Keys, T1546.003 WMI Event Subscription |
