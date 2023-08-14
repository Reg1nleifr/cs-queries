# cs-queries
Curation of several cs queries. Almost all of these queries are at least inspired from /r/crowdstrike. This is my attempt in giving back to the community.


### Local Account Creation
```
index=main event_simpleName=UserAccountCreated
| stats values(UserName) by aid, ComputerName
```

### Accounts Added to Local Administrative Groups	
```
index=main event_simpleName=UserAccountAddedToGroup
| eval GroupRid_dec=tonumber(ltrim(tostring(GroupRid), "0"), 16) | lookup grouprid_wingroup.csv GroupRid_dec OUTPUT WinGroup
| convert ctime(ContextTimeStamp_decimal) AS GroupMoveTime | join aid, UserRid
    [search event_simpleName=UserAccountCreated]
| convert ctime(ContextTimeStamp_decimal) AS UserCreateTime | table UserCreateTime UserName GroupMoveTime WinGroup ComputerName
| rename UserCreateTime as "Creation Time",UserName as Username,GroupMoveTime as "Group Add Time"
| rename WinGroup as "Local Security Group",ComputerName as Hostname
```

### Powershell Encoded Commands
```
FileName=powershell.exe (base64 OR -enc OR -ec OR -en OR -enco OR -encod OR -encode OR -encoded OR -encodedC OR -encodedco OR -encodedcom OR -encodedcomm OR -encodedcomma OR -encodedcomman OR -encodedcommand)
| stats values(CommandLine) as "commands" by ComputerName
```

### All hosts with dns request to collector.github.com
```
event_simpleName=DnsRequest DomainName="collector.github.com"
| stats count by DomainName ComputerName
| rename count as "Domain & ComputerName Count"
```

### Suspicious Process (MS / Webserver) spawning commandline or related program*
*Performance could be improved by removing the join.
```
event_simpleName=ProcessRollup2 FileName IN (winword.exe, powerpnt.exe, excel.exe, visio.exe, outlook.exe, onenote.exe, one.exe, apache*.exe, tomcat*.exe, nginx.exe, httpd.exe, php-cgi.exe, w3wp.exe)
| rename TargetProcessId_decimal AS ParentProcessId_decimal
| rename ImageFileName AS ParentImage
| rename CommandLine AS ParentCommandLine
| join ParentProcessId_decimal
    [ search event_simpleName=ProcessRollup2 FileName IN (powershell.exe, control.exe, cmd.exe, pwsh.exe, ping.exe)
        AND NOT (CommandLine IN ("*\\control.exe input.dll", "*\\control.exe\" input.dll"))
    ]
| table _time cid aid Customer ComputerName event_simpleName UserName ImageFileName CommandLine ParentImage ParentCommandLine TargetFileName FileName MD5HashData SHA256HashData CommandHistory
| sort -_time
```

### WMI Event Consumer & Provider Registration
```
event_platform=win AND (event_simpleName=WmiFilterConsumerBindingEtw OR event_simpleName=WmiProviderRegistrationEtw)
```

### Scripts written to Temp directory
```
event_simpleName=NewScriptWritten FilePath="*\\Windows\\Temp\\*" NOT FilePath="*\\Windows\\Temp\\*\\*"
| stats count by TargetFileName
| where count < 10
| sort - count asc
```

### Processes related to enumeration
```
event_simpleName="ProcessRollup2" AND (FileName IN ("net.exe", "gpresult.exe", "dsquery.exe", "whoami.exe", "regedit.exe", "dir.exe", "type.exe", "dsquery.exe", "csvde.exe", "nltest.exe", "tasklist.exe", "qwinsta.exe", "ver.exe", "qprocess.exe", "query.exe", "nbtstat.exe", "wevtutil.exe", "taskkill.exe", "systeminfo.exe", "ipconfig.exe", "netstat.exe")
OR (FileName IN ("powershell.exe", "cmd.exe", "pwshell.exe", "posh.exe") AND CommandLine IN ("*objectcategory*", "*username*", "*domain*", "*HKCU*", "*HKEY*", "*HKLM*")))
| fillnull value="SYSTEM" UserName
| fillnull value="-" GrandParentBaseFileName
| stats count earliest(_time) AS Etime latest(_time) AS Ltime range(_time) AS Diff dc(FileName) AS DC_FileName values(UserName) AS Username values(GrandParentBaseFileName) AS Granies values(ParentBaseFileName) AS ParentFileName values(FileName) AS FileNames values(CommandLine) as CommandLines by ComputerName
| convert ctime(Etime) ctime(Ltime)
| where DC_FileName >= 3
```

### IP to Commandline
Event => More Actions => Draw Process Tree
```
event_simpleName=NetworkConnectIP4 AND ComputerName="myendpointname" AND RemoteAddressIP4=1.2.3.4 AND RPort=1337
```

### IP to Commandline complex
```
index=main AND (event_simpleName=ProcessRollup2 OR event_simpleName=SyntheticProcessRollup2 OR event_simpleName=DnsRequest OR event_simpleName=NetworkConnectIP4) AND ComputerName=myendpointname
| eval falconPID=coalesce(TargetProcessId_decimal, ContextProcessId_decimal)
| fields aid, event_simpleName, falconPID, FileName, CommandLine, DomainName, RemoteAddressIP4, RPort, ContextTimeStamp_decimal, ProcessStartTime_decimal
| eval CommandLine=substr(CommandLine,1,100)
| stats dc(event_simpleName) AS events, values(ProcessStartTime_decimal) as fileExecutionTime, earliest(ContextTimeStamp_decimal) as firstConnection, latest(ContextTimeStamp_decimal) as lastConnection, values(FileName) as FileName, values(CommandLine) as CommandLine, values(DomainName) as DomainName, values(RemoteAddressIP4) as RemoteAddressIP4, values(RPort) as RPort by aid, falconPID
| search events>1
| dedup FileName
| where isnotnull(FileName)
| convert ctime(fileExecutionTime) ctime(firstConnection) ctime(lastConnection)
| search RemoteAddressIP4=1.2.3.4, RPort=1337
```

### Domain to Commandline
Event => More Actions => Draw Process Tree
```
event_simpleName=DnsRequest AND ComputerName=myendpointname AND DomainName=myexternaldomain.org
```

### Domain to Commandline complex
```
index=main AND (event_simpleName=ProcessRollup2 OR event_simpleName=SyntheticProcessRollup2 OR event_simpleName=DnsRequest) AND ComputerName=myendpointname
| eval falconPID=coalesce(TargetProcessId_decimal, ContextProcessId_decimal)
| fields aid, event_simpleName, falconPID, FileName, CommandLine, DomainName, ContextTimeStamp_decimal, ProcessStartTime_decimal
| search DomainName=myexternaldomain.org OR NOT DomainName="*"
| stats dc(event_simpleName) AS events, values(ProcessStartTime_decimal) as fileExecutionTime, earliest(ContextTimeStamp_decimal) as firstConnection, latest(ContextTimeStamp_decimal) as lastConnection, values(FileName) as FileName, values(CommandLine) as CommandLine, values(DomainName) as DomainName by aid, falconPID
| search DomainName=myexternaldomain.org
```

### Dll sideloading attempts on dlls
e.g. via: https://github.com/TactiKoolSec/SideLoadHunter
```
event_platform=win SignInfoFlags_decimal="*" event_simpleName IN (ImageHash, ClassifiedModuleLoad, ModuleLoadV3DetectInfo, UnsignedModuleLoad)
| search FileName IN (anythingthatinterestsyou.dll)
| eval isInWinDir=if(match(FilePath,"(?i).*(System32|SysWow64).*"),"Yes","No")

| search isInWinDir=No
| search NOT SignInfoFlags_decimal IN (2, 8, 16, 32 , 128, 786434, 9175042, 33554432)
| search NOT (SignInfoFlags_decimal=787456 FileName IN (d3dcompiler_47.dll, wimgapi.dll))
| search NOT (SignInfoFlags_decimal=32768 FileName=oci.dll)
| rex field=FilePath "\\\Device\\\HarddiskVolume\d+(?<filePath>.+)$"
| stats values(filePath) as filePaths, values(ComputerName) as computerNames, values(SignInfoFlags_decimal) as SignInfoFlags_decimal, values(SHA256HashData) as SHA256HashData, count by FileName
```

### All executables by certificate
```
EventType=Event_ExternalApiEvent ExternalApiType=Event_ModuleSummaryInfoEvent
| lookup local=true appinfo.csv SHA256HashData OUTPUT FileName CompanyName FileDescription
| search CompanyName=*Microsoft*
| stats dc(AgentIdString) as uniqueEndpoints values(FileName) as fileName values(CompanyName) as companyName values(IssuerCN) as certCN values(FileDescription) as description by SHA256HashData
```

### Suspious Service Paths
Be prepared to tune this for your environment.
```
event_platform=win event_simpleName IN (CreateService) NOT ServiceType_decimal IN (1,2) ServiceImagePath="*"
| search NOT ServiceImagePath IN ("C:\\WINDOWS\\System32\\svchost.exe -k *", "C:\\Program Files\\*", "C:\\Program Files (x86)\\*")
| stats values(ServiceImagePath) as ServiceImagePath, values(ServiceDisplayName) as ServiceDisplayName, values(ServiceType_decimal) as ServiceType_decimal, values(ServiceStart_decimal) as ServiceStart_decimal, values(ServiceErrorControl_decimal) as ServiceErrorControl_decimal, count by ComputerName
```

### Logons on client/server
```
event_platform=win event_simpleName=UserLogon ComputerName IN (myendpointname)
| eval LogonType=case(LogonType_decimal="2", "Local Logon", LogonType_decimal="3", "Network", LogonType_decimal="4", "Batch", LogonType_decimal="5", "Service", LogonType_decimal="6", "Proxy", LogonType_decimal="7", "Unlock", LogonType_decimal="8", "Network Cleartext", LogonType_decimal="9", "New Credentials", LogonType_decimal="10", "RDP", LogonType_decimal="11", "Cached Credentials", LogonType_decimal="12", "Auditing", LogonType_decimal="13", "Unlock Workstation")
```

### Links opened from outlook
```
event_simpleName="ProcessRollup2" ParentBaseFileName="outlook.exe" CommandLine="*single-argument*"
| table ComputerName CommandLine
```

### Linux Server Modes
```
earliest=-26h event_platform=Lin event_simpleName IN (ConfigStateUpdate, SensorHeartbeat, OsVersionInfo)
| stats latest(ConfigStateData) as ConfigStateData, latest(SensorStateBitMap_decimal) as SensorStateBitMap_decimal, latest(OSVersionString) as OSVersionString by cid, aid
| rex field=OSVersionString "Linux\\s\\S+\\s(?<kernelVersion>\\S+)?\\s.*"
| eval ConfigStateData=split(ConfigStateData, ",")
| eval userModeEnabled=if(match(ConfigStateData,"1400000000c4"),"Yes","No")
| eval rfmFlag=if(match(SensorStateBitMap_decimal,"2"),"Yes","No")
| eval sensorState=case(
userModeEnabled == "Yes" AND rfmFlag == "Yes", "User Mode Enabled",
userModeEnabled == "No" AND rfmFlag == "No", "Kernel Mode Enabled",
userModeEnabled == "No" AND rfmFlag == "Yes", "RFM",
true(),"-")
| lookup local=true aid_master.csv aid OUTPUT ComputerName, AgentVersion as falconVersion, Version as osVersion, FirstSeen, Time as LastSeen
| fillnull kernelVersion value="-"
| table aid, ComputerName, falconVersion, osVersion, kernelVersion, sensorState, osVersion, FirstSeen, LastSeen
| convert ctime(FirstSeen) ctime(LastSeen)
| sort + ComputerName
```
