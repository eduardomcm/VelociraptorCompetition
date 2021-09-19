# 2021 Velociraptor Competition

My 2021 Velociraptor Competition package contains multiple Windows Detection, Application, Event log and Scanner artifacts, four new MacOS artifacts and one Server artifact.

These artifacts were created based on real-world Incident Response use-cases, with the mindset of an Incident Responder and a Threat Hunter. 

They build upon Velociraptor's capabilities to expand the ways DFIR/Threat Hunter analysts can perform their tasks, with more accuracy, efficiency
and practicality.

# Windows.Detection.HashHunt

  On multiple cases, an analyst may want to check for the presence of certain files (IOCs or otherwise) 
  in a filesystem by their hashes, which this artifact will allow you to do. 
  
  Velociraptor's current hash-related hunting artifacts must first generate a database of hashes on a client, 
  prior to being able to query for hashes. 
  
  This artifact, instead, allows an analyst to directly hunt for a list of hashes on endpoints. 
      
  The analyst can choose to:
  1 - manually enter hashes in a csv table, OR
  2 - upload a CSV list as the "CSV_HASH_LIST" tool in this artifact.
  
# Windows.Detection.PEInjection
  
  This artifact will use the vad() plugin to enumerate the memory regions of each running process,
  and return regions marked as PAGE_EXECUTE_READWRITE ('xrw') to find possibly injected processes. 
  Out of the pages marked as 'xrw', it performs a Yara scan to find and return hits on regions containing
  PE Headers. 
  
  Out of the regions containing the PE Headers, it will then use the parse_pe() plugin to try and
  parse the injected PE, returning all possible characteristics from them. It allows the analyst to find 
  certain PE characteristics out of injected PEs directly from the process running in memory.
  
  MITRE ATT&CK ID: T1055 - Process Injection

# Windows.Detection.ParsePE

  This artifact parses PE information out of targeted folder/files chosen by the analyst, using the TargetGlob
  parameter, and allows them to filter results based on VersionInformation table or ImpHash.
  
  An analyst may be hunting for PEs with certain characteristics (e.g.: PE Original Filename, PE ImpHash, etc.), 
  given a certain hunt mission, and this artifact allows them to target these specifics.
  
# Windows.Applications.OfficeServerCache

  This artifact returns the Office Internet Server Cache Registry keys and values
  in order to identify possible C2 URLs from malicious opened Office documents.
  
  Such reg keys should be written by exploits, such as the recent CVE-2021-40444
  (Microsoft MSHTML Remote Code Execution Vulnerability), and finding URLs in them
  is a strong indicator of this CVE exploitation. 
  
  Given it is a registry based artifact, it provides a very quick and easy check for 
  signs of CVE-2021-40444 signs of exploitation.
  
# Windows.Applications.JLECmd

  This artifact executes Eric Zimmerman's JLECmd and returns the output for analysis. 
  It aims to complete Velociraptor's coverage for all of the SANS Windows Forensic Analysis Poster
  
  Objective:
  
  - The Windows 7 task bar (Jump List) is engineered to allow users to “jump” or
  access items they have frequently or recently used quickly and easily. 
  This functionality cannot only include recent media files; it must also include recent tasks.
  - The data stored in the AutomaticDestinations folder will each have a unique file 
  prepended with the AppID of the associated application. 
  
  Interpretation:
  
  First time of execution of application.
  - Creation Time = First time item added to the AppID file.
  
  Last time of execution of application w/file open.
  - Modification Time = Last time item added to the AppID file. 

  References:
  - https://github.com/EricZimmerman/JLECmd

# Windows.Applications.ProcessHollowingEnriched

  This artifact executes Hasherezade's Hollows Hunter, enriches it with Process List (PsList)
  artifact information, and returns the enriched rows for analysis. 
  
  By enriching Hollows Hunter output, the analyst will have better visibility over the results, 
  allowing better filtering of possible false positives and correlation with other previously
  found IOCs.
    
  MITRE ATT&CK ID: T1055 - Process Injection
  
  References:
  - https://github.com/hasherezade/hollows_hunter
  
# Windows.EventLogs.PassTheHash

  Pass-The-Hash attacks are usually performed by dumping the connected user password’s hash (AKA NTLM hash)
  from memory and instead of using a clear text password to authenticate a user,
  the hash is passed straight to a remote host as an NTLM authentication 
  instead of requesting service ticket from the domain controller using Kerberos, 
  therefore the actual authentication occurs on the target endpoint.
  
  The detection of Pass-The-Hash attack can be done with any “Negotiation” 
  logon sessions that contains the Logon Type "9" and Logon Process Name "seclogo", 
  and these are the parameters this artifact is based on.
  
  There’s a high probability that Pass-The-Hash attack will be executed via this method, 
  and the only time that you’ll see Logon Type ‘9’ in “Negotiation” session will be if 
  someone is using RUNAS command with the /NETONLY flag, which is not something you see 
  every day in normal environments, so the false positive rate in this method is very low.
  Even though there can be false positives, encountering “Negotiation” logon session with Logon Type 9 
  usually means someone tried to pass-the-hash instead of entering the username’s password.
  
  References:
  - https://jblog.javelin-networks.com/blog/detecting-pass-ticket-pass-hash-attack-using-simple-wmi-commands
  - https://stealthbits.com/blog/how-to-detect-pass-the-hash-attacks
  - https://www.elastic.co/blog/how-attackers-abuse-access-token-manipulation
  
# Windows.EventLogs.ZeroLogon
  
  Even though it has been patched by Microsoft long ago, organizations who do not implement patches in all of their
  Domain Controllers might still be exploited by the ZeroLogon vulnerability during an attacker's
  post-exploitation phase. So much so, that it is part of the arsenal in the recently leaked Conti Ransomware group's 
  operator's manual.
  
  This artifact will extract Event Logs related to ZeroLogon exploitation and should be executed
  in Domain Controllers only. 
  
  It was created after testing with multiple ZeroLogon implementations, such as Cobalt Strike's, 
  SharpZeroLogon and other ZeroLogon tools found during breach cases.

# Windows.EventLogs.NTLMRelayAttack

  This artifact detect possible signs of NTLM Relay Attacks in event logs from Domain Controllers, 
  such as the ones produced by PetitPotam and Impacket's NTLMRelayX. 
  
  It was created after multiple tests with PetitPotam, Impacket and Rubeus tools, and also based on
  the articles references within the artifact.
  
  Note: There are potential false positives.
  
  MITRE ATT&CK ID: [T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
  
  References: 
  - https://posts.bluraven.io/detecting-petitpotam-and-other-domain-controller-account-takeovers-d3364bd9ee0a
  - https://isc.sans.edu/forums/diary/Active+Directory+Certificate+Services+ADCS+PKI+domain+admin+vulnerability/27668/

# Windows.Registry.AteraNetworks

  This artifact was created after working on multiple ransomware Incident Response engagements where
  threat actors have deployed Atera and Splashtop RMM software in victim's environments, and used them
  as Command and Control tools.

  Once a threat actor installs Atera, it leaves behind a registry key with the configuration of the agent,
  including the email address utilized to register to the service. This registry key can be used to find
  installations of this tool, and the email utilized in Threat Intelligence efforts.

  Atera and Splashtop (along with other RMM tools such as AnyDesk and others), have also been mentioned in
  the recently leaked Conti Ransomware group's operator's manual as part of their arsenal.
  
  References:
  - https://www.advintel.io/post/secret-backdoor-behind-conti-ransomware-operation-introducing-atera-agent
  
# Windows.Registry.UsrClass

  Based off of Windows.Registry.NTUser artifact, this artifact instead searches for keys or values within the user's
  UsrClass registry hives, which contains keys such as Shell Bags and MuiCache.

  It is used within the Windows.Registry.MuiCache, also part of this package.
  
# Windows.Registry.MuiCache

  Each time that you start using a new application, Windows operating system automatically extracts 
  the application name from the version resource of the exe file, and stores it for using it later, 
  in Registry key known as the 'MuiCache'. Even if your delete MUICache items, they'll reappear
  in the next time that you run the application.

  The location of the MUICache data in the registry is under 
  HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache, and
  these keys are returned by calling the newly build Windows.Registry.UsrClass supporting artifact.

# Windows.Scanner.Loki

  This artifact executed the open-source scanning tool Loki on targeted clients.

  Loki users out there may utilize their breadth of Yara-signatures, alongside PE-Sieve and other Loki 
  IOC/signature capabilities to perform scans via Velociraptor at scale, and return the output to be
  filtered in VQL. A great combination of two powerful open-source threat hunting tools.
  
  References:
  - https://github.com/Neo23x0/Loki

# Server.Enrichment.IPList

  This handy artifact makes use of the recently added geoip() plugin, in conjunction with MaxMind databases,
  in order to enrich a list of IPs which can be provided in multiple ways, at the convenience of the analyst.

  By combining both Geo City and Geo ISP MaxMind databases, the analyst may be able to enrich any number of 
  IPs supplied to this artifact, including large lists with the intention of performing VQL queries for 
  associations. Examples:

  - Finding specific ASNs known to be utilized by a certain threat actor group, within 
  a list of IPs observed in network logs;
  - Finding IPs from specific countries, within any supplied list of IPs.
  - Performing LFA (Least Frequency Analysis) on large lists of supplied IPs, identifying outliers based 
  on Geolocation or ISP information.

  You may supply the IPs in 3 different ways, and the priority order of arguments is the following

  - (1) If a single IP is supplied, only it will be resolved;
  - (2) If the CSV table has values manually inputted, only the table will be resolved;
  - (3) If a CSV list is uploaded under tool 'CSV_IP_LIST', only the CSV list will be resolved 
  (The fist column name must be "IP")
  
# MacOS.Triage.AutoMacTC

  This artifact leverages CrowdStrike's AutoMacTC open-source collector to collect triage data.
  It can be thought of as a Kape Triage version of a collector, for MacOS.

  You may select the included modules by modifying the parameter **Module** 
  according to the available module names below, or you may include all and exclude specific modules 
  by specifying modules in the **ExcludeModules** parameter, in order to collect what you need.

  Reference:
  - https://github.com/CrowdStrike/automactc
  
# MacOS.Sysdiagnose

  This artifact executes MacOS sysdiagnose tool and uploads the compressed output for further investigation.
  
  The sysdiagnose tool gathers system diagnostic information helpful in investigating system performance issues.  
  A great deal of information is harvested, spanning system state and configuration.
  
  What sysdiagnose collects:
   
  -   A spindump of the system
  -   Several seconds of fs_usage output
  -   Several seconds of top output
  -   Data about kernel zones
  -   Status of loaded kernel extensions
  -   Resident memory usage of user processes
  -   Recent system logs
  -   A System Profiler report
  -   Recent crash reports
  -   Disk usage information
  -   I/O Kit registry information
  -   Network status
  
  References:
  - https://labs.sentinelone.com/macos-incident-response-part-1-collecting-device-file-system-data/
  
# MacOS.Sys.BashHistory 

  As MacOS artifacts are still highly unexplored in Velociraptor, it was missing a BashHistory parser
  which is so valuable during investigations.
  
  This artifact enables grep of Bash and alternate shells (python/zsh/etc.) history files, with 
  regex parameters to filter in/out specific strings.
  
# MacOS.Applications.Safari.History

  During tests it was noticed that MacOS protects the History.db Safari database from
  being read directly, under normal circumstances. This causes several DFIR tools to fail to
  parse Safari's browsing history.
  
  This artifact provides the analyst with the capability to parse Safari history, by creating
  temporary copies of the History.db files across specific targeted users (regex filter),
  and performing a SQLite query on them to return all user's Safari history.
