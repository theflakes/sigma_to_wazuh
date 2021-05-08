# sigma_to_wazuh
Convert Sigma rules to Wazuh rules

NOT READY FOR PRODUCTION!

## Overview:
My initial attempt at creating a Sigma to Wazuh rule converter.

Still a long ways to go. At the least, I hope to be able to convert ~70% of the Sigma rule base without needing any manual fixups.

NOTE: 
- Due to OR logic limitations in Wazuh rules, one Sigma rule can produce more than one Wazuh rule.
- PCRE case insenstivie logic is used for all logic.
- Sigma field name to Wazuh field name conversion is mapped out in the config.ini file based upon the Sigma rule's [logsource][product] field. If a field is not presently mapped, the Wazuh "full_log" field will be used.

Rule conversion needs to check the Sigma detection logic for several different nested data types:
- dictionaries
- lists
- lists of dictionaries
- single value
- dictionaries in dictionaries
- etc.

There are other things that need to be accounted for:
- Keyword logic
- Field lists to run detection logic against
- "all of", "one of", etc.

Clone the Sigma rules repository and point the "directory" variable to the Sigma rules cloned repository directory location.

## Required Python packages:  
- lxml
- BeautifulSoup 4: bs4
- ruamel.yaml

## References:  
Sigma Rules: [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)  
Wazuh HIDS: [https://wazuh.com](https://wazuh.com)

## Rule logic not yet converted:
- Any containing parentheses
- Any using Sigma near logic
- Any using a timeframe condition
- Error loading some rules needing some cleanup
- Any deprecated rules

Example Sigma rule conversions:
```
SIGMA RULE:
-----------------------------------------
title: Suspicious Compression Tool Parameters
id: 27a72a60-7e5e-47b1-9d17-909c9abafdcd
status: experimental
description: Detects suspicious command line arguments of common data compression tools
references:
    - https://twitter.com/SBousseaden/status/1184067445612535811
tags:
    - attack.collection
    - attack.t1560.001
    - attack.exfiltration # an old one
    - attack.t1020 # an old one
    - attack.t1002 # an old one
author: Florian Roth, Samir Bousseaden
date: 2019/10/15
modified: 2020/09/05
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName:
            - '7z*.exe'
            - '*rar.exe'
            - '*Command*Line*RAR*'
        CommandLine|contains:
            - ' -p'
            - ' -ta'
            - ' -tb'
            - ' -sdel'
            - ' -dw'
            - ' -hp'
    falsepositive:
        ParentImage|startswith: 'C:\Program'
    condition: selection and not falsepositive
falsepositives:
    - unknown
level: high


WAZUH RULE(s):
-----------------------------------------
<rule id="1000559" level="13">
    <!--https://github.com/SigmaHQ/sigma/tree/master/rules/windows/process_creation/win_susp_compression_params.yml-->
    <!--Sigma Rule Author: Florian Roth, Samir Bousseaden-->
    <mitre>
        <id>attack.collection</id>
        <id>attack.t1560.001</id>
        <id>attack.exfiltration</id>
        <id>attack.t1020</id>
        <id>attack.t1002</id>
    </mitre>
    <description>Suspicious Compression Tool Parameters</description>
    <options>no_full_log,alert_by_email</options>
    <group>process_creation,windows,</group>
    <field name="win.eventdata.originalFileName" negate="no" type="pcre2">(?i)7z.+\.exe|rar\.exe|Command.+Line.+RAR</field>
    <field name="win.eventdata.commandLine" negate="no" type="pcre2">(?i)\ \-p|\ \-ta|\ \-tb|\ \-sdel|\ \-dw|\ \-hp</field>
    <field name="win.eventdata.parentImage" negate="yes" type="pcre2">(?i)^(?:C:\\Program)</field>
</rule>
```
```
SIGMA RULE:
-----------------------------------------
title: Suspicious PsExec Execution - Zeek
id: f1b3a22a-45e6-4004-afb5-4291f9c21166
description: detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one
author: 'Samir Bousseaden, @neu5ron'
date: 2020/04/02
references:
    - https://github.com/neo23x0/sigma/blob/d42e87edd741dd646db946f30964f331f92f50e6/rules/windows/builtin/win_susp_psexec.yml
tags:
    - attack.lateral_movement
    - attack.t1077 # an old one
    - attack.t1021.002
logsource:
    product: zeek
    service: smb_files
detection:
    selection1:
        path|contains|all: 
            - '\\'
            - '\IPC$'
        name|endswith:
            - '-stdin'
            - '-stdout'
            - '-stderr'
    selection2:
        name|contains|all: 
            - '\\'
            - '\IPC$'
        path|startswith: 'PSEXESVC'
    condition: selection1 and not selection2
falsepositives:
    - nothing observed so far
level: high


WAZUH RULE(s):
-----------------------------------------
<rule id="1000135" level="13">
    <!--https://github.com/SigmaHQ/sigma/tree/master/rules/network/zeek/zeek_smb_converted_win_susp_psexec.yml-->
    <!--Sigma Rule Author: Samir Bousseaden, @neu5ron-->
    <mitre>
        <id>attack.lateral_movement</id>
        <id>attack.t1077</id>
        <id>attack.t1021.002</id>
    </mitre>
    <description>Suspicious PsExec Execution - Zeek</description>
    <options>no_full_log,alert_by_email</options>
    <group>zeek,smb_files,</group>
    <field name="data.path" negate="no" type="pcre2">(?i)\\\\</field>
    <field name="data.path" negate="no" type="pcre2">(?i)\\IPC\$</field>
    <field name="data.name" negate="no" type="pcre2">(?i)(?:\-stdin|\-stdout|\-stderr)$</field>
    <field name="data.path" negate="yes" type="pcre2">(?i)^(?:PSEXESVC)</field>
</rule>
```
```
SIGMA RULE:
-----------------------------------------
title: CobaltStrike Malleable Amazon Browsing Traffic Profile
id: 953b895e-5cc9-454b-b183-7f3db555452e
status: experimental
description: Detects Malleable Amazon Profile
author: Markus Neis
date: 2019/11/12
modified: 2020/09/02
references:
  - https://github.com/rsmudge/Malleable-C2-Profiles/blob/master/normal/amazon.profile
  - https://www.hybrid-analysis.com/sample/ee5eca8648e45e2fea9dac0d920ef1a1792d8690c41ee7f20343de1927cc88b9?environmentId=100
logsource:
  category: proxy
detection:
  selection1:
    c-useragent: "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
    cs-method: 'GET'
    c-uri: '/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books'
    cs-host: 'www.amazon.com'
    cs-cookie|endswith: '=csm-hit=s-24KU11BB82RZSYGJ3BDK|1419899012996'
  selection2:
    c-useragent: "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
    cs-method: 'POST'
    c-uri: '/N4215/adj/amzn.us.sr.aps'
    cs-host: 'www.amazon.com'
  condition: selection1 or selection2
falsepositives:
  - Unknown
level: high
tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001
  - attack.t1043  # an old one


WAZUH RULE(s):
-----------------------------------------
<rule id="1000011" level="13">
    <!--https://github.com/SigmaHQ/sigma/tree/master/rules/proxy/proxy_cobalt_amazon.yml-->
    <!--Sigma Rule Author: Markus Neis-->
    <mitre>
        <id>attack.defense_evasion</id>
        <id>attack.command_and_control</id>
        <id>attack.t1071.001</id>
        <id>attack.t1043</id>
    </mitre>
    <description>CobaltStrike Malleable Amazon Browsing Traffic Profile</description>
    <options>no_full_log,alert_by_email</options>
    <group>proxy,</group>
    <field name="data.c-useragent" negate="no" type="pcre2">(?i)Mozilla/5\.0\ \(Windows\ NT\ 6\.1;\ WOW64;\ Trident/7\.0;\ rv:11\.0\)\ like\ Gecko</field>
    <field name="data.cs-method" negate="no" type="pcre2">(?i)GET</field>
    <field name="data.c-uri" negate="no" type="pcre2">(?i)/s/ref=nb_sb_noss_1/167\-3294888\-0262949/field\-keywords=books</field>
    <field name="data.cs-host" negate="no" type="pcre2">(?i)www\.amazon\.com</field>
    <field name="data.cs-cookie" negate="no" type="pcre2">(?i)(?:=csm\-hit=s\-24KU11BB82RZSYGJ3BDK\|1419899012996)$</field>
</rule>
<rule id="1000012" level="13">
    <!--https://github.com/SigmaHQ/sigma/tree/master/rules/proxy/proxy_cobalt_amazon.yml-->
    <!--Sigma Rule Author: Markus Neis-->
    <mitre>
        <id>attack.defense_evasion</id>
        <id>attack.command_and_control</id>
        <id>attack.t1071.001</id>
        <id>attack.t1043</id>
    </mitre>
    <description>CobaltStrike Malleable Amazon Browsing Traffic Profile</description>
    <options>no_full_log,alert_by_email</options>
    <group>proxy,</group>
    <field name="data.c-useragent" negate="no" type="pcre2">(?i)Mozilla/5\.0\ \(Windows\ NT\ 6\.1;\ WOW64;\ Trident/7\.0;\ rv:11\.0\)\ like\ Gecko</field>
    <field name="data.cs-method" negate="no" type="pcre2">(?i)POST</field>
    <field name="data.c-uri" negate="no" type="pcre2">(?i)/N4215/adj/amzn\.us\.sr\.aps</field>
    <field name="data.cs-host" negate="no" type="pcre2">(?i)www\.amazon\.com</field>
</rule>
```
