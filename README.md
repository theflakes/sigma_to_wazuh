# sigma_to_wazuh
Convert Sigma rules to Wazuh rules

## Overview:
My initial attempt at creating a Sigma to Wazuh rule converter.

Still a long ways to go. At the least, I hope to be able to convert ~70% of the Sigma rule base without needing any manual fixups.

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
