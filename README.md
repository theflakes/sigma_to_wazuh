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


WAZUH RULE:
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
