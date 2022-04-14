# sigma_to_wazuh
Convert Sigma rules to Wazuh rules

# NOTE: Some logic conversion is still broken due to the complexities of converting Sigma OR logic into Wazuh OR logic unfortunately.

## How to:
Clone repository.  

Install Python3 packages: ```pip3 install lxml bs4 ruamel.yaml```

Clone Sigma repository: [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)

Update "config.ini" variables where necessary.
- directory: point it to the rules folder in the cloned Sigma repository

Run sigma_to_wazuh.py
- You'll see output of rules that are skipped, rules that error out on loading, followed by a summary of the rules conversion.

## Overview:
My initial attempt at creating a Sigma to Wazuh rule converter.

Sigma rule GUID to Wazuh rule ID use is tracked between runs in a file defined in the ini configuration: rule_id_file. This should ensure that a given Sigma rule when converted will always use the same Wazuh rule IDs. 

Depending on the logic used in a Sigma rule, the conversion of a single Sigma rule may create multiple Wazuh rules. The conversion does not gaurentee that the same Wazuh rule ID is used for each Wazuh rule created by one Sigma rule. The same set of Wazuh rule IDs will be used though, assuming that a Sigma rule's logic has not drastically changed from its previous conversion.

Still a long ways to go. At the least, I hope to be able to convert ~70% of the Sigma rule base without needing any manual fixups.

### More work needs to be completed on Wazuh if_sid rule dependencies and Sigma to Wazuh field name transforms.

## get-wazuh_rule_info.py
- creates a CSV file named "wazuh_rule_report.csv" with the below information
```"id","level","description","decoded_as","fields","parents","children"```
- Fields = all fields used in Field logic rule entries
- Parents = all rules this rule depends on to be run against a log
- Children = all rule IDs where this rule occurs in their if_sid  

I use this script for writing Sigma rules to understand when I need to use if_sid to ensure my new rule will fire on the correct logs.

## sigma_to_wazuh.py
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
- Wazuh "decoded_as", "if_group", and other logic sometimes required for a rule to be run against log not yet accounted for
- Any using Sigma near logic
- Any using a timeframe condition
- Error loading some rules needing some cleanup
- Any deprecated rules

Example summary output:
```
***************************************************************************
 Number of Sigma Experimental rules skipped: 0
    Number of Sigma TIMEFRAME rules skipped: 30
        Number of Sigma PAREN rules skipped: 0
         Number of Sigma NEAR rules skipped: 25
         Number of Sigma 1_OF rules skipped: 11
       Number of Sigma ALL_OF rules skipped: 16
       Number of Sigma CONFIG rules skipped: 0
        Number of Sigma ERROR rules skipped: 59
-------------------------------------------------------
                  Total Sigma rules skipped: 119
                Total Sigma rules converted: 898
-------------------------------------------------------
                  Total Wazuh rules created: 1346
-------------------------------------------------------
                          Total Sigma rules: 1017
                    Sigma rules converted %: 88.3
***************************************************************************
```
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
<rule id="1000662" level="13">
    <info type="link">https://github.com/SigmaHQ/sigma/tree/master/rules/windows/process_creation/win_susp_compression_params.yml</info>
    <!--Sigma Rule Author: Florian Roth, Samir Bousseaden-->
    <!--Description: Detects suspicious command line arguments of common data compression tools-->
    <!--Date: 2019/10/15-->
    <!--Status: experimental-->
    <!--ID: 27a72a60-7e5e-47b1-9d17-909c9abafdcd-->
    <mitre>
        <id>attack.collection</id>
        <id>attack.t1560.001</id>
        <id>attack.exfiltration</id>
        <id>attack.t1020</id>
        <id>attack.t1002</id>
    </mitre>
    <description>Suspicious Compression Tool Parameters</description>
    <options>no_full_log</options>
    <options>alert_by_email</options>
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
<rule id="1000144" level="13">
    <info type="link">https://github.com/SigmaHQ/sigma/tree/master/rules/network/zeek/zeek_smb_converted_win_susp_psexec.yml</info>
    <!--Sigma Rule Author: Samir Bousseaden, @neu5ron-->
    <!--Description: detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one-->
    <!--Date: 2020/04/02-->
    <!--ID: f1b3a22a-45e6-4004-afb5-4291f9c21166-->
    <mitre>
        <id>attack.lateral_movement</id>
        <id>attack.t1077</id>
        <id>attack.t1021.002</id>
    </mitre>
    <description>Suspicious PsExec Execution - Zeek</description>
    <options>no_full_log</options>
    <options>alert_by_email</options>
    <group>zeek,smb_files,</group>
    <field name="full_log" negate="no" type="pcre2">(?i)\\\\</field>
    <field name="full_log" negate="no" type="pcre2">(?i)\\IPC\</field>
    <field name="full_log" negate="no" type="pcre2">(?i)(?:\-stdin|\-stdout|\-stderr)</field>
    <field name="full_log" negate="yes" type="pcre2">(?i)(?:PSEXESVC)</field>
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
<rule id="1000015" level="13">
    <info type="link">https://github.com/SigmaHQ/sigma/tree/master/rules/proxy/proxy_cobalt_amazon.yml</info>
    <!--Sigma Rule Author: Markus Neis-->
    <!--Description: Detects Malleable Amazon Profile-->
    <!--Date: 2019/11/12-->
    <!--Status: experimental-->
    <!--ID: 953b895e-5cc9-454b-b183-7f3db555452e-->
    <mitre>
        <id>attack.defense_evasion</id>
        <id>attack.command_and_control</id>
        <id>attack.t1071.001</id>
        <id>attack.t1043</id>
    </mitre>
    <description>CobaltStrike Malleable Amazon Browsing Traffic Profile</description>
    <options>no_full_log</options>
    <options>alert_by_email</options>
    <group>proxy,</group>
    <field name="full_log" negate="no" type="pcre2">(?i)Mozilla/5\.0\ \(Windows\ NT\ 6\.1;\ WOW64;\ Trident/7\.0;\ rv:11\.0\)\ like\ Gecko</field>
    <field name="full_log" negate="no" type="pcre2">(?i)GET</field>
    <field name="full_log" negate="no" type="pcre2">(?i)/s/ref=nb_sb_noss_1/167\-3294888\-0262949/field\-keywords=books</field>
    <field name="full_log" negate="no" type="pcre2">(?i)www\.amazon\.com</field>
    <field name="full_log" negate="no" type="pcre2">(?i)(?:=csm\-hit=s\-24KU11BB82RZSYGJ3BDK\|1419899012996)</field>
</rule>
<rule id="1000016" level="13">
    <info type="link">https://github.com/SigmaHQ/sigma/tree/master/rules/proxy/proxy_cobalt_amazon.yml</info>
    <!--Sigma Rule Author: Markus Neis-->
    <!--Description: Detects Malleable Amazon Profile-->
    <!--Date: 2019/11/12-->
    <!--Status: experimental-->
    <!--ID: 953b895e-5cc9-454b-b183-7f3db555452e-->
    <mitre>
        <id>attack.defense_evasion</id>
        <id>attack.command_and_control</id>
        <id>attack.t1071.001</id>
        <id>attack.t1043</id>
    </mitre>
    <description>CobaltStrike Malleable Amazon Browsing Traffic Profile</description>
    <options>no_full_log</options>
    <options>alert_by_email</options>
    <group>proxy,</group>
    <field name="full_log" negate="no" type="pcre2">(?i)Mozilla/5\.0\ \(Windows\ NT\ 6\.1;\ WOW64;\ Trident/7\.0;\ rv:11\.0\)\ like\ Gecko</field>
    <field name="full_log" negate="no" type="pcre2">(?i)POST</field>
    <field name="full_log" negate="no" type="pcre2">(?i)/N4215/adj/amzn\.us\.sr\.aps</field>
    <field name="full_log" negate="no" type="pcre2">(?i)www\.amazon\.com</field>
</rule>
```
