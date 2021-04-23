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
