#!//usr/bin/python3
"""
    Author: Brian Kellogg

    Purpose: Sigma to Wazuh rule converter.

    References:
        Sigma: https://github.com/SigmaHQ/sigma
        Wazuh: https://wazuh.com

    Complete parsing of Sigma logic is not implemented. Just simpler rules are converted presently.
    Rules skipped:
        - Any containing parentheses
        - Any using Sigma near logic
        - Any using a timeframe condition
    Stats on all the above will be reported by this script.
"""
import os
import configparser
import bs4, re
import json
import base64
from xml.etree.ElementTree import Element, SubElement, Comment, tostring, fromstring
from ruamel.yaml import YAML


class BuildRules(object):
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read(r'./config.ini')
        self.rules_link = self.config.get('sigma', 'rules_link')
        self.low = self.config.get('levels', 'low')
        self.medium = self.config.get('levels', 'medium')
        self.high = self.config.get('levels', 'high')
        self.critical = self.config.get('levels', 'critical')
        self.no_full_log = self.config.get('options', 'no_full_log')
        self.sigma_guid_email = eval(self.config.get('options', 'sigma_guid_email'), {}, {})
        self.alert_by_email = self.config.get('options', 'alert_by_email')
        self.email_levels = self.config.get('options', 'email_levels')
        self.rule_id_start = int(self.config.get('options', 'rule_id_start'))
        self.rule_id = self.rule_id_start
        self.out_file = self.config.get('sigma', 'out_file')
        self.track_rule_ids_file = self.config.get('options', 'rule_id_file')   # file that stores Sigma GUID to Wazuh rule ID mappings
        self.track_rule_ids = self.load_wazuh_to_sigma_id_mappings()    # in memory Dict of self.track_rule_ids_file contents
        self.used_wazuh_ids = self.get_used_wazuh_rule_ids()    # used Wazuh rule IDs used in previous runs
        self.used_wazuh_ids_this_run = []   # new Wazuh rule IDs consummed this run
        self.root = self.create_root()
        self.rule_count = 0
        # monkey patching prettify
        # reference: https://stackoverflow.com/questions/15509397/custom-indent-width-for-beautifulsoup-prettify
        orig_prettify = bs4.BeautifulSoup.prettify
        r = re.compile(r'^(\s*)', re.MULTILINE)
        def prettify(self, encoding=None, formatter="minimal", indent_width=4):
            return r.sub(r'\1' * indent_width, orig_prettify(self, encoding, formatter))
        bs4.BeautifulSoup.prettify = prettify

    def load_wazuh_to_sigma_id_mappings(self):
        """
            Need to track Wazuh rule ID between runs so that any rules dependent
            on these auto generated rules will not be broken by subsequent runs.
        """
        try:
            with open(self.track_rule_ids_file, 'r') as ids:
                return json.load(ids)
        except:
            print("ERROR loading rule id tracking file: %s" % self.track_rule_ids_file)
            return {}

    def get_used_wazuh_rule_ids(self):
        #ids = [str(self.rule_id_start)] # never use the first number
        ids = []
        for k, v in self.track_rule_ids.items():
            for i in v:
                if i not in ids:
                    ids.append(i)
        return ids

    def create_root(self):
        root = Element('group')
        root.set('name', 'sigma,')
        self.add_header_comment(root)
        return root

    def add_header_comment(self, root):
        comment = Comment("""
Author: Brian Kellogg
Sigma: https://github.com/SigmaHQ/sigma
Wazuh: https://wazuh.com
All Sigma rules licensed under DRL: https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md
""")
        root.append(comment)

    def update_rule_id_mappings(self, sigma_guid, wid):
        if sigma_guid in self.track_rule_ids:
            if wid not in self.track_rule_ids[sigma_guid]:
                self.track_rule_ids[sigma_guid].append(wid)
        else:
            self.track_rule_ids[sigma_guid] = [wid]

    def find_unused_rule_id(self, sigma_guid):
        """
            Lets make sure we use a Wazuh rule ID not already assigned to a Sigma GUID
        """
        while True:
            self.rule_id += 1
            wid = str(self.rule_id)
            if wid not in self.used_wazuh_ids:
                if wid not in self.used_wazuh_ids_this_run:
                    self.update_rule_id_mappings(sigma_guid, wid)
                    return wid
        
    def find_wazuh_id(self, sigma_guid):
        """
            Has this Sigma rule already been converted and assigned a Wazuh rule ID?
            If so, we need to keep it the same.
        """
        if sigma_guid in self.track_rule_ids:
            for wid in self.track_rule_ids[sigma_guid]:
                if wid not in self.used_wazuh_ids_this_run:
                    return wid
        wid = self.find_unused_rule_id(sigma_guid)
        return wid

    def init_rule(self, level, sigma_guid):
        rule = SubElement(self.root, 'rule')
        wid = self.find_wazuh_id(sigma_guid)
        self.used_wazuh_ids_this_run.append(wid)
        rule.set('id', wid)
        rule.set('level', self.get_level(level))
        self.rule_count += 1
        return rule

    def convert_field_name(self, product, field):
        if product in self.config.sections():
            if field in self.config[product]:
                return self.config[product][field]
        return "full_log" # target full log if we cannot find the field

    def if_ends_in_space(self, value, is_b64):
        """
            spaces at end of logic are being chopped, therefore hacking this fix
        """
        if value.startswith('(?i)'): # if value start with this, it is a Sigma regex, remove it as it will be added again
            value = value[4:]
        if value.endswith(' '):
            value = '(?:' + value + ')'
        if is_b64:
            return value
        return '(?i)' + value

    def handle_full_log_field(self, value):
        """
            We do not want to honor Sigma startwith and endswith logic if we use the full_log field
        """
        if value.startswith('^'):
            value = value[1:]
        if value.endswith('$') and not value[-2:] == '\$':
            value = value[:-1]
        return value

    def add_logic(self, rule, product, field, negate, value, is_b64):
        logic = SubElement(rule, 'field')
        name = self.convert_field_name(product, field)
        logic.set('name', name)
        logic.set('negate', negate)
        logic.set('type', 'pcre2')
        if name == 'full_log': # should we use .* or .+ to replace *
            logic.text = self.if_ends_in_space(self.handle_full_log_field(value), is_b64).replace(r'\*', r'.+')
        else:
            logic.text = self.if_ends_in_space(value, is_b64).replace(r'\*', r'.+') # assumption is all '*' are wildcards

    def get_level(self, level):
        if level == "critical":
            return self.critical
        if level == "high":
            return self.high
        if level == "medium":
            return self.medium
        
        return self.low

    def add_options(self, rule, level, sigma_guid):
        if self.no_full_log == 'yes':
            options = SubElement(rule, 'options')
            options.text = "no_full_log"
        if self.alert_by_email == 'yes' and (level in self.email_levels):
            options = SubElement(rule, 'options')
            options.text = "alert_by_email"
            return
        if sigma_guid in self.sigma_guid_email:
            if_sid = SubElement(rule, 'options')
            if_sid.text = "alert_by_email"

    def add_mitre(self, rule, tags):
        mitre = SubElement(rule, 'mitre')
        for t in tags:
            mitre_id = SubElement(mitre, 'id')
            mitre_id.text = t

    def add_sigma_author(self, rule, sigma_rule_auther):
        comment = Comment('Sigma Rule Author: ' + sigma_rule_auther)
        rule.append(comment)

    def add_sigma_link_info(self, rule, sigma_rule_link):
        link = SubElement(rule, 'info')
        link.set('type', 'link')
        link.text = (self.rules_link + sigma_rule_link)

    def add_rule_comment(self, rule, misc):
        comment = Comment(misc.replace('--', ' - ')) # '--' not allowed in XML comment
        rule.append(comment)

    def add_sigma_rule_references(self, rule, reference):
        refs = 'References: \n'
        for r in reference:
            refs += '\t' + r + '\n'
        comment = Comment(refs[:-1])
        rule.append(comment)

    def add_description(self, rule, title):
        description = SubElement(rule, 'description')
        description.text = title

    def add_sources(self, rule, sources):
        log_sources = ""
        for key, value in sources.items():
            if value and not key == 'definition':
                log_sources += value + ","
        groups = SubElement(rule, 'group')
        groups.text = log_sources

    def add_if_group(self, rule, product):
        if product in self.config['if_group']:
            if_group = SubElement(rule, 'if_group')
            if_group.text = self.config['if_group'][product]
            return

    def add_if_sid(self, rule, sigma_guid, log_source):
        target = ""
        if sigma_guid in self.config['if_sid_guid']:
            target = self.config['if_sid_guid'][sigma_guid]
        elif ('service' in log_source) and (log_source['service'] in self.config['if_sid_product']):
            target = log_source['service']
        elif log_source['product'] in self.config['if_sid_product']:
            target = log_source['product']
        if target:
            if_sid = SubElement(rule, 'if_sid')
            if_sid.text = self.config['if_sid_product'][target]
        
    def create_rule(self, sigma_rule, sigma_rule_link, sigma_guid):
        level = sigma_rule['level']
        rule = self.init_rule(level, sigma_guid)
        self.add_sigma_link_info(rule, sigma_rule_link)
        # Add rule link and author
        if 'author' in sigma_rule and sigma_rule['author'] is not None:
            self.add_sigma_author(rule, sigma_rule['author'])
        if 'description' in sigma_rule and sigma_rule['description'] is not None:
            self.add_rule_comment(rule, "Description: " + sigma_rule['description'])
        if 'date' in sigma_rule and sigma_rule['date'] is not None:
            self.add_rule_comment(rule, "Date: " + sigma_rule['date'])
        if 'status' in sigma_rule and sigma_rule['status'] is not None:
            self.add_rule_comment(rule, "Status: " + sigma_rule['status'])
        if 'id' in sigma_rule:
            self.add_rule_comment(rule, "ID: " + sigma_rule['id'])
        #if 'references' in sigma_rule:
        #    self.add_sigma_rule_references(rule, sigma_rule['references'])
        if 'tags' in sigma_rule:
            self.add_mitre(rule, sigma_rule['tags'])
        self.add_description(rule, sigma_rule['title'])
        self.add_options(rule, level, sigma_rule['id'])
        self.add_sources(rule, sigma_rule['logsource'])
        if 'product' in sigma_rule['logsource']:
            self.add_if_sid(rule, sigma_guid, sigma_rule['logsource'])
        return rule

    def write_wazah_id_to_sigman_id(self):
        with open(self.track_rule_ids_file, 'w') as ids:
            ids.write(json.dumps(self.track_rule_ids))

    def write_rules_file(self):
        xml = bs4.BeautifulSoup(tostring(self.root), 'xml').prettify()

        # collapse some tags to single lines
        xml = re.sub(r'<id>\n\s+', r'<id>', xml)
        xml = re.sub(r'\s+</id>', r'</id>', xml)

        xml = re.sub(r'<description>\n\s+', r'<description>', xml)
        xml = re.sub(r'\s+</description>', r'</description>', xml)

        xml = re.sub(r'<options>\n\s+', r'<options>', xml)
        xml = re.sub(r'\s+</options>', r'</options>', xml)

        xml = re.sub(r'<group>\n\s+', r'<group>', xml)
        xml = re.sub(r'\s+</group>', r'</group>', xml)

        xml = re.sub(r'<field(.+)>\n\s+', r'<field\1>', xml)
        xml = re.sub(r'\s+</field>', r'</field>', xml)

        xml = re.sub(r'<info(.+)>\n\s+', r'<info\1>', xml)
        xml = re.sub(r'\s+</info>', r'</info>', xml)

        xml = re.sub(r'<if_sid>\n\s+', r'<if_sid>', xml)
        xml = re.sub(r'\s+</if_sid>', r'</if_sid>', xml)

        xml = re.sub(r'<if_group>\n\s+', r'<if_group>', xml)
        xml = re.sub(r'\s+</if_group>', r'</if_group>', xml)

        # fixup some output messed up by the above
        xml = re.sub(r'</rule></group>', r'</rule>\n</group>', xml)
        xml = xml.replace('<?xml version="1.0" encoding="utf-8"?>\n', '')

        with open(self.out_file, "w") as file:
            file.write(xml)

        self.write_wazah_id_to_sigman_id()


class ParseSigmaRules(object):
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read(r'./config.ini')
        self.sigma_rules_dir = self.config.get('sigma', 'directory')
        self.sigma_rules = self.get_sigma_rules()
        self.error_count = 0
        self.converted_total = 0

    def get_sigma_rules(self):
        fname = []
        exclude = set(['deprecated'])
        for root, dirs, f_names in os.walk(self.sigma_rules_dir):
            dirs[:] = [d for d in dirs if d not in exclude]
            for f in f_names:
                fname.append(os.path.join(root, f))
        return fname

    def load_sigma_rule(self, rule_file):
        try:
            yaml = YAML(typ='safe')
            with open(rule_file) as file:
                sigma_raw_rule = file.read()
            sigma_rule = yaml.load(sigma_raw_rule)
            return sigma_rule
        except:
            self.error_count += 1
            return ""

    def fixup_condition(self, condition):
        """
            Replace spaces with _ when the words constitute a logic operation.
            Allows for easier tokenization.
        """
        if isinstance(condition, list):
            return [tok.replace('1 of them', '1_of_them')
                            .replace('all of them', 'all_of_them')
                            .replace('1 of', '1_of')
                            .replace('all of', 'all_of')\
                            .replace('(', ' ( ')\
                            .replace(')', ' ) ')
                            for tok in condition]
        return condition.replace('1 of them', '1_of_them')\
                        .replace('all of them', 'all_of_them')\
                        .replace('1 of', '1_of')\
                        .replace('all of', 'all_of')\
                        .replace('(', ' ( ')\
                        .replace(')', ' ) ')

    def remove_wazuh_rule(self, rules, rule, sid):
        wid = rule.get('id')
        if wid == str(rules.rule_id - 1):
            rules.rule_id -= 1
        if wid in rules.track_rule_ids[sid]:
            rules.track_rule_ids[sid].remove(wid)
        if wid in rules.used_wazuh_ids_this_run:
            rules.used_wazuh_ids_this_run.remove(wid)
        rules.rule_count -= 1   # decrement count of rules created
        rules.root.remove(rule) # destroy the extra rule that is created

    def fixup_logic(self, logic):
        logic = str(logic)
        if len(logic) > 2:  # when converting to Wazuh pcre2 expressions, we don't need start and end wildcards
            if logic[0] == '*': logic = logic[1:]
            if logic[-1] == '*': logic = logic[:-1]
        return re.escape(logic)

    def handle_b64offsets_list(self, value):
        offset1 = ('|'.join([str(base64.b64encode(i.encode('utf-8')), 'utf-8') for i in value])).replace('=', '')
        offset2 = ('|'.join([str(base64.b64encode((' ' + i).encode('utf-8')), 'utf-8') for i in value])).replace('=', '')[2:]
        offset3 = ('|'.join([str(base64.b64encode(('  ' + i).encode('utf-8')), 'utf-8') for i in value])).replace('=', '')[3:]
        return offset1 + "|" + offset2 + "|" + offset3

    def handle_b64offsets(self, value):
        offset1 = (str(base64.b64encode(value.encode('utf-8')), 'utf-8')).replace('=', '')
        offset2 = (str(base64.b64encode((' ' + value).encode('utf-8')), 'utf-8')).replace('=', '')[2:]
        offset3 = (str(base64.b64encode(('  ' + value).encode('utf-8')), 'utf-8')).replace('=', '')[3:]
        return offset1 + "|" + offset2 + "|" + offset3

    def handle_list(self, value, is_b64, b64_offset):
        if isinstance(value, list):
            if is_b64:
                if b64_offset:
                    return self.handle_b64offsets_list(value)
                return ('|'.join([str(base64.b64encode(i.encode('utf-8')), 'utf-8') for i in value])).replace('=', '')
            return ('|'.join([self.fixup_logic(i) for i in value]))
        if is_b64:
            if b64_offset:
                return self.handle_b64offsets(value)
            return str(base64.b64encode(value.encode('utf-8')), 'utf-8').replace('=', '')
        return self.fixup_logic(value)

    def convert_transforms(self, key, value):
        if '|' in key:
            field, transform = key.split('|', 1)
            if transform.lower() == 'contains':
                return field, self.handle_list(value, False, False), False
            if transform.lower() == 'contains|all':
                return field, value, False
            if transform.lower() == 'startswith':
                return field, '^(?:' + self.handle_list(value, False, False) + ')', False
            if transform.lower() == 'endswith':
                return field, '(?:' + self.handle_list(value, False, False) + ')$', False
            if transform.lower() == "re":
                return field, value, False
            if transform.lower() == "base64offset|contains":
                return field, self.handle_list(value, True, True), True
            if transform.lower() == "base64|contains":
                return field, self.handle_list(value, True, False), True
        return key, self.handle_list(value, False, False), False

    def handle_one_of_them(self, rules, rule, detection, sigma_rule, 
                            sigma_rule_link, product, negate):
        if isinstance(detection, dict):
            for k, v in detection.items():
                if k == "condition": continue
                if isinstance(v, dict):
                    rule = self.handle_dict(v, rules, rule, product, sigma_rule, sigma_rule_link, negate)
                    continue
                if isinstance(v, list):
                    for d in v:
                        if isinstance(d, dict):
                            rule = self.handle_dict(d, rules, rule, product, sigma_rule, sigma_rule_link, negate)
                    continue
                field, logic, is_b64 = self.convert_transforms(k, v)
                rules.add_logic(rule, product, field, negate, logic, is_b64)
            self.remove_wazuh_rule(rules, rule, sigma_rule['id'])

    def handle_keywords(self, rules, rule, sigma_rule, sigma_rule_link, product, logic, negate, is_b64):
        """
            A condition set as keywords will have a list of fields to look for those keywords in.
        """
        if 'fields' in sigma_rule:
            for f in sigma_rule['fields']:
                self.is_dict_list_or_not(logic, rules, rule, sigma_rule, sigma_rule_link, product, f, negate, is_b64)
                rule = rules.create_rule(sigma_rule, sigma_rule_link, sigma_rule['id'])
            self.remove_wazuh_rule(rules, rule, sigma_rule['id'])
            return
        rules.add_logic(rule, product, "full_log", negate, logic, is_b64)

    def handle_dict(self, d, rules, rule, product, sigma_rule, sigma_rule_link, negate):
        for k, v in d.items():
            field, logic, is_b64 = self.convert_transforms(k, v)
            self.is_dict_list_or_not(logic, rules, rule, sigma_rule, sigma_rule_link, product, field, negate, is_b64)
        return rules.create_rule(sigma_rule, sigma_rule_link, sigma_rule['id'])

    def is_dict_list_or_not(self, logic, rules, rule, sigma_rule, sigma_rule_link, product, field, negate, is_b64):
        if isinstance(logic, list): # if logic is still a list then its contain|all logic
            for l in logic:
                #if isinstance(l, dict):
                #    rule = self.handle_dict(l, rules, rule, product, sigma_rule, sigma_rule_link, negate)
                #    continue
                rules.add_logic(rule, product, field, negate, self.fixup_logic(l), is_b64)
            return
        rules.add_logic(rule, product, field, negate, logic, is_b64)

    def list_add_unique(self, record, values, key):
        for d in values:
            for k, v in d.items():
                if k == key:
                    v = [v]
                    if isinstance(record[key], list):
                        for i in record[key]:
                            if i not in v:
                                v.append(i)
                    if record[key] not in v:
                        v.append(record[key])
                    return values
        values.append(record)
        return values

    def handle_detection_nested_lists(self, values, record, key, value):
        """
            We can run into lists at various depths in Sigma deteciton logic.
        """
        if not key.endswith('|all'):
            if isinstance(record[key], list):
                    values = self.list_add_unique(record, values, key)
            else:
                if isinstance(value, list):
                    values = self.list_add_unique(record, values, key)
                else:
                    values = self.list_add_unique(record, values, key)
        else:
            values.append(record)
        return values

    def get_detection(self, detection, token):
        """
            Break appart detection logic into dictionaries for use in creating the Wazuh logic.
            e.g. {"fieldname|<startswith|endswith|etc.>": ["something to look for", "another thing to look for"]}
        """
        record = {}
        values = []
        if isinstance(detection, list):
            for d in detection:
                if isinstance(d, dict):
                    for k, v in d.items():
                        record[k] = v
                        values = self.handle_detection_nested_lists(values, d, k, v)
                else:
                    record[token] = detection
                    values.append(record)
                record = {}
            return values
        for k, v in detection.items():
            record[k] = v
        values.append(record)
        return values

    def get_product(self, sigma_rule):
        if 'logsource' in sigma_rule and 'product' in sigma_rule['logsource']:
            return sigma_rule['logsource']['product'].lower()
        return ""

    def handle_fields(self, rules, rule, token, negate, sigma_rule, 
                        sigma_rule_link, detection, product, all_logic, all_of):
        detections = []
        detections = self.get_detection(detection, token)

        for d in detections:
            for k, v in d.items():
                if all_of:
                    k = k + "|contains|all"
                    field, logic, is_b64 = self.convert_transforms(k, v)
                else:
                    field, logic, is_b64 = self.convert_transforms(k, v)
                name = rules.convert_field_name(product, field) # lets get what the field name will be in the Wazuh XML rules file
                                                                # as we need to handle the full_log field
                if name not in all_logic:
                    all_logic[name] = []
                if logic not in all_logic[name]: # do not add duplicate logic to a rule, even if its negated
                    all_logic[name].append(logic)
                    if k == 'keywords':
                        self.handle_keywords(rules, rule, sigma_rule, sigma_rule_link, product, logic, negate, is_b64)
                        continue
                    self.is_dict_list_or_not(logic, rules, rule, sigma_rule, sigma_rule_link, product, field, negate, is_b64)
        return all_logic

    def handle_logic_paths(self, rules, sigma_rule, sigma_rule_link, logic_paths):
        product = self.get_product(sigma_rule)
        all_of = False
        for path in logic_paths:
            all_logic = {}  # track all the logic used in a single rule to ensure we don't duplicat it
                            # e.g. https://github.com/SigmaHQ/sigma/tree/master/rules/network/zeek/zeek_smb_converted_win_susp_psexec.yml
            negate = "no"
            rule = rules.create_rule(sigma_rule, sigma_rule_link, sigma_rule['id'])
            for p in path:
                if p == "not":
                    negate = "yes"
                    continue
                elif p == "all_of":
                    all_of = True
                    continue
                elif p == "1_of_them":
                    self.handle_one_of_them(rules, rule, sigma_rule['detection'], 
                                    sigma_rule, sigma_rule_link, product, negate)
                    continue
                all_logic = self.handle_fields(rules, rule, p, negate, 
                                                sigma_rule, sigma_rule_link, 
                                                sigma_rule['detection'][p], 
                                                product, all_logic, all_of)
                all_of = False
                negate = "no"

    def handle_all_of(self, detections, token):
        path = []
        if token.endswith('*'):
            for d in detections:
                if d.startswith(token.replace('*','')):
                    path.append(d)
        else:
            # all_of applied to just one detection is handled by adding all as Wazuh AND logic
            path.append('all_of')
            path.append(token)
        return path

    def build_logic_paths(self, rules, tokens, sigma_rule, sigma_rule_link):
        logic_paths = []    # we can have multiple paths for evaluating the sigma rule as Wazuh AND logic
        path = []           # minimum logic for one AND path
        negate = False      # are we to negate the logic?
        neg_paren = 0       # track depth to which a not should be carried to
        level = 0           # track paren netsting levels
        paren_set = 0       # track number of paren sets
        is_or = False       # did we bump into an OR
        is_and = False      # did we bump into an and
        all_of = False      # handle "all of" directive
        tokens = list(filter(None, tokens)) # remove all Null entries
        for t in tokens:
            if t.lower() == 'not':
                if negate:
                    negate = False
                else:
                    negate = True
                continue
            if t == '(':
                if negate:
                    neg_paren += 1
                level += 1
                continue
            if t == ')':
                level -= 1
                if neg_paren > 0:
                    neg_paren -= 1
                paren_set += 1
                continue
            if t.lower() == 'or':
                is_or = True
                continue
            if t.lower() == 'and':
                if level == 0:
                    negate = False
                is_or = False
                is_and = True
                continue
            if all_of:
                # figure out to handle all of and field does not have '|' directive
                path = self.handle_all_of(sigma_rule['detection'], t)
                all_of = False
                continue
            if is_or and not negate:
                logic_paths.append(path)
                if paren_set > 0 or level == 0 or not is_and:
                    path = []
                elif (len(path) > 1) and (path[-1] not in 'not'):
                    path = path[:-1]
            if negate:
                if path and path[-1] != 'not':
                    path.append('not')
                elif not path:
                    path.append('not')
                if neg_paren == 0:
                    negate = False
            if t.lower() == 'all_of':
                all_of = True
                continue
            path.append(t)
        logic_paths.append(path)
        #print(sigma_rule['id'])
        #print(logic_paths)
        self.handle_logic_paths(rules, sigma_rule, sigma_rule_link, logic_paths)


class TrackSkip(object):
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read(r'./config.ini')
        self.process_experimental_rules = self.config.get('sigma', 'process_experimental')
        self.sigma_skip_ids = eval(self.config.get('sigma', 'skip_sigma_guids'), {}, {})
        self.sigma_convert_all = self.config.get('sigma', 'convert_all')
        self.sigma_only_products = eval(self.config.get('sigma', 'convert_only_products'), {}, {})
        self.sigma_only_categories = eval(self.config.get('sigma', 'convert_only_categories'), {}, {})
        self.sigma_only_services = eval(self.config.get('sigma', 'convert_only_services'), {}, {})
        self.sigma_skip_products = eval(self.config.get('sigma', 'skip_products'), {}, {})
        self.sigma_skip_categories = eval(self.config.get('sigma', 'skip_categories'), {}, {})
        self.sigma_skip_services = eval(self.config.get('sigma', 'skip_services'), {}, {})
        self.near_skips = 0
        self.paren_skips = 0
        self.timeframe_skips = 0
        self.experimental_skips = 0
        self.hard_skipped = 0
        self.rules_skipped = 0
        self.one_of_skipped = 0

    def rule_not_loaded(self, rule, sigma_rule):
        if not sigma_rule:
            self.rules_skipped += 1
            print("ERROR loading Sigma rule: " + rule)
            return True
        return False

    def skip_experimental_rules(self, sigma_rule):
        if self.process_experimental_rules == "no":
            if 'status' in sigma_rule:
                if sigma_rule['status'] == "experimental":
                    self.rules_skipped += 1
                    self.experimental_skips += 1
                    return True
        return False

    def inc_skip_counters(self):
        self.rules_skipped += 1
        self.hard_skipped += 1

    def skip_rule(self, sigma_rule):
        skip = False
        if sigma_rule["id"] in self.sigma_skip_ids: # skip specific Sigma rule GUIDs
            skip = True
        if 'category' in sigma_rule['logsource']:
            if sigma_rule['logsource']['category'].lower() in self.sigma_skip_categories:
                skip = True
        if 'service' in sigma_rule['logsource']:
            if sigma_rule['logsource']['service'].lower() in self.sigma_skip_services:
                skip = True
        if 'product' in sigma_rule['logsource']:
            if sigma_rule['logsource']['product'].lower() in self.sigma_skip_products:
                skip = True
        if skip:
            self.inc_skip_counters()
            return True

        if self.sigma_convert_all.lower() == 'yes': # convert all rules except explicit GUID skips
            return False

        skip = True
        if 'category' in sigma_rule['logsource']:
            if sigma_rule['logsource']['category'].lower() in self.sigma_only_categories:
                skip = False
        if 'service' in sigma_rule['logsource']:
            if sigma_rule['logsource']['service'].lower() in self.sigma_only_services:
                skip = False
        if 'product' in sigma_rule['logsource']:
            if sigma_rule['logsource']['product'].lower() in self.sigma_only_products:
                skip = False
        if skip:
            self.inc_skip_counters()
        return skip

    def skip_logic(self, condition, detection):
        skip = False
        logic = []
        message = "SKIPPED Sigma rule:"
        if '|' in condition:
            skip = True
            self.near_skips += 1
            logic.append('Near')
        if (condition.count('(') > 1 and ' or ' in condition) or (not ') or (' in condition and condition.count('(') == 2 ):
            skip = True
            self.paren_skips += 1
            logic.append('Paren')
        if 'timeframe' in detection:
            skip = True
            self.timeframe_skips += 1
            logic.append('Timeframe')
        if '1_of ' in condition:
            skip = True
            self.one_of_skipped += 1
            logic.append('1_of')
        return skip, "{} {}".format(message, logic)

    def check_for_skip(self, rule, sigma_rule, detection, condition):
        """
            All logic conditions are not parsed yet.
            This procedure will skip Sigma rules we are not ready to parse.
        """
        if self.skip_experimental_rules(sigma_rule):
            print("SKIPPED Sigma rule: " + rule)
            return True
        if self.skip_rule(sigma_rule):
            print("HARD SKIPPED Sigma rule: " + rule)
            return True
        
        skip, message = self.skip_logic(condition, detection)
        if skip:
            self.rules_skipped += 1
            print(message + ": " + rule)
            
        return skip

    def report_stats(self, error_count, wazuh_rules_count, sigma_rules_count):
        sigma_rules_converted = sigma_rules_count - self.rules_skipped
        sigma_rules_converted_percent = round((( sigma_rules_converted / sigma_rules_count) * 100), 2)
        print("\n\n" + "*" * 75)
        print(" Number of Sigma Experimental rules skipped: %s" % self.experimental_skips)
        print("    Number of Sigma TIMEFRAME rules skipped: %s" % self.timeframe_skips)
        print("        Number of Sigma PAREN rules skipped: %s" % self.paren_skips)
        print("         Number of Sigma NEAR rules skipped: %s" % self.near_skips)
        print("         Number of Sigma 1_OF rules skipped: %s" % self.one_of_skipped)
        print("       Number of Sigma CONFIG rules skipped: %s" % self.hard_skipped)
        print("        Number of Sigma ERROR rules skipped: %s" % error_count)
        print("-" * 55)
        print("                  Total Sigma rules skipped: %s" % self.rules_skipped)
        print("                Total Sigma rules converted: %s" % sigma_rules_converted)
        print("-" * 55)
        print("                  Total Wazuh rules created: %s" % wazuh_rules_count)
        print("-" * 55)
        print("                          Total Sigma rules: %s" % sigma_rules_count)
        print("                    Sigma rules converted %%: %s" % sigma_rules_converted_percent)
        print("*" * 75 + "\n\n")


def main():
    convert = ParseSigmaRules()
    wazuh_rules = BuildRules()
    stats = TrackSkip()

    for rule in convert.sigma_rules:
        sigma_rule = convert.load_sigma_rule(rule)
        if stats.rule_not_loaded(rule, sigma_rule):
            continue

        conditions = convert.fixup_condition(sigma_rule['detection']['condition'])
        #print(conditions)

        skip_rule = stats.check_for_skip(rule, sigma_rule, sigma_rule['detection'], conditions)
        if skip_rule:
            continue
        #print(rule)

        # build the URL to the sigma rule, handle relative paths
        partial_url_path = rule.replace('/sigma/rules', '').replace('../', '/').replace('./', '/').replace('\\','/').replace('..','')

        if isinstance(conditions, list):
            for condition in conditions: # create new rule for each condition, needs work
                tokens = condition.strip().split(' ')
                convert.build_logic_paths(wazuh_rules, tokens, sigma_rule, partial_url_path)
            continue
        tokens = conditions.strip().split(' ')
        convert.build_logic_paths(wazuh_rules, tokens, sigma_rule, partial_url_path)

    # write out all Wazuh rules created
    wazuh_rules.write_rules_file()

    stats.report_stats(convert.error_count, wazuh_rules.rule_count, len(convert.sigma_rules))


if __name__ == "__main__":
    main()