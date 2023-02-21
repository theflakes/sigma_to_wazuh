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
import argparse
import collections
import os
import configparser
import bs4, re
import json
import base64
from xml.etree.ElementTree import Element, SubElement, Comment, tostring
from ruamel.yaml import YAML

debug = False

class Notify(object):
    def __init__(self):
        pass

    def info(self, message):
        print("[#] %s" % message)

    def error(self, message):
        print("[!] %s" % message)
        
    def debug(self, message):
        if debug:
            print("[*] %s" % repr(message)[1:-1])


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
        self.track_rule_ids_file = self.config.get('options','rule_id_file')  # file that stores Sigma GUID to Wazuh rule ID mappings
        self.track_rule_ids = self.load_wazuh_to_sigma_id_mappings()  # in memory Dict of self.track_rule_ids_file contents
        self.used_wazuh_ids = self.get_used_wazuh_rule_ids()  # used Wazuh rule IDs used in previous runs
        self.used_wazuh_ids_this_run = []  # new Wazuh rule IDs consummed this run
        self.root = self.create_root()
        self.rule_count = 0
        # monkey patching prettify
        # reference: https://stackoverflow.com/questions/15509397/custom-indent-width-for-beautifulsoup-prettify
        orig_prettify = bs4.BeautifulSoup.prettify
        r = re.compile(r'^(\s*)', re.MULTILINE)

        def prettify(self, encoding=None, formatter="minimal", indent_width=4):
            Notify.debug(self, "Function: {}".format(self.prettify.__name__))
            return r.sub(r'\1' * indent_width, orig_prettify(self, encoding, formatter))

        bs4.BeautifulSoup.prettify = prettify

    def load_wazuh_to_sigma_id_mappings(self):
        """
            Need to track Wazuh rule ID between runs so that any rules dependent
            on these auto generated rules will not be broken by subsequent runs.
        """
        Notify.debug(self, "Function: {}".format(self.load_wazuh_to_sigma_id_mappings.__name__))
        try:
            with open(self.track_rule_ids_file, 'r') as ids:
                return json.load(ids)
        except:
            Notify.error(self, "ERROR loading rule id tracking file: %s" % self.track_rule_ids_file)
            return {}

    def get_used_wazuh_rule_ids(self):
        Notify.debug(self, "Function: {}".format(self.get_used_wazuh_rule_ids.__name__))
        # ids = [str(self.rule_id_start)] # never use the first number
        ids = []
        for k, v in self.track_rule_ids.items():
            for i in v:
                if i not in ids:
                    ids.append(i)
        return ids

    def create_root(self):
        Notify.debug(self, "Function: {}".format(self.create_root.__name__))
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
        Notify.debug(self, "Function: {}".format(self.update_rule_id_mappings.__name__))
        if sigma_guid in self.track_rule_ids:
            if wid not in self.track_rule_ids[sigma_guid]:
                self.track_rule_ids[sigma_guid].append(wid)
        else:
            self.track_rule_ids[sigma_guid] = [wid]

    def find_unused_rule_id(self, sigma_guid):
        """
            Lets make sure we use a Wazuh rule ID not already assigned to a Sigma GUID
        """
        Notify.debug(self, "Function: {}".format(self.find_unused_rule_id.__name__))
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
        Notify.debug(self, "Function: {}".format(self.find_wazuh_id.__name__))
        if sigma_guid in self.track_rule_ids:
            for wid in self.track_rule_ids[sigma_guid]:
                if wid not in self.used_wazuh_ids_this_run:
                    return wid
        wid = self.find_unused_rule_id(sigma_guid)
        return wid

    def init_rule(self, level, sigma_guid):
        Notify.debug(self, "Function: {}".format(self.init_rule.__name__))
        rule = SubElement(self.root, 'rule')
        wid = self.find_wazuh_id(sigma_guid)
        self.used_wazuh_ids_this_run.append(wid)
        rule.set('id', wid)
        rule.set('level', self.get_level(level))
        self.rule_count += 1
        return rule

    def convert_field_name(self, product, field):
        Notify.debug(self, "Function: {}".format(self.convert_field_name.__name__))
        if product in self.config.sections():
            if field in self.config[product]:
                return self.config[product][field]
        return "full_log"  # target full log if we cannot find the field

    def if_ends_in_space(self, value, is_b64):
        """
            spaces at end of logic are being chopped, therefore hacking this fix
        """
        Notify.debug(self, "Function: {}".format(self.if_ends_in_space.__name__))
        if value.startswith('(?i)'):  # if value start with this, it is a Sigma regex, remove it as it will be added again
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
        Notify.debug(self, "Function: {}".format(self.handle_full_log_field.__name__))
        if value.startswith('^'):
            value = value[1:]
        if value.endswith('$') and not value[-2:] == '\$':
            value = value[:-1]
        return value

    def add_logic(self, rule, product, field, negate, value, is_b64):
        Notify.debug(self, "Function: {}".format(self.add_logic.__name__))
        logic = SubElement(rule, 'field')
        name = self.convert_field_name(product, field)
        logic.set('name', name)
        logic.set('negate', negate)
        logic.set('type', 'pcre2')
        value = str(value).replace(r'\?', r'.').replace(r'\\', r'\\+') # This does replace escaped '*'s, FIX UP NEEDED
        value = re.sub(r'(?:\\\\\+){2,}', r'\\\\+', value) # cleanup multiple '\\+' back to back
        if name == 'full_log':
            logic.text = self.if_ends_in_space(self.handle_full_log_field(value), is_b64).replace(r'\*', r'.+') # assumption is all '*' are wildcards
        else:
            logic.text = self.if_ends_in_space(value, is_b64).replace(r'\*', r'.+') # assumption is all '*' are wildcards

    def get_level(self, level):
        Notify.debug(self, "Function: {}".format(self.get_level.__name__))
        if level == "critical":
            return self.critical
        if level == "high":
            return self.high
        if level == "medium":
            return self.medium
        return self.low

    def add_options(self, rule, level, sigma_guid):
        Notify.debug(self, "Function: {}".format(self.add_options.__name__))
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
        Notify.debug(self, "Function: {}".format(self.add_mitre.__name__))
        mitre = SubElement(rule, 'mitre')
        for t in tags:
            mitre_id = SubElement(mitre, 'id')
            mitre_id.text = t

    def add_sigma_author(self, rule, sigma_rule_auther):
        Notify.debug(self, "Function: {}".format(self.add_sigma_author.__name__))
        comment = Comment('Sigma Rule Author: ' + sigma_rule_auther)
        rule.append(comment)

    def add_sigma_link_info(self, rule, sigma_rule_link):
        Notify.debug(self, "Function: {}".format(self.add_sigma_link_info.__name__))
        link = SubElement(rule, 'info')
        link.set('type', 'link')
        link.text = (self.rules_link + sigma_rule_link)

    def add_rule_comment(self, rule, misc):
        Notify.debug(self, "Function: {}".format(self.add_rule_comment.__name__))
        comment = Comment(misc.replace('--', ' - '))  # '--' not allowed in XML comment
        rule.append(comment)

    def add_sigma_rule_references(self, rule, reference):
        Notify.debug(self, "Function: {}".format(self.add_sigma_rule_references.__name__))
        refs = 'References: \n'
        for r in reference:
            refs += '\t' + r + '\n'
        comment = Comment(refs[:-1])
        rule.append(comment)

    def add_description(self, rule, title):
        Notify.debug(self, "Function: {}".format(self.add_description.__name__))
        description = SubElement(rule, 'description')
        description.text = title

    def add_sources(self, rule, sources):
        Notify.debug(self, "Function: {}".format(self.add_sources.__name__))
        log_sources = ""
        for key, value in sources.items():
            if value and not key == 'definition':
                log_sources += value + ","
        groups = SubElement(rule, 'group')
        groups.text = log_sources

    def add_if_group_guid(self, rule, sigma_guid):
        Notify.debug(self, "Function: {}".format(self.add_if_group_guid.__name__))
        if sigma_guid in self.config['if_group_guid']:
            if_sid = SubElement(rule, 'if_group')
            if_sid.text = self.config['if_group_guid'][sigma_guid]
            return True
        return False

    def add_if_sid_guid(self, rule, sigma_guid):
        Notify.debug(self, "Function: {}".format(self.add_if_group.__name__))
        if sigma_guid in self.config['if_sid_guid']:
            if_sid = SubElement(rule, 'if_sid')
            if_sid.text = self.config['if_sid_guid'][sigma_guid]
            return True
        return False

    def add_if_group(self, rule, log_source):
        Notify.debug(self, "Function: {}".format(self.add_if_group.__name__))
        target = ""
        if ('service' in log_source) and (log_source['service'] in self.config['if_group']):
            target = log_source['service']
        elif ('product' in log_source) and (log_source['product'] in self.config['if_group']):
            target = log_source['product']
        if target:
            if_group = SubElement(rule, 'if_group')
            if_group.text = self.config['if_group'][target]
            return True
        return False
        
    def add_if_sid(self, rule, log_source):
        Notify.debug(self, "Function: {}".format(self.add_if_sid.__name__))
        target = ""
        if ('service' in log_source) and (log_source['service'] in self.config['if_sid']):
            target = log_source['service']
        elif log_source['product'] in self.config['if_sid']:
            target = log_source['product']
        if target:
            if_sid = SubElement(rule, 'if_sid')
            if_sid.text = self.config['if_sid'][target]

    def create_rule(self, sigma_rule, sigma_rule_link, sigma_guid):
        Notify.debug(self, "Function: {}".format(self.create_rule.__name__))
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
        # if 'references' in sigma_rule:
        #    self.add_sigma_rule_references(rule, sigma_rule['references'])
        if 'tags' in sigma_rule:
            self.add_mitre(rule, sigma_rule['tags'])
        self.add_description(rule, sigma_rule['title'])
        self.add_options(rule, level, sigma_rule['id'])
        self.add_sources(rule, sigma_rule['logsource'])
        if_group_guid = self.add_if_group_guid(rule, sigma_guid)
        if not if_group_guid:
            if_sid_guid = self.add_if_sid_guid(rule, sigma_guid)
            if not if_sid_guid and 'product' in sigma_rule['logsource']:
                if_group = self.add_if_group(rule, sigma_rule['logsource'])
                if not if_group:
                    self.add_if_sid(rule, sigma_rule['logsource'])
        return rule

    def write_wazah_id_to_sigman_id(self):
        Notify.debug(self, "Function: {}".format(self.write_wazah_id_to_sigman_id.__name__))
        with open(self.track_rule_ids_file, 'w') as ids:
            ids.write(json.dumps(self.track_rule_ids))
                

    def write_rules_file(self):
        Notify.debug(self, "Function: {}".format(self.write_rules_file.__name__))
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

        with open(self.out_file, "w", encoding="utf-8") as file:
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
        Notify.debug(self, "Function: {}".format(self.get_sigma_rules.__name__))
        fname = []
        exclude = set(['deprecated'])
        for root, dirs, f_names in os.walk(self.sigma_rules_dir):
            dirs[:] = [d for d in dirs if d not in exclude]
            for f in f_names:
                fname.append(os.path.join(root, f))
        return fname

    def load_sigma_rule(self, rule_file):
        Notify.debug(self, "Function: {}".format(self.load_sigma_rule.__name__))
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
        Notify.debug(self, "Function: {}".format(self.fixup_condition.__name__))
        if isinstance(condition, list):
            return [tok.replace('1 of them', '1_of')
                        .replace('all of them', 'all_of')
                        .replace('1 of', '1_of')
                        .replace('all of', 'all_of') \
                        .replace('(', ' ( ') \
                        .replace(')', ' ) ')
                    for tok in condition]
        return condition.replace('1 of them', '1_of') \
            .replace('all of them', 'all_of') \
            .replace('1 of', '1_of') \
            .replace('all of', 'all_of') \
            .replace('(', ' ( ') \
            .replace(')', ' ) ')

    def remove_wazuh_rule(self, rules, rule, sid):
        Notify.debug(self, "Function: {}".format(self.remove_wazuh_rule.__name__))
        wid = rule.get('id')
        if wid == str(rules.rule_id - 1):
            rules.rule_id -= 1
        if wid in rules.track_rule_ids[sid]:
            rules.track_rule_ids[sid].remove(wid)
        if wid in rules.used_wazuh_ids_this_run:
            rules.used_wazuh_ids_this_run.remove(wid)
        rules.rule_count -= 1  # decrement count of rules created
        rules.root.remove(rule)  # destroy the extra rule that is created

    def fixup_logic(self, logic, is_regex):
        Notify.debug(self, "Function: {}".format(self.fixup_logic.__name__))
        logic = str(logic)
        if len(logic) > 2:  # when converting to Wazuh pcre2 expressions, we don't need start and end wildcards
            if logic[0] == '*': logic = logic[1:]
            if logic[-1] == '*': logic = logic[:-1]
        if is_regex:
            return logic
        else:
            return re.escape(logic)

    def handle_b64offsets_list(self, value):
        Notify.debug(self, "Function: {}".format(self.handle_b64offsets_list.__name__))
        offset1 = ('|'.join([str(base64.b64encode(i.encode('utf-8')), 'utf-8') for i in value])).replace('=', '')
        offset2 = ('|'.join([str(base64.b64encode((' ' + i).encode('utf-8')), 'utf-8') for i in value])).replace('=','')[2:]
        offset3 = ('|'.join([str(base64.b64encode(('  ' + i).encode('utf-8')), 'utf-8') for i in value])).replace('=','')[3:]
        return offset1 + "|" + offset2 + "|" + offset3

    def handle_b64offsets(self, value):
        Notify.debug(self, "Function: {}".format(self.handle_b64offsets.__name__))
        offset1 = (str(base64.b64encode(value.encode('utf-8')), 'utf-8')).replace('=', '')
        offset2 = (str(base64.b64encode((' ' + value).encode('utf-8')), 'utf-8')).replace('=', '')[2:]
        offset3 = (str(base64.b64encode(('  ' + value).encode('utf-8')), 'utf-8')).replace('=', '')[3:]
        return offset1 + "|" + offset2 + "|" + offset3

    def handle_list(self, value, is_b64, b64_offset, is_regex):
        Notify.debug(self, "Function: {}".format(self.handle_list.__name__))
        if isinstance(value, list):
            if is_b64:
                if b64_offset:
                    return self.handle_b64offsets_list(value)
                return ('|'.join([str(base64.b64encode(i.encode('utf-8')), 'utf-8') for i in value])).replace('=', '')
            return ('|'.join([self.fixup_logic(i, is_regex) for i in value]))
        if is_b64:
            if b64_offset:
                return self.handle_b64offsets(value)
            return str(base64.b64encode(value.encode('utf-8')), 'utf-8').replace('=', '')
        return self.fixup_logic(value, is_regex)

    # def handle_one_of_them(self, rules, rule, detection, sigma_rule,
    #                        sigma_rule_link, product, negate):
    #     if isinstance(detection, dict):
    #         for k, v in detection.items():
    #             if k == "condition":
    #                 continue
    #             if isinstance(v, dict):
    #                 rule = self.handle_dict(v, rules, rule, product, sigma_rule, sigma_rule_link, negate)
    #                 continue
    #             if isinstance(v, list):
    #                 for d in v:
    #                     if isinstance(d, dict):
    #                         rule = self.handle_dict(d, rules, rule, product, sigma_rule, sigma_rule_link, negate)
    #                 continue
    #             field, logic, is_b64 = self.convert_transforms(k, v, negate)
    #             rules.add_logic(rule, product, field, negate, logic, is_b64)
    #         self.remove_wazuh_rule(rules, rule, sigma_rule['id'])

    def handle_keywords(self, rules, rule, sigma_rule, sigma_rule_link, product, logic, negate, is_b64):
        Notify.debug(self, "Function: {}".format(self.handle_keywords.__name__))
        rules.add_logic(rule, product, "full_log", negate, logic, is_b64)

    def handle_dict(self, d, rules, rule, product, sigma_rule, sigma_rule_link, negate):
        Notify.debug(self, "Function: {}".format(self.handle_dict.__name__))
        for k, v in d.items():
            field, logic, is_b64 = self.convert_transforms(k, v, negate)
            self.is_dict_list_or_not(logic, rules, rule, sigma_rule, sigma_rule_link, product, field, negate, is_b64)
        return rules.create_rule(sigma_rule, sigma_rule_link, sigma_rule['id'])

    def is_dict_list_or_not(self, logic, rules, rule, sigma_rule, sigma_rule_link, product, field, negate, is_b64):
        Notify.debug(self, "Function: {}".format(self.is_dict_list_or_not.__name__))
        if isinstance(logic, list):
            for l in logic:
                rules.add_logic(rule, product, field, negate, l, is_b64)
            return
        rules.add_logic(rule, product, field, negate, logic, is_b64)

    def list_add_unique(self, record, values, key):
        Notify.debug(self, "Function: {}".format(self.list_add_unique.__name__))
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
        Notify.debug(self, "Function: {}".format(self.handle_detection_nested_lists.__name__))
        values = []
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
        Notify.debug(self, "Detection values: {}".format(values))
        return values

    def get_detection(self, detection, token):
        """
            Break apart detection logic into dictionaries for use in creating the Wazuh logic.
            e.g. {"fieldname|<startswith|endswith|etc.>": ["something to look for", "another thing to look for"]}
        """
        Notify.debug(self, "Function: {}".format(self.get_detection.__name__))
        record = {}
        values = []
        Notify.debug(self, "Detection: {}".format(detection))
        if isinstance(detection, list):
            for d in detection:
                if isinstance(d, dict):
                    for k, v in d.items():
                        values.extend(self.handle_detection_nested_lists(values, d, k, v))
                else:
                    record[token] = detection
                    values.append(record)
                    break
            return values
        for k, v in detection.items():
            record[k] = v
            Notify.debug(self, "Detection Record: {}".format(record))
        values.append(record)
        Notify.debug(self, "Discovered Detections: {}".format(values))
        return values

    def get_product(self, sigma_rule):
        Notify.debug(self, "Function: {}".format(self.get_product.__name__))
        if 'logsource' in sigma_rule and 'product' in sigma_rule['logsource']:
            return sigma_rule['logsource']['product'].lower()
        return ""

    def handle_or_to_and(self, value, negate, contains_all, start, end, is_regex):
        Notify.debug(self, "Function: {}".format(self.handle_or_to_and.__name__))
        """
            We have to split up contains_all and any negated fields into individual field statements in Wazuh rules
        """
        if (negate == "yes" or contains_all) and isinstance(value, list):
            result = []
            for v in value:
                v = self.fixup_logic(v, is_regex)
                result.append(start + v + end)
            return result
        else:
            return start + self.handle_list(value, False, False, is_regex) + end

    def convert_transforms(self, key, value, negate):
        Notify.debug(self, "Function: {}".format(self.convert_transforms.__name__))
        if '|' in key:
            field, transform = key.split('|', 1)
            if transform.lower() == 'contains':
                return field, self.handle_or_to_and(value, negate, False, '', '', False), False
            if transform.lower() == 'contains|all':
                return field, self.handle_or_to_and(value, negate, True, '', '', False), False
            if transform.lower() == 'startswith':
                return field, self.handle_or_to_and(value, negate, False, '^(?:', ')', False), False
            if transform.lower() == 'endswith':
                return field, self.handle_or_to_and(value, negate, False, '(?:', ')$', False), False
            if transform.lower() == "re":
                return field, self.handle_or_to_and(value, negate, False, '', '', True), False
            if transform.lower() == "base64offset|contains":
                return field, self.handle_or_to_and(value, negate, False, '', '', False), True
            if transform.lower() == "base64|contains":
                return field, self.handle_or_to_and(value, negate, False, '', '', False), True
        return key, self.handle_or_to_and(value, negate, False, '', '', False), False

    def handle_fields(self, rules, rule, token, negate, sigma_rule,
                      sigma_rule_link, detections, product):
        Notify.debug(self, "Function: {}".format(self.handle_fields.__name__))
        detection = self.get_detection(detections, token)
        Notify.debug(self, "Detections: {}".format(detections))
        Notify.debug(self, "Detection: {}".format(detection))
        for d in detection:
            Notify.debug(self, "Detection: {}".format(d))
            for k, v in d.items():
                # if all_of:
                #     k = k + "|contains|all"
                #     field, logic, is_b64 = self.convert_transforms(k, v, negate)
                # else:
                field, logic, is_b64 = self.convert_transforms(k, v, negate)
                Notify.debug(self, "Logic: {}".format(logic))
                if k == 'keywords':
                    self.handle_keywords(rules, rule, sigma_rule, sigma_rule_link, product, logic, negate, is_b64)
                    continue
                self.is_dict_list_or_not(logic, rules, rule, sigma_rule, sigma_rule_link, product, field, negate, is_b64)

    def handle_logic_paths(self, rules, sigma_rule, sigma_rule_link, logic_paths):
        Notify.debug(self, "Function: {}".format(self.handle_logic_paths.__name__))
        product = self.get_product(sigma_rule)
        logic_paths = list(filter(None, logic_paths))
        for path in logic_paths:
            negate = "no"
            all_of = False
            rule = rules.create_rule(sigma_rule, sigma_rule_link, sigma_rule['id'])
            Notify.debug(self, "Logic Path: {}".format(path))
            path = list(filter(None, path))
            for p in path:
                if isinstance(p, collections.abc.Sequence) and not isinstance(p, str): # kludge to fix token that is an array
                    p = p[0]
                Notify.debug(self, "Token - {} : {}".format(type(p), p))
                Notify.debug(self, "Detection Type: {}".format(type(sigma_rule['detection'])))
                if p == "not":
                    negate = "yes"
                    continue
                # elif p == "all_of":
                #     all_of = True
                #     continue
                #elif p == "1_of":
                #    self.handle_one_of_them(rules, rule, sigma_rule['detection'],
                #                            sigma_rule, sigma_rule_link, product, negate)
                #    continue
                self.handle_fields(rules, rule, p, negate,
                                    sigma_rule, sigma_rule_link,
                                    sigma_rule['detection'][p],
                                    product)
                negate = "no"

    def handle_all_of(self, detections, token):
        Notify.debug(self, "Function: {}".format(self.handle_all_of.__name__))
        path = []
        Notify.debug(self, "All of token: {}".format(token))
        if token.endswith('*'):
            for d in detections:
                if d.startswith(token.replace('*', '')):
                    path.extend([d])
        else:
            path.extend([token])
        Notify.debug(self, "All of: {}".format(path))
        return path

    def handle_one_of(self, detections, token, path, negate):
        Notify.debug(self, "Function: {}".format(self.handle_one_of.__name__))
        paths = []
        path_start = path.copy()
        for d in detections:
            if d.startswith(token.replace('*', '')):
                if negate:
                    path_start.extend(["not"])
                path_start.extend([d])
                Notify.debug(self, "One of path: {}".format(path_start))
                if not negate:
                    paths.append(path_start)
                    path_start = path.copy()
                Notify.debug(self, "One of paths: {}".format(paths))
        if negate:
            paths.extend([path_start])
        Notify.debug(self, "One of results: {}".format(paths))
        return paths

    def build_logic_paths(self, rules, tokens, sigma_rule, sigma_rule_link):
        Notify.debug(self, "Function: {}".format(self.build_logic_paths.__name__))
        logic_paths = []        # we can have multiple paths for evaluating the sigma rule as Wazuh AND logic
        path = []               # minimum logic for one AND path
        negate = {'n': False, 'd': 0}
        level = 0               # track paren nesting levels
        is_or = False           # did we bump into an OR
        is_and = False          # did we bump into an and
        all_of = False          # handle "all of" directive
        one_of = False          # handle "1 of" directive
        ignore = False          # if exiting the token loop and "all_of" or "one_of" was the last processed don't add token to logic_paths
        tokens = list(filter(None, tokens))  # remove all Null entries
        Notify.debug(self, "*" * 80)
        Notify.debug(self, "Rule ID: " + sigma_rule['id'])
        Notify.debug(self, "Rule Link: " + sigma_rule_link)
        Notify.debug(self, "Tokens: {}".format(tokens))
        for t in tokens:
            if t.lower() == 'not':
                if negate['n']:
                    negate['n'] = False
                else:
                    negate['n'] = True
                    negate['d'] = level
                continue
            if t == '(':
                level += 1
                continue
            if t == ')':
                if negate['d'] == level:
                    negate['n'] = False
                    negate['d'] = 0
                level -= 1
                continue
            if t.lower() == 'or':
                is_or = True
                continue
            if t.lower() == 'and':
                if level == 0:
                    negate['n'] = False
                is_or = False
                is_and = True
                continue
            if all_of:
                path.extend(self.handle_all_of(sigma_rule['detection'], t))
                ignore = True
                all_of = False
                continue
            if one_of:
                # one_of logic parsing is an utter kludge (e.g. what if 1_of comes at the beginning of condition followed by more logic?)
                paths = self.handle_one_of(sigma_rule['detection'], t, path, negate['n'])
                ignore = True
                logic_paths.extend(paths)
                one_of = False
                continue
            if is_or and not negate['n']:
                logic_paths.append(path)
                if level == 0 or not is_and:
                    path = []
                elif (len(path) > 1) and (path[-1] != 'not'):
                    path = path[:-1]
            if t.lower() == '1_of':
                one_of = True
                continue
            if negate['n']:
                if path and path[-1] != 'not':
                    path.append('not')
                elif not path:
                    path.append('not')
            if t.lower() == 'all_of':
                all_of = True
                continue
            path.append(t)
            ignore = False
            Notify.debug(self, "Logic Path: {}".format(path))
        if path and not ignore:
            Notify.debug(self, "Logic Path: {}".format(path))
            logic_paths.append(path)
        Notify.debug(self, "Logic Paths: {}".format(logic_paths))
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

    def rule_not_loaded(self, rule, sigma_rule):
        Notify.debug(self, "Function: {}".format(self.rule_not_loaded.__name__))
        if not sigma_rule:
            self.rules_skipped += 1
            Notify.error(self, "ERROR loading Sigma rule: " + rule)
            return True
        return False

    def skip_experimental_rules(self, sigma_rule):
        Notify.debug(self, "Function: {}".format(self.skip_experimental_rules.__name__))
        if self.process_experimental_rules == "no":
            if 'status' in sigma_rule:
                if sigma_rule['status'] == "experimental":
                    self.rules_skipped += 1
                    self.experimental_skips += 1
                    return True
        return False

    def inc_skip_counters(self):
        Notify.debug(self, "Function: {}".format(self.inc_skip_counters.__name__))
        self.rules_skipped += 1
        self.hard_skipped += 1

    def skip_rule(self, sigma_rule):
        Notify.debug(self, "Function: {}".format(self.skip_rule.__name__))
        skip = False
        if sigma_rule["id"] in self.sigma_skip_ids:  # skip specific Sigma rule GUIDs
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

        if self.sigma_convert_all.lower() == 'yes':  # convert all rules except explicit GUID skips
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
        Notify.debug(self, "Function: {}".format(self.skip_logic.__name__))
        skip = False
        logic = []
        message = "SKIPPED Sigma rule:"
        if '|' in condition:
            skip = True
            self.near_skips += 1
            logic.append('Near')
        # if (condition.count('(') > 1 and ' or ' in condition) or (
        #         not ') or (' in condition and condition.count('(') == 2):
        #     skip = True
        #     self.paren_skips += 1
        #     logic.append('Paren')
        if 'timeframe' in detection:
            skip = True
            self.timeframe_skips += 1
            logic.append('Timeframe')
        return skip, "{} {}".format(message, logic)

    def check_for_skip(self, rule, sigma_rule, detection, condition):
        """
            All logic conditions are not parsed yet.
            This procedure will skip Sigma rules we are not ready to parse.
        """
        Notify.debug(self, "Function: {}".format(self.check_for_skip.__name__))
        if self.skip_experimental_rules(sigma_rule):
            Notify.info(self, "SKIPPED Sigma rule: " + rule)
            return True
        if self.skip_rule(sigma_rule):
            Notify.info(self, "HARD SKIPPED Sigma rule: " + rule)
            return True

        skip, message = self.skip_logic(condition, detection)
        if skip:
            self.rules_skipped += 1
            Notify.info(self, message + ": " + rule)

        return skip

    def report_stats(self, error_count, wazuh_rules_count, sigma_rules_count):
        Notify.debug(self, "Function: {}".format(self.report_stats.__name__))
        sigma_rules_converted = sigma_rules_count - self.rules_skipped
        sigma_rules_converted_percent = round(((sigma_rules_converted / sigma_rules_count) * 100), 2)
        print("\n\n" + "*" * 75)
        print(" Number of Sigma Experimental rules skipped: %s" % self.experimental_skips)
        print("    Number of Sigma TIMEFRAME rules skipped: %s" % self.timeframe_skips)
        print("        Number of Sigma PAREN rules skipped: %s" % self.paren_skips)
        print("         Number of Sigma NEAR rules skipped: %s" % self.near_skips)
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


def arguments() -> argparse.ArgumentParser:
    global debug
    parser = argparse.ArgumentParser(
        usage="%(prog)s [OPTION]",
        description="Convert Sigma rules into Wazuh rules."
    )
    parser.add_argument(
        "-v", "--version", action="version",
        version = f"{parser.prog} version 1.0.0"
    )
    parser.add_argument('--debug', "-d", action="store_true",
                        help="increase output verbosity")
    args = parser.parse_args()
    if args.debug:
        debug = args.debug

def main():
    arguments()
    notify = Notify()
    notify.debug("Function: {}".format(main.__name__))
    convert = ParseSigmaRules()
    wazuh_rules = BuildRules()
    stats = TrackSkip()

    for rule in convert.sigma_rules:
        sigma_rule = convert.load_sigma_rule(rule)
        if stats.rule_not_loaded(rule, sigma_rule):
            continue

        conditions = convert.fixup_condition(sigma_rule['detection']['condition'])
        #notify.debug(conditions)

        skip_rule = stats.check_for_skip(rule, sigma_rule, sigma_rule['detection'], conditions)
        if skip_rule:
            continue
        #notify.debug(rule)

        # build the URL to the sigma rule, handle relative paths
        partial_url_path = rule.replace('/sigma/rules', '').replace('../', '/').replace('./', '/').replace('\\','/').replace('..', '')

        if isinstance(conditions, list):
            for condition in conditions:  # create new rule for each condition, needs work
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
