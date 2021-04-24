#!//usr/bin/python3
"""
    Author: Brian Kellogg

    Purpose: Sigma to Wazuh log parser.

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
import sys, os
import configparser
import bs4, re
from itertools import tee
from xml.dom import minidom
from xml.etree.ElementTree import Element, SubElement, Comment, tostring, ElementTree, parse, dump
from ruamel.yaml import YAML


class BuildRules(object):
    def __init__(self):
        configParser = configparser.RawConfigParser()   
        configFilePath = r'./config.ini'
        configParser.read(configFilePath)
        self.rules_link = configParser.get('sigma', 'rules_link')
        self.low = configParser.get('levels', 'low')
        self.medium = configParser.get('levels', 'medium')
        self.high = configParser.get('levels', 'high')
        self.critical = configParser.get('levels', 'critical')
        self.no_full_log = configParser.get('options', 'no_full_log')
        self.alert_by_email = configParser.get('options', 'alert_by_email')
        self.email_levels = configParser.get('options', 'email_levels')
        self.rule_id_start = int(configParser.get('options', 'rule_id_start'))
        self.rule_id = int(configParser.get('options', 'rule_id_start'))
        self.out_file = configParser.get('sigma', 'out_file')
        self.root = self.create_root()
        # monkey patching prettify
        # reference: https://stackoverflow.com/questions/15509397/custom-indent-width-for-beautifulsoup-prettify
        orig_prettify = bs4.BeautifulSoup.prettify
        r = re.compile(r'^(\s*)', re.MULTILINE)
        def prettify(self, encoding=None, formatter="minimal", indent_width=4):
            return r.sub(r'\1' * indent_width, orig_prettify(self, encoding, formatter))
        bs4.BeautifulSoup.prettify = prettify

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

    def init_rule(self, level):
        rule = SubElement(self.root, 'rule')
        rule.set('id', str(self.rule_id))
        rule.set('level', self.get_level(level))
        return rule

    def add_logic(self, rule, field, negate, value):
        logic = SubElement(rule, 'field')
        logic.set('name', "data." + field)
        logic.set('negate', negate)
        logic.set('type', 'pcre2')
        if value.endswith(' '):
            value = '(?i)(?:' + value + ')' # spaces at end of logic are being chopped, therefore hacking this fix
        else:
            value = '(?i)' + value
        logic.text = value.replace(r'\*', r'.+') # assumption is all '*' are wildcards

    def get_level(self, level):
        if level == "critical":
            return self.critical
        elif level == "high":
            return self.high
        elif level == "medium":
            return self.medium
        else:
            return self.low

    def add_options(self, rule, level):
        options = SubElement(rule, 'options')
        ops = ""
        if self.no_full_log:
            ops = "no_full_log"
        if self.alert_by_email and (level in self.email_levels):
            ops = ops + ",alert_by_email"
        options.text = ops

    def add_mitre(self, rule, tags):
        mitre = SubElement(rule, 'mitre')
        for t in tags:
            mitre_id = SubElement(mitre, 'id')
            mitre_id.text = t

    def add_sigma_author(self, rule, sigma_rule_auther):
        comment = Comment('Sigma Rule Author: ' + sigma_rule_auther)
        rule.append(comment)

    def add_sigma_link_comment(self, rule, sigma_rule_link):
        comment = Comment(self.rules_link + sigma_rule_link)
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

    def create_rule(self, sigma_rule, sigma_rule_link):
        level = sigma_rule['level']
        rule = self.init_rule(level)
        self.add_sigma_link_comment(rule, sigma_rule_link)
        # Add rule link and author
        if 'author' in sigma_rule:
            self.add_sigma_author(rule, sigma_rule['author'])
        if 'tags' in sigma_rule:
            self.add_mitre(rule, sigma_rule['tags'])
        self.add_description(rule, sigma_rule['title'])
        self.add_options(rule, level)
        self.add_sources(rule, sigma_rule['logsource'])
        self.rule_id += 1 
        return rule

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

        # fixup some output mess up by the above
        xml = re.sub(r'</rule></group>', r'</rule>\n</group>', xml)
        xml = xml.replace('<?xml version="1.0" encoding="utf-8"?>\n', '')

        with open(self.out_file, "w") as file:
            file.write(xml)


class ParseSigmaRules(object):
    def __init__(self):
        configParser = configparser.RawConfigParser()   
        configFilePath = r'./config.ini'
        configParser.read(configFilePath)
        self.sigma_rules_dir = configParser.get('sigma', 'directory')
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
        if isinstance(condition, list):
            return [tok.replace('1 of them', '1_of_them')
                            .replace('all of them', 'all_of_them')
                            .replace('1 of', '1_of')
                            .replace('all of', 'all_of') 
                            for tok in condition]
        else:
            return condition.replace('1 of them', '1_of_them')\
                            .replace('all of them', 'all_of_them')\
                            .replace('1 of', '1_of')\
                            .replace('all of', 'all_of')

    def pairwise(self, iterable):
        "s -> (s0,s1), (s1,s2), (s2, s3), ..."
        a, b = tee(iterable)
        next(b, None)
        return zip(a, b)

    def get_detection(self, detection, token):
        values = {}
        if isinstance(detection, list):
            for item in detection: # handle detection dicts
                if isinstance(item, dict):
                    for k, v in item.items():
                        values[k] = v
                else: # handle one deep detections
                    values[token] = detection
        else:
            for k, v in detection.items():
                values[k] = v
        return values

    def fixup_logic(self, logic):
        logic = str(logic)
        if len(logic) > 2:
            if logic[0] == '*': logic = logic[1:]
            if logic[-1] == '*': logic = logic[:-1]
        return re.escape(logic)

    def handle_list(self, value):
        if isinstance(value, list):
            return ('|'.join([self.fixup_logic(i) for i in value]))
        else:
            return self.fixup_logic(value)

    def convert_transforms(self, key, value):
        field = logic = ""
        if '|' in key:
            field, transform = key.split('|', 1)
            if 'contains' == transform:
                logic = self.handle_list(value)
            elif 'contains|all' == transform:
                logic = value
            elif 'startswith' == transform:
                logic = '^(?:' + self.handle_list(value) + ')'
            elif 'endswith' == transform:
                logic = '(?:' + self.handle_list(value) + ')$'
        else:
            field = key
            logic = self.handle_list(value)
        return field, logic

    def handle_one_of_them(self, rules, rule, detection, sigma_rule, sigma_rule_link):
        rules.root.remove(rule)
        rules.rule_id -= 1
        if isinstance(detection, dict):
            for k, v in detection.items():
                if k == "condition": continue
                if isinstance(v, dict):
                    for x, y in v.items():
                        rule = rules.create_rule(sigma_rule, sigma_rule_link)
                        field, logic = self.convert_transforms(x, y)
                        self.is_dict_or_not(logic, rules, rule, field, "no")

    def handle_keywords(self, rules, rule, keywords, sigma_rule, 
                        sigma_rule_link, logic, negate):
        """
            A condition set as keywords will have a list of fields to look for those keywords in.
        """
        if 'fields' in sigma_rule:
            for f in sigma_rule['fields']:
                if isinstance(logic, list): # if logic is still a list then its contain|all logic
                    for l in logic:
                        rules.add_logic(rule, f, negate, l)
                else:
                    rules.add_logic(rule, f, negate, logic)
                rule = rules.create_rule(sigma_rule, sigma_rule_link)
            rules.root.remove(rule)
            rules.rule_id -= 1
        else:
            rules.add_logic(rule, "full_log", negate, logic)

    def is_dict_logic(self, values, rules, rule, negate):
        for k, v in values.items():
            if isinstance(v, dict):
                self.is_dict_logic(v, rules, rule, negate)
            else:
                rules.add_logic(rule, k, negate, v)

    def is_dict_or_not(self, logic, rules, rule, field, negate):
        if isinstance(logic, dict):
            self.is_dict_logic(logic, rules, rule, negate)
        else:
            if isinstance(logic, list): # if logic is still a list then its contain|all logic
                for l in logic:
                    rules.add_logic(rule, field, negate, self.fixup_logic(l))
            else:
                rules.add_logic(rule, field, negate, logic)

    def handle_fields(self, rules, rule, token, negate, is_or, sigma_rule, 
                    sigma_rule_link, detection, all_logic):
        if negate:
            n = negate.pop()
            if negate and negate[-1] == '(':
                negate.append(n)
        else:
            n = "no"

        detections = self.get_detection(detection, token)

        if is_or:
            rule = rules.create_rule(sigma_rule, sigma_rule_link)

        for k, v in detections.items():
            field, logic = self.convert_transforms(k, v)
            if logic not in all_logic: # do not add duplicate logic to a rule, even if its negated
                all_logic.append(logic)
                if k == 'keywords':
                    self.handle_keywords(rules, rule, v, sigma_rule, sigma_rule_link, logic, n)
                else:
                    self.is_dict_or_not(logic, rules, rule, field, n)

        return False, negate, all_logic

    def handle_tokens(self, rules, tokens, sigma_rule, sigma_rule_link, rule_path):
        """
            Messy attempt at a Sigma logic condition lexer. I am not good at this yet.

            Need to be able to handle rules like below:
            https://github.com/SigmaHQ/sigma/tree/master/rules/network/zeek/zeek_smb_converted_win_susp_psexec.yml
            The above rule converted to one Wazuh rule would not produce expected detection. 
        """
        level = 0       # track logic paren nesting
        is_or = False   # or logic is not supported between logic statements in a Wazuh rule
        negate = []     # stack to track negation logic
        all_logic =[]   # track all logic used in a rule to ensure a rule does not contain duplicate logic
        rule = rules.create_rule(sigma_rule, sigma_rule_link)
        for token in tokens:
            if token == '(':
                level += 1
                if negate:
                    last = negate.pop()
                    negate.append('(')
                    negate.append(last)
            elif token == ')':
                if len(negate) > 1 and negate[-2] == '(':
                    negate.pop()
                    negate.pop()
                level -= 1
            elif token.lower() == 'or':
                is_or = True
                all_logic =[] # clear logic list as we will be creating a new rule to handle OR logic
            elif token.lower() == 'and':
                continue
            elif token.lower() == 'not':
                if negate:
                    if negate[-1] != "yes":
                        negate.append('yes')
                else:
                    negate.append("yes")
            elif token.lower() == '1_of_them':
                self.handle_one_of_them(rules, rule, sigma_rule['detection'], 
                                        sigma_rule, sigma_rule_link)
            else:
                is_or, negate, all_logic = self.handle_fields(rules, rule, token,negate, is_or, 
                                                            sigma_rule, sigma_rule_link, 
                                                            sigma_rule['detection'][token], 
                                                            all_logic)


class TrackStats(object):
    def __init__(self):
        self.near_skips = 0
        self.paren_skips = 0
        self.timeframe_skips = 0
        self.rules_skipped = 0

    def check_for_logic_to_skip(self, detection, condition):
        """
            All logic conditions are not parsed yet.
            This procedure will skip Sigma rules we are not ready to parse.
        """
        skip = False
        if '|' in condition:
            skip = True
            self.near_skips += 1
        if '(' in condition:
            skip = True
            self.paren_skips += 1
        if 'timeframe' in detection:
            skip = True
            self.timeframe_skips += 1
        if '1_of ' in condition:
            skip = True
            self.rules_skipped += 1
        if 'all_of' in condition:
            skip = True
            self.rules_skipped += 1
            
        return skip

    def report_stats(self, error_count, sigma_rules_count, rule_id_start, rule_id_end):
        sigma_rules_converted = sigma_rules_count - self.rules_skipped
        sigma_rules_converted_percent = round((( sigma_rules_converted / sigma_rules_count) * 100), 2)
        print("\n\n" + "*" * 75)
        print("    Number of Sigma TIMEFRAME rules skipped: %s" % self.timeframe_skips)
        print("         Number of Sigma NEAR rules skipped: %s" % self.near_skips)
        print("        Number of Sigma PAREN rules skipped: %s" % self.paren_skips)
        print("        Number of Sigma ERROR rules skipped: %s" % error_count)
        print("                  Total Sigma rules skipped: %s" % self.rules_skipped)
        print("                Total Sigma rules converted: %s" % sigma_rules_converted)
        print("-" * 55)
        print("                  Total Wazuh rules created: %s" % (rule_id_end - rule_id_start))
        print("-" * 55)
        print("                          Total Sigma rules: %s" % sigma_rules_count)
        print("                    Sigma rules converted %%: %s" % sigma_rules_converted_percent)
        print("*" * 75 + "\n\n")


def main():
    convert = ParseSigmaRules()
    wazuh_rules = BuildRules()
    stats = TrackStats()

    for rule in convert.sigma_rules:
        sigma_rule = convert.load_sigma_rule(rule)
        if not sigma_rule:
            stats.rules_skipped += 1
            print("ERROR loading Sigma rule: " + rule)
            continue

        conditions = convert.fixup_condition(sigma_rule['detection']['condition'])

        skip_rule = stats.check_for_logic_to_skip(sigma_rule['detection'], conditions)
        if skip_rule:
            stats.rules_skipped += 1
            print("SKIPPED Sigma rule: " + rule)
            continue
        #print(rule)

        # build the URL to the sigma rule, handle relative paths
        partial_path = rule.replace('/sigma/rules', '').replace('../', '/').replace('./', '/')

        if isinstance(conditions, list):
            for condition in conditions: # create new rule for each condition
                tokens = condition.strip().split(' ')
                convert.handle_tokens(wazuh_rules, tokens, sigma_rule, partial_path, rule)
        else:
            tokens = conditions.strip().split(' ')
            convert.handle_tokens(wazuh_rules, tokens, sigma_rule, partial_path, rule)

    # write out all Wazuh rules created
    wazuh_rules.write_rules_file()

    stats.report_stats(convert.error_count, len(convert.sigma_rules), 
                        wazuh_rules.rule_id_start, wazuh_rules.rule_id)


if __name__ == "__main__":
    main()