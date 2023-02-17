#!//usr/bin/python3
"""
    Author: Brian Kellogg

    Purpose: Get Wazuh rule information and report out in CSV.
"""


import os
import xml.etree.ElementTree as etree


class WazuhRules(object):
    def __init__(self):
        self.rule_dirs = ['/var/ossec/ruleset/rules', '/var/ossec/etc/rules']
        self.rule_files = self.get_wazuh_rule_files() # array containing all file absolute paths
        self.rules = self.load_wazuh_rules() # array of all rule files loaded from files stored ElementTrees

    def get_wazuh_rule_files(self):
        fname = []
        for dir in self.rule_dirs:
            for root, dirs, f_names in os.walk(dir):
                for f in f_names:
                    fname.append(os.path.join(root, f))
        return fname

    def load_wazuh_rule(self, rule_file):
        try:
            with open(rule_file) as file:
                raw_xml = '<rules>' + file.read() + '</rules>' # wrap file contents in outer tags so we can load it as one XML file
            return etree.ElementTree(etree.fromstring(raw_xml))
        except Exception as e:
            print("ERROR: unable to load %si -> %s" % (rule_file, e))
            return None

    def load_wazuh_rules(self):
        rules = []
        for f in self.rule_files:
            temp = self.load_wazuh_rule(f)
            if temp:
                rules.append(self.load_wazuh_rule(f))
        return rules


class Report(object):
    def __init__(self, rules):
        self.tsv = [] # initial array of per rule tsv entries
        self.final_csv = [] # final result of parsing all the information we want to be written to a file
        self.rules = rules # rules array passed in from Wazuh Rules class

    def init_print_vars(self):
        """
            (Re)initialize variables used in the parse_rules loop
        """
        ifsid = None
        rid = None
        level = None
        description = None
        decoded_as = None
        fields = []
        return rid, level, description, decoded_as, ifsid, fields

    def parse_rules(self):
        self.tsv.append('"id"\t"level"\t"description"\t"decoded_as"\t"fields"\t"parents"')
        for r in self.rules:
            rid, level, description, decoded_as, ifsid, fields = self.init_print_vars()
            new_rule = False
            for e in r.iter():
                if e.tag == 'rule':
                    if new_rule:
                        self.tsv.append('"{}"\t"{}"\t"{}"\t"{}"\t"{}"\t"{}"'.format(rid, level, description, decoded_as, fields, ifsid))
                        rid, level, description, decoded_as, ifsid, fields = self.init_print_vars()
                    new_rule = True
                    rid = e.attrib.get('id')
                    level = e.attrib.get('level')
                elif e.tag == 'description':
                    description = e.text
                    description = description.replace('"', '""') # one rule has quotes in the description, need to escap them
                elif e.tag == 'if_sid':
                    ifsid = e.text
                elif e.tag == "decoded_as":
                    decoded_as = e.text
                elif e.tag == 'field':
                    fields.append(e.attrib.get('name'))

    def find_children(self):
        self.final_csv.append('"id","level","description","decoded_as","fields","parents","children"')
        for outer in self.tsv[1:]:
            children = []
            rule_id = outer.split("\t")[0]
            for inner in self.tsv[1:]:
                fields = inner.split("\t")
                ifsids = [s.strip() for s in fields[5].split(',')]
                if rule_id in ifsids:
                    children.append(fields[0])
            if children:
                children = [int(i.strip('"')) for i in children]
            self.final_csv.append('{},"{}"'.format(outer.replace('\t',','), str(children).strip('[]')))

    def write_report(self):
        with open('wazuh_rule_report.csv', 'w') as file:
            for line in self.final_csv:
                file.write(line + "\n")


def main():
    wazuh_rules = WazuhRules()
    report = Report(wazuh_rules.rules)
    report.parse_rules()
    report.find_children()
    report.write_report()

if __name__ == "__main__":
    main()