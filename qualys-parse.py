#!/usr/bin/env python3
"""
Parsing Qualys XML
"""
 
import argparse
import csv
import os
 
from collections import defaultdict
import xml.etree.ElementTree as ET
 
targets = defaultdict(set)
 
def parse_xml(xml):
    tree = ET.parse(xml)
    root = tree.getroot()
    for ip in root.iter('IP'):
        host = ip.get('value')
        for finding in ip.iter('CAT'):
            # <TITLE>
            title = finding[0][0].text
            if "Services List" in title:
                # <RESULTS>
                results = finding[0][6].text
                for line in results.split('\n')[1:]:
                    column = line.split('\t')
                    port = column[0]
                    details = column[1:]
                    http_webports = [ '80', '8080']
                    http_webprotocols = [ 'www', 'http','http-alt' ]
                    https_webports = [ '443', '4433', '8443' ]
                    https_webprotocols = [ 'https', 'http over ssl' ]
                    bah = [ 'unknown over ssl' ]
                    # https checks to account for future usage with fierce
                    # Also, this needs to be better
                    if (port in http_webports) or (column[1] in http_webprotocols) or (column[2] in http_webprotocols):
                        https = False
                        print(" - [*]  Target found = {host}:{port} - HTTPS [{https}]"
                                .format(host=host, port=port, https=https))
                        targets[host].add(port)
                    elif (port in https_webports) or (column[1] in https_webprotocols) or (column[2] in https_webprotocols) or (column[3] in bah):
                        https = True
                        print(" - [*]  Target found = {host}:{port} - HTTPS [{https}]"
                                .format(host=host, port=port, https=https))
                        targets[host].add(port)
 
def write_csv(outfile):
    with open(outfile, 'w') as f:
        writer = csv.writer(f)    
        for k,v in targets.items():
            v = list(v)
            writer.writerow([k] + list(v))
 
def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('-x', '--xml')
    argparser.add_argument('-o', '--outfile', default="web_site-targets.csv")
    args = argparser.parse_args()
    xml = (os.getcwd() + "/" + args.xml)
    outfile = (os.getcwd() + "/" + args.outfile)
    parse_xml(xml)
    write_csv(outfile)
 
if __name__ == "__main__":
    main()
