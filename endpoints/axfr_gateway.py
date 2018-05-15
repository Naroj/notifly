#!/usr/bin/python3

import threading as td
import logging
import requests
import random
import time
import sys

from flask import Flask, request, jsonify, Response
import dns.message
import dns.query

axfr_gw_app = Flask(__name__)

"""
TODO: Make this a fully functional endpoint
"""

"""
def get_masters(domain):
    try:
        base_url = self.config['endpoints']['pdns']['url']
        url = "{}/get_masters/{}".format(base_url, self.domain)
    except KeyError:
        return []
    try:
        headers = {}
        for header in self.config['endpoints']['pdns']['headers']:
            headers.update(header)
    except KeyError:
        headers = {}
    try:
        req = requests.get(url, headers=headers)
        json_data = req.json()
    except Exception as api_call_error: 
        logging.error("error {} while fetching masters from {}"\
        .format(api_call_error, self.domain))
        return []
    if json_data:
        logging.info("masters found for {} ({})".format(self.domain, json_data))
        return json_data
    return []


def filter_axfr(axfr_query):
    filtered_rrsets = []
    ignore_types = (
        'RRSIG',
        'DNSKEY',
        'RP',
        'NSEC',
        'NSEC3PARAM',
        'NSEC3'
    )
    for message in axfr_query:
        for rrset in message.answer:
            rdatatype = dns.rdatatype.to_text(rrset.rdtype)
            if not rdatatype in ignore_types:
                filtered_rrsets.append(rrset)
    for rrset in filtered_rrsets:
        rdatatype = dns.rdatatype.to_text(rrset.rdtype)
        domain_name_object = dns.name.Name(self.domain.split('.'))
        rrset_name = rrset.name.derelativize(origin=domain_name_object)
        new_set = {
            'name' : rrset_name.to_text(),
            'type' : rdatatype,
            'ttl' : rrset.ttl,
            'records' : []
        }
        for rdata in rrset.items:
            content = " ".join(rdata.to_text().split())
            new_set['records'].append({"content" : str(rdata.to_text())})
        logging.info("set dump: {}".format(json.dumps(new_set)))
        filtered_rrsets.append(new_set)
        
def axfr_query(domain, masters):
    for master in masters:
        logging.info("asking master: " + master)
        req = dns.query.xfr(master, domain)
        self.filter_axfr(req)
        break
"""

def serial_query(domain, masters):
    """
    Get serial from one of the DNS masters
    """
    request = dns.message.make_query(domain, dns.rdatatype.SOA)
    for master in masters:
        logging.info("asking master: " + master)
        req = dns.query.udp(request, domain)
        break

@axfr_gw_app.route('/', methods=['PUT'])
def accept_notification():
    content = request.get_json()
    logging.info(content)

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    axfr_gw_app.run(host='127.0.0.1', port=1027)
