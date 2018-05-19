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
def get_masters(domain, remote_api, remote_api_key):
    """
    Get masters from a domain
    """
    url = "{}/api/v1/servers/localhost/zones/{}".format(remote_api, domain)
    headers = {'X-API-Key' : remote_api_key}
    payload = {'server_id':'localhost', 'zone_id' : domain}
    req = requests.get(url, headers=headers)
    data = req.json()
    if 'error' in data.keys():
        logging.error(data['error'])
        return []
    try:
        return data['masters']
    except KeyError:
        return []
    return []

"""

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

def serial_query(domain, nameservers):
    """
    Get serial from one of the DNS masters
    """
    request = dns.message.make_query(domain, dns.rdatatype.SOA)
    for ns in nameservers:
        logging.info("asking nameserver: " + ns)
        try:
            req = dns.query.udp(request, ns)
            break
        except Exception as query_error:
            req = None
            logging.warning("nameserver threw an error: {}".format(query_error))
    if not req:
        logging.error("no nameserver returned a serial")
        return False
    try:
        ns_serial = int(req.answer[0].to_text().split()[-5:][0])
        return ns_serial
    except:
        logging.error("got invalid SOA record: {}".format(req.answer))
        return False

@axfr_gw_app.route('/', methods=['PUT'])
def accept_notification():
    content = request.get_json()
    if not content:
        msg = 'no json in payload (maybe you forgot to set the content-type)'
        return jsonify({'error' : msg}), 400
    remote_api = request.headers.get('remote_api'),
    remote_api_key = request.headers.get('remote_api_key')
    masters = get_masters(
        content['domain'], 
        remote_api[0], 
        remote_api_key
    )
    slaves = ['185.3.211.53']
    master_serial = serial_query(content['domain'], masters)
    slave_serial = serial_query(content['domain'], slaves)
    if master_serial > slave_serial:
        perform_transfer()
    return jsonify({'msg' : masters}), 202

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    axfr_gw_app.run(host='127.0.0.1', port=1027)
