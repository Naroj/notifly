import threading as td
import logging
import requests
import random
import time
import sys

from flask import Flask, request, jsonify, Response
pdns_app = Flask(__name__)

"""
REST endpoint which receives zone input and emails it to someone of great importance
"""

def pdns_perform_rectify(**kwargs):
    """
    DNSSEC enabled domains need to be rectified when content is changed.
    Especially when wildcards are used (it'll re-orden NSEC3 data).
    """
    url = "{}/api/v1/servers/localhost/zones/{}/rectify".format(kwargs['remote_api'], kwargs['domain'])
    headers = {'X-API-Key' : kwargs['remote_api_key']}
    payload = {'server_id':'localhost', 'zone_id' : kwargs['domain']}
    req = requests.put(url, headers=headers, data=payload)
    logging.info(str(req))

def pdns_get_masters(**kwargs):
    """
    Get masters from a domain
    """
    url = "{}/api/v1/servers/localhost/zones/{}".format(kwargs['remote_api'], kwargs['domain'])
    headers = {'X-API-Key' : kwargs['remote_api_key']}
    payload = {'server_id':'localhost', 'zone_id' : kwargs['domain']}
    req = requests.get(url, headers=headers, data=payload)
    data = req.json()
    if 'error' in data.keys():
        logging.error(data['error'])
        return []
    return data['masters']

@pdns_app.route('/get_masters/<string:domain>', methods=['GET'])
def get_masters(domain):
    """ """
    content = request.get_json()
    conf = {
        'check_masters' : request.headers.get('check_masters'),
        'remote_api' : request.headers.get('remote_api'),
        'remote_api_key' : request.headers.get('remote_api_key')
    }
    masters = pdns_get_masters(
        remote_api=conf['remote_api'],
        remote_api_key=conf['remote_api_key'],
        domain=domain
    )
    logging.info("masters: {}".format(masters))
    return jsonify(masters)
    
@pdns_app.route('/', methods=['PUT'])
def accept_notification():
    """ receive notifications """
    content = request.get_json()
    conf = {
        'check_masters' : request.headers.get('check_masters'),
        'remote_api' : request.headers.get('remote_api'),
        'remote_api_key' : request.headers.get('remote_api_key')
    }
    pdns_perform_rectify(
        remote_api=conf['remote_api'],
        remote_api_key=conf['remote_api_key'],
        domain='dootall.nl'
    )
    return jsonify({'msg' : 'gracias amigo!'})

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    pdns_app.run(host='127.0.0.1', port=1026)
