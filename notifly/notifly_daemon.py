#!/usr/bin/env python3

import os
import sys
import asyncio
import logging
import argparse
import collections
import time
import random
import threading as td
import multiprocessing as mp
import pprint
import json

import requests
import yaml
import dns.flags
import dns.name
import dns.query
import dns.opcode
import dns.message
import dns.rdtypes
import dns.rdatatype
import dns.rdataclass
import dns.resolver

"""
Asynchronous TCP/UDP DNS service
Listens for DNS notifications and calls backend as configured
(c) jfranx@kernelbug.org
"""

class Event(td.Thread):

    """
    Handle a single event non-blocking
    """

    def __init__(self, **kwargs):
        super(Event, self).__init__()
        self.config = kwargs['config']
        self.domain = kwargs['domain']

    def run(self):
        time.sleep(random.choice((1, 2, 3)))
        self.invoke_endpoints()

    def invoke_endpoints(self):
        """
        Invoke endpoints from configuration
        """
        for name, conf  in self.config['endpoints'].items():
            logging.info("invoking endpoint: {}".format(name))
            try:
                url = conf['url']
            except KeyError:
                logging.error("endpoint without url")
                continue
            try:
                headers = {}
                for header in conf['headers']:
                    headers.update(header)
            except KeyError:
                headers = {}
            payload = json.dumps({'domain' : self.domain})
            req = requests.put(url, headers=headers, data=payload)
            json_data = req.json()
            logging.info(json_data)


class EventReceiver(mp.Process):

    """
    Receive events and initiate an 'Event' class
    """

    daemon = True

    def __init__(self, config):
        super(EventReceiver, self).__init__()
        self.config = config

    def run(self):
        """
        run a daemonized consumer
        consumer will drop events in our queue
        """
        while True:
            time.sleep(random.choice((2, 1)))
            qsize = EVENT_QUEUE.qsize()
            for num in range(0, qsize):
                event = EVENT_QUEUE.get()
                event_thread = Event(
                    config=self.config,
                    domain=event[1]
                )
                event_thread.start()
                #self.event_handler(event)
            logging.info('{} has naptime'.format(os.getpid()))


class AsyncUDP(asyncio.DatagramProtocol):

    """
    event-driven UDP DNS parser
    we process binary payload
    relevant elements in a queue
    event listener classes will take notice and perform content-level operations
    """

    def connection_made(self, transport):
        self.transport = transport

    def health_check(self, request, addr):
        """
        Forward query to system resolvers (upstream)
        send resolver answer downstream
        (override response id with query id in order to satisfy client)
        """
        res = dns.resolver.Resolver(configure=True)
        health_query = res.query(request.origin, request.rdtype)
        health_resp = health_query.response
        health_resp.id = request.query_id
        self.transport.sendto(health_resp.to_wire(), addr)

    def unpack_from_wire(self, data):
        """
        Parse binary payload from wire
        return a shiny object with relevant aspects
        """
        payload = dns.message.from_wire(data)
        if not payload.question:
            return
        request = collections.namedtuple(
            'Request', [
                'request',
                'query_id',
                'rdtype',
                'origin',
                'opcode_int',
                'opcode_text'
            ]
        )
        request_data = request(
            request=payload,
            query_id=payload.id,
            rdtype=payload.question[0].rdtype,
            origin=payload.question[0].name.to_text(),
            opcode_int=dns.opcode.from_flags(payload.flags),
            opcode_text=dns.opcode.to_text(dns.opcode.from_flags(payload.flags))
        )
        return request_data

    def datagram_received(self, data, addr):
        """
        this method is called on each incoming UDP packet
        """
        request = self.unpack_from_wire(data)
        source_ip = addr[0]
        if request is None:
            return()
        if request.opcode_text == 'NOTIFY':
            logging.info(dir(request.request))
            for opt in request.request.options:
                logging.info(opt.data)
            if request.origin[-1] == '.':
                EVENT_QUEUE.put((source_ip, request.origin[:-1]))
            else:
                EVENT_QUEUE.put((source_ip, request.origin))
            self.transport.sendto(data, addr)
            logging.info('notification')
        else:
            try:
                self.health_check(request, addr)
            except Exception as health_err:
                logging.info("health-check error: {}".format(health_err))


class UDPListener(mp.Process):

    """
    Clueless UNIX process
    when initiated we switch to an async event loop
    """

    daemon = True

    def __init__(self, address='127.0.0.1', port=5500):
        super(UDPListener, self).__init__()
        self.address = address
        self.port = port

    def run(self):
        """
        process entry method
        daemonize async event loop
        """
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        endpoint = loop.create_datagram_endpoint(
            AsyncUDP,
            local_addr=(self.address, int(self.port))
        )
        server = loop.run_until_complete(endpoint)
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()


def parameter_parser():
    """ parse CLI parameters """
    parser = argparse.ArgumentParser(
        description='Programmable DNS notification daemon (c) jfranx@kernelbug.org'
    )
    parser.add_argument(
        '--local-ip',
        required=False,
        default='127.0.0.1',
        help='IP address to listen on'
    )
    parser.add_argument(
        '--local-port',
        required=False,
        default=0,
        help='Port on which we receive DNS notifications (RFC1996)'
    )
    parser.add_argument(
        '--conf',
        required=False,
        default=None,
        help='parse config for endpoint invocation'
    )
    parsed_args = parser.parse_args(sys.argv[1:])
    return parsed_args


def proc_manager(**kwargs):
    """
    Manage nameserver processes
    classes: dict of process categories
    properties: dict of class arguments passed as **kwargs
    runtime: list of running processes
    """
    if 'classes' in kwargs.keys():
        classes = kwargs['classes']
    else:
        sys.exit(1)
    if 'properties' in kwargs.keys():
        properties = kwargs['properties']
    else:
        properties = {}
    if 'runtime' in kwargs.keys():
        runtime = kwargs['runtime']
    else:
        runtime = []
    if not runtime:
        logging.info('we have an empty runtime, a new one is coming up')
        for proc_name, proc_class in classes.items():
            proc_instance = proc_class(**properties)
            proc_instance.start()
            runtime.append(tuple((proc_name, proc_instance)))
    for unix_proc in runtime:
        proc_name = unix_proc[0]
        proc_inst = unix_proc[1]
        if not proc_inst.is_alive():
            logging.info('proc {} died, new instance is on the rise %s' % proc_inst)
            runtime.remove(unix_proc)
            new_instance = classes[proc_name](**properties)
            new_instance.start()
            runtime.append(tuple((proc_name, new_instance)))

def load_config(config):
    """
    Load config file (primarily for endpoints)
    """
    fail = False
    with open(config, 'r') as fp:
        content = yaml.load(fp.read())
    if not 'endpoints' in content.keys():
        return
    for title, items in content['endpoints'].items():
        if not 'url' in items.keys():
            fail = True
            logging.error("no url found in endpoint '{}'".format(title))
        if not items['url'].startswith('http'):
            fail = True
            logging.error("non HTTP(S) url found in endoint '{}'".format(title))
        if not items['url'].startswith('https'):
            logging.warning("non SSL url found in endoint '{}'".format(title))
    if fail:
        logging.info("stopping execution due to blocking config issues")
        sys.exit(1)
    return content

if __name__ == '__main__':
    """
    Get settings from CLI arguments
    TODO: add yaml config support
    Start proc managers
    """
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    EVENT_QUEUE = mp.Queue()
    PARAMS = parameter_parser()
    if PARAMS.conf:
        CONFIG = load_config(PARAMS.conf)
    else:
        CONFIG = None
    NS_CLASSES = {
        'udp' : UDPListener
    }
    NS_PROPERTIES = {
        'address' : PARAMS.local_ip,
        'port' : int(PARAMS.local_port)
    }
    NS_RUNTIME = []
    EVENT_CLASSES = {
        'recv0' : EventReceiver,
        'recv1' : EventReceiver
    }
    EVENT_PROPERTIES = {
        'config' : CONFIG
    }
    EVENT_RUNTIME = []
    while True:
        time.sleep(1)
        proc_manager(**{
            'classes' : NS_CLASSES,
            'properties': NS_PROPERTIES,
            'runtime' : NS_RUNTIME
        })
        proc_manager(**{
            'classes' : EVENT_CLASSES,
            'properties' : EVENT_PROPERTIES,
            'runtime' : EVENT_RUNTIME
        })
