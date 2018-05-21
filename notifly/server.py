#!/usr/bin/env python3

"""
Asynchronous TCP/UDP DNS service
Listens for DNS notifications and calls backend as configured
(c) jfranx@kernelbug.org
"""

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

class EventQueueMonitor(td.Thread):

    """
    Report event queue size via logging module
    """

    deamon = True

    def run(self):
        while True:
            time.sleep(3)
            logging.info("event queue size: %s", EVENT_QUEUE.qsize()) 

class Event(td.Thread):

    """
    Handle a single event non-blocking
    """

    def __init__(self, domain):
        super(Event, self).__init__()
        self.domain = domain

    def run(self):
        self.invoke_endpoints()

    def invoke_endpoints(self):
        """
        Invoke endpoints from configuration
        """
        for name, conf  in CONF['endpoints'].items():
            #logging.info("invoking endpoint: {}".format(name))
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
            try:
                req = requests.put(url, headers=headers, data=payload)
                json_data = req.json()
                logging.debug(json_data)
                #EVENT_QUEUE.put(('127.0.0.1', self.domain))
            except Exception as endpoint_error:
                logging.error(
                    "endpoint {} errors: {}".format(name, endpoint_error)
                )
            # TODO explicit logging of endpoint responses
            #      perform checks on returned output


class EventReceiver(mp.Process):

    """
    Receive events and initiate an 'Event' class
    """

    daemon = True

    def run(self):
        # TODO find out if event queue provides an iterator
        #      add limit on events to process
        while True:
            time.sleep(random.choice((1, 3, 2)))
            qsize = EVENT_QUEUE.qsize()
            if qsize > CONF['event_batch_size']:
                run_length = CONF['event_batch_size']
            else:
                run_length = qsize
            if run_length:
                logging.info("event queue contains {} items, processing {}"\
                .format(qsize, run_length))
            else:
                logging.info('{} has naptime'.format(os.getpid()))
            threads = []
            for event in iter(EVENT_QUEUE.get, None):
                run_length -= 1
                if not run_length:
                    logging.info("event limit reached %s items left", EVENT_QUEUE,qsize())
                    break
                event_thread = Event(
                    domain=event[1]
                )
                threads.append(event_thread)
                event_thread.start()
                event_thread.join()


class AsyncUDP(asyncio.DatagramProtocol):

    """
    event-driven UDP DNS parser
    we process binary payload
    relevant elements in a queue
    event listener classes will take notice and perform content-level operations
    if event_queue is given to our contructor we use that (meant for tests)
    """

    def __init__(self, event_queue=None):
        self.event_queue = event_queue
        super(AsyncUDP, self).__init__()

    def connection_made(self, transport):
        """ called from asyncio module """
        self.transport = transport

    def health_check(self, request, addr):
        """
        keeps DNSDIST happy
        Forward query to system resolvers (upstream)
        send resolver answer downstream
        """
        res = dns.resolver.Resolver(configure=True)
        health_query = res.query(request.origin, request.rdtype)
        health_resp = health_query.response
        health_resp.id = request.query_id
        self.transport.sendto(health_resp.to_wire(), addr)

    def unpack_from_wire(self, data):
        """
        Parse binary payload from wire
        return a request object with meaningful aspects from DNS packet
        """
        payload = dns.message.from_wire(data)
        if not payload.question:
            logging.error("dropping packet without question section")
            return None
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

    def handle_request(self, request, addr, is_test):
        """
        Take a parsed request (from self.unpack_from_wire)
        Perform checks on content and either process a NOTIFY or pass it to self.health_check
        trailling dots from origins are always removed
        when is_test (boolean) is True we won't send a UDP response but return binary response instead
        """
        if request is None:
            logging.error('no data received')
            return
        if request.opcode_text == 'NOTIFY':
            if request.origin[-1] == '.':
                origin = request.origin[:-1]
            else:
                origin = request.origin
            #logging.info("notify for %s", origin)
            if not self.event_queue:
                EVENT_QUEUE.put((addr[0], origin))
            else:
                self.event_queue.put((addr[0], origin))
            response = dns.message.make_response(request.request)
            response.flags |= dns.flags.AA
            wire = response.to_wire(response)
            if is_test:
                return wire
            self.transport.sendto(wire, addr)
        # TODO: explicit DNSDIST health query check
        else:
            if is_test:
                return False
            try:
                self.health_check(request, addr)
            except Exception as health_err:
                logging.info("health-check error: {}".format(health_err))

    def datagram_received(self, data, addr, is_test=False):
        """
        this method is called on each incoming UDP packet by asyncio module
        """
        try:
            source_ip = addr[0]
        except KeyError:
            logging.error('incomplete packet received, no src IP found')
            return
        try:
            addr[1]
        except KeyError:
            logging.error('incomplete packet received, no src port found')
            return
        request = self.unpack_from_wire(data)
        self.handle_request(request, addr, is_test)


class UDPListener(mp.Process):

    """
    Clueless UNIX process
    when initiated we switch to an async event loop
    """

    daemon = True

    def run(self):
        """
        process entry method
        daemonize async event loop
        """
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        endpoint = loop.create_datagram_endpoint(
            AsyncUDP,
            local_addr=(CONF['local_ip'], int(CONF['local_port']))
        )
        server = loop.run_until_complete(endpoint)
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()


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
        '--event-batch-size',
        required=False,
        default=100,
        help='Port on which we receive DNS notifications (RFC1996)'
    )
    parser.add_argument(
        '--workers',
        required=False,
        default=2,
        help='Parallel workers to spread the load'
    )
    parser.add_argument(
        '--conf',
        required=False,
        default=None,
        help='parse config for endpoint invocation'
    )
    parsed_args = parser.parse_args(sys.argv[1:])
    return parsed_args

def parse_config_file(config):
    """
    Load config file (primarily for endpoints)
    """
    fail = False
    with open(config, 'r') as fp:
        content = yaml.load(fp.read())
    if 'endpoints' not in content.keys():
        return
    for title, items in content['endpoints'].items():
        if not 'url' in items.keys():
            fail = True
            logging.error("no url found in endpoint '%s'", title)
        if not items['url'].startswith('http'):
            fail = True
            logging.error("non HTTP(S) url found in endoint '%s'", title)
        if not items['url'].startswith('https'):
            logging.warning("non SSL url found in endoint '%s'", title)
    if fail:
        logging.info("stopping execution due to blocking config issues")
        sys.exit(1)
    return content

def load_config(config_file=None):
    """
    Parse config file and load parameters from CLI
    the config file is always leading
    """
    params = parameter_parser()
    if params.conf:
        conf_file = parse_config_file(params.conf)
    else:
        if config_file:
            conf_file = parse_config_file(config_file)
    try:
        local_ip = conf_file['net']['local_ip']
    except KeyError:
        local_ip = None
    try:
        local_port = conf_file['net']['local_port']
    except KeyError:
        local_port = None
    try:
        accept_from = conf_file['net']['accept_from']
    except KeyError:
        accept_from = None
    try:
        endpoints = conf_file['endpoints']
    except KeyError:
        endpoints = None
    try:
        event_batch_size = conf_file['general']['event_batch_size']
    except KeyError:
        event_batch_size = None
    try:
        workers = conf_file['workers']
    except KeyError:
        workers = None
    if not local_ip:
        local_ip = params.local_ip
    if not local_port:
        local_port = params.local_port
    if not workers:
        workers = params.workers
    if not event_batch_size:
        event_batch_size = params.event_batch_size
    return {
        'local_port' : local_port,
        'local_ip' : local_ip,
        'accept_from' : accept_from,
        'workers' : workers,
        'event_batch_size' : event_batch_size,
        'endpoints' : endpoints
    }

if __name__ == '__main__':
    """
    Get settings from CLI arguments and config
    Start event queue monitor
    Start proc managers
    """
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)
    EVENT_QUEUE = mp.Queue()
    CONF = load_config()
    logging.info("starting server %s:%s",\
    CONF['local_ip'], CONF['local_port'])
    WORKER_CLASSES = {}
    for num in range(0, int(CONF['workers'])):
        WORKER_CLASSES.update({num : EventReceiver})
    logging.info("starting {} workers".format(CONF['workers']))
    NS_CLASSES = {
        'udp' : UDPListener
    }
    NS_RUNTIME = []
    WORKER_RUNTIME = []
    event_monitor = EventQueueMonitor()
    event_monitor.start()
    while True:
        proc_manager(**{
            'classes' : NS_CLASSES,
            'runtime' : NS_RUNTIME
        })
        proc_manager(**{
            'classes' : WORKER_CLASSES,
            'runtime' : WORKER_RUNTIME
        })
        time.sleep(10)
