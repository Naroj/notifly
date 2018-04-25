#!/usr/bin/env python3

import os
import sys
import asyncio
import logging
import argparse
import collections
import time
import multiprocessing as mp

import requests
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
Asynchronous TCP/UDP DNS service python
Listens for DNS notifications and returns AXFR fetched content as JSON object
(c) jfranx@kernelbug.org
"""

class EventReceiver(mp.Process):

    """
    Receive events, send them to shared memory space
    The EventRouter will get take over from there
    """

    daemon = True

    def __init__(self, remote_api, remote_api_key):
        super(EventReceiver, self).__init__()
        self.remote_api = remote_api
        self.remote_api_key = remote_api_key

    def perform_rectify(self, domain):
        url = "{}/api/v1/servers/localhost/zones/{}/rectify".format(self.remote_api, domain)
        headers = {'X-API-Key' : self.remote_api_key}
        payload = {'server_id':'localhost', 'zone_id' : domain}
        req = requests.put(url, headers=headers, data=payload)
        logging.info(str(req))

    def check_masters(self, source_ip, domain):
        """
        check if notify sender is configured as a master
        """
        url = "{}/api/v1/servers/localhost/zones/{}".format(self.remote_api, domain)
        headers = {'X-API-Key' : self.remote_api_key}       
        req = requests.get(url, headers=headers)    
        json_data = req.json()
        if not 'masters' in json_data:
            logging.error("domain {} has no configured masters")
            return None
        if source_ip in json_data['masters']:
            logging.info("sender is known master")
            return True
        else:
            logging.info("sender ({}) is not master".format(source_ip))
            return False

    def run(self):
        """
        run a daemonized consumer
        consumer will drop events in our queue
        """
        while True:
            time.sleep(3)
            qsize = EVENT_QUEUE.qsize()
            for num in range(0, qsize):
                item = EVENT_QUEUE.get()
                sender_is_master = self.check_masters(source_ip=item[0], domain=item[1])
                if sender_is_master:
                    self.perform_rectify(domain=item[1])
            logging.info('{} has naptime'.format(os.getpid()))


class AsyncUDP(asyncio.DatagramProtocol):

    """
    event-driven UDP DNS parser
    we process binary payload
    relevant elements in a queue
    event listener classes will take notice and perform content-level operations
    """

    #def __init__(self):
    #    super(AsyncUDP, self).__init__()

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
        default='0.0.0.0',
        help='IP address to listen on'
    )
    parser.add_argument(
        '--local-port',
        required=False,
        default=53,
        help='Port on which we receive DNS notifications (RFC1996)'
    )
    parser.add_argument(
        '--remote-api',
        required=False,
        default="http://185.3.211.53:8081",
        help='remote authoritive PowerDNS API'
    )
    parser.add_argument(
        '--remote-api-key',
        required=False,
        default="api_Iu2ooyuoSee5zeihee5doeNgohPhir0f",
        help='remote authoritive PowerDNS API key'
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

if __name__ == '__main__':
    """
    Get settings from CLI arguments
    TODO: add yaml config support
    Start proc managers
    """
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    EVENT_QUEUE = mp.Queue()
    PARAMS = parameter_parser()
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
        'recv1' : EventReceiver,
        'recv2' : EventReceiver
    }
    EVENT_PROPERTIES = {
        'remote_api' : PARAMS.remote_api,
        'remote_api_key' : PARAMS.remote_api_key
    }
    EVENT_RUNTIME = []
    while True:
        time.sleep(1)
        proc_manager(**{
            'classes'   : NS_CLASSES,
            'properties': NS_PROPERTIES,
            'runtime'   : NS_RUNTIME
        })
        proc_manager(
            classes=EVENT_CLASSES,
            properties=EVENT_PROPERTIES,
            runtime=EVENT_RUNTIME
        )
