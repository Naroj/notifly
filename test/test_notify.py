"""
Notification test module
Check if a NOTIFY message is parsed the right way
"""

import unittest
import sys
import os
import tempfile
import logging
import queue
import random

import dns.name
import dns.message
import dns.query
import dns.rdatatype

from notifly import server

class TestNotifyHandling(unittest.TestCase):

    """
    test the handling of a binary NOTIFY message
    """
 
    domain = None
    addr = None

    def setUp(self):
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
        self.domain = random.choice((
            'example.nl', 
            'example.com', 
            'example.tk'
        ))
        self.addr = random.choice((
            ('127.0.0.1', 40), 
            ('126.0.0.1', 20), 
            ('125.0.0.1', 30),
        ))

    def tearDown(self):
        logging.debug("ending test")

    def test_queue_in_out(self):
        """
        Test if result queue is the expected amount of items
        """
        logging.info("notify queue in/out test")
        event_queue = conduct_notify(self.domain, self.addr)
        if not event_queue.qsize():
            self.fail("notification was not passed to queue")
        elif event_queue.qsize() > 1:
            self.fail("queue got more than one item")
        else:
            pop = event_queue.get()
        if event_queue.qsize():
            self.fail("queue still contains items after the only item is popped")

    def test_queue_content(self):
        """
        Test if the result queue items have expected values in content
        """
        logging.info("notify queue content test")
        event_queue = conduct_notify(self.domain, self.addr)
        item = event_queue.get()
        logging.info("received item: %s", item)
        if not item[0] == self.addr[0]:
            self.fail("unexpected source address returned: %s", item[0])
        if not item[1] == self.domain:
            self.fail("unexpected domain returned: %s", item[1])


def conduct_notify(domain, addr):
    """ 
    Conduct DNS NOTIFY object and event queue based on function input
    The result can be fetched from the returned queue object
    """
    Q = queue.Queue()
    notify = dns.message.make_query(domain, dns.rdatatype.SOA)
    notify.set_opcode(dns.opcode.NOTIFY)
    logging.debug("sending '%s' to parser", notify.question)
    wire = notify.to_wire()
    udp_server = server.AsyncUDP(
        event_queue=Q
    )
    request = udp_server.unpack_from_wire(wire)
    answer = udp_server.handle_request(
        request,
        addr=addr,
        is_test=True
    )
    return Q



if __name__ == '__main__':
    unittest.main()
