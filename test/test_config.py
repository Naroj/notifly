"""
Config test module
Check wether config parser return expected output based on input
"""

import unittest
import sys
import os
import tempfile
import logging
from notifly import server

MOCK_CONFIG_NO_DEFAULTS = """
endpoints:
  pdns:
    headers:
      - check_masters: "true"
      - remote_api: "http://185.3.211.53:8081"
      - remote_api_key: "*******"
    url: "http://127.0.0.1:1026"
  #axfr_gateway:
  #  headers:
  #    - content-type: "application/json"
  #    - remote_api: "http://185.3.211.53:8081"
  #    - remote_api_key: "******"
  #  url: "http://127.0.0.1:1027"
  #mailer: 
  #  headers: 
  #    - from_email: "corn@example.io"
  #    - to_email: "bucket+lol@example.nl"
  #    - subject: "zone update"
  #  url: "http://127.0.0.1:1025"

general:
  check_masters: true
  event_batch_size: 5000

net:
  accept_from: "dnsdist1.example.nl,dnsdist2.example.nl"
  local_ip: "0.0.0.0"
  local_port: 5400
"""

MOCK_CONFIG_ONLY_DEFAULTS = """
endpoints:
  pdns:
    headers:
      - check_masters: "true"
      - remote_api: "http://185.3.211.53:8081"
      - remote_api_key: "api_Iu2ooyuoSee5zeihee5doeNgohPhir0f"
    url: "http://127.0.0.1:1026"
"""

MOCK_CONFIG_IMPOSSIBLE_PORT = """
endpoints:
  pdns:
    headers:
      - check_masters: "true"
      - remote_api: "http://185.3.211.53:8081"
      - remote_api_key: "api_Iu2ooyuoSee5zeihee5doeNgohPhir0f"
    url: "http://127.0.0.1:1026"

net:
  local_port: "no int"
"""

MOCK_CONFIG_IMPOSSIBLE_BATCH_SIZE = """
endpoints:
  pdns:
    headers:
      - check_masters: "true"
      - remote_api: "http://185.3.211.53:8081"
      - remote_api_key: "api_Iu2ooyuoSee5zeihee5doeNgohPhir0f"
    url: "http://127.0.0.1:1026"

general:
  event_batch_size: "no int"
"""

MOCK_CONFIG_IMPOSSIBLE_WORKERS = """
endpoints:
  pdns:
    headers:
      - check_masters: "true"
      - remote_api: "http://185.3.211.53:8081"
      - remote_api_key: "api_Iu2ooyuoSee5zeihee5doeNgohPhir0f"
    url: "http://127.0.0.1:1026"

general:
  workers: "no int"
"""

class TestConfigParser(unittest.TestCase):

    """
    Config parser tests
    """

    def setUp(self):
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
        logging.debug("setting up config test")

    def tearDown(self):
        logging.debug("ending test")

    def test_config(self):
        """
        Test if config parser output corresponds with mock config
        """
        logging.debug("test config parser with defaults")
        config = parser(MOCK_CONFIG_NO_DEFAULTS)
        self.assertTrue(len(config['endpoints']))
        self.assertTrue(config['endpoints']['pdns'])
        self.assertTrue(config['local_ip'] == "0.0.0.0")
        self.assertTrue(config['local_port'] == 5400)

    def test_config_defaults(self):
        """
        Test is config parser sets expected defaults
        """
        config = parser(MOCK_CONFIG_ONLY_DEFAULTS)
        self.assertTrue(config['local_ip'] == "127.0.0.1")
        self.assertTrue(config['local_port'] == 0)
        self.assertTrue(config['event_batch_size'] == 100)
        self.assertTrue(config['workers'] == 2)

    def test_config_fails(self):
        """
        Our config parser should raise a 'ConfigError' if 
        """
        try:
            config = parser(MOCK_CONFIG_IMPOSSIBLE_PORT)
            self.fail("wrong local_port value does not result in ConfigError")
        except server.ConfigError:
            pass
        try:
            config = parser(MOCK_CONFIG_IMPOSSIBLE_BATCH_SIZE)
            self.fail("wrong batch_size value does not result in ConfigError")
        except server.ConfigError:
            pass
        try:
            config = parser(MOCK_CONFIG_IMPOSSIBLE_WORKERS)
            self.fail("wrong worker value does not result in ConfigError")
        except server.ConfigError:
            pass


def parser(config_as_string):
    """
    Return config object based on string input
    """
    config_file = tempfile.mktemp()
    with open(config_file, 'w') as file_p:
        file_p.write(config_as_string)
    logging.debug("mock config written to %s", config_file)
    config = server.load_config(config_file)
    os.unlink(config_file)
    return config

if __name__ == '__main__':
    unittest.main()
