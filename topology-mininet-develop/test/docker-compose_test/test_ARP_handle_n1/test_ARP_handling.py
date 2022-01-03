# Questo file di test ci metto i test della classe ch eho creato per la gestione
# articolare dei pacchetti ARP
import contextlib

from cStringIO import StringIO  # Python3 use: from io import StringIO
import logging
import sys
import unittest

from ryu import log
from ryu.base.app_manager import AppManager
from ryu.lib import hub


@contextlib.contextmanager
def nostderr():
    global new_stderr
    old_stderr = sys.stderr
    new_stderr = StringIO()
    sys.stderr = new_stderr
    try:
        yield
    finally:
        sys.stderr = old_stderr


class MyTestCase(unittest.TestCase):
    def setUp(self):
        hub.patch(thread=False)

    def test_INIT_string_is_present(self):
        app_lists = ['ryu.app.simple_switch_Dulla']
        global app_mgr
        with nostderr():
            global new_stderr
            log.early_init_log(logging.DEBUG)
            log.init_log()
            logger = logging.getLogger(__name__)
            app_mgr = AppManager.get_instance()
            app_mgr.load_apps(app_lists)
            contexts = app_mgr.create_contexts()
            services = []
            services.extend(app_mgr.instantiate_apps(**contexts))
            output = new_stderr.getvalue()
        self.assertTrue("RANDOM" in output)

    def tearDown(self):
        app_mgr.close()


if __name__ == '__main__':
    unittest.main()
