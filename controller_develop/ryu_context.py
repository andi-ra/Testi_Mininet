"""
   File che uso per creare e testare che tutto vada bene nell'iniezione dei miei moduli
   questo e' il file che usato nella fase esplorativa per sapere se potevo iniettare il
   mio modulo. In realta' creo un nuovo file (simil-ryu simple_switch) e poi lo testo
"""

# SPIKING FILE

from cStringIO import StringIO  # Python3 use: from io import StringIO
import sys

from ryu.lib import hub

hub.patch(thread=False)

import logging
from ryu import log

log.early_init_log(logging.DEBUG)
from ryu.base.app_manager import AppManager

mypath = "/var/log/"


def main():
    log.init_log()
    logger = logging.getLogger(__name__)

    app_lists = ['ryu.app.simple_switch_Dulla']

    app_mgr = AppManager.get_instance()
    app_mgr.load_apps(app_lists)
    contexts = app_mgr.create_contexts()
    services = []
    services.extend(app_mgr.instantiate_apps(**contexts))
    app_mgr.close()

    output = new_stderr.getvalue()
    # print(output)
    if "RANDOM" in output:
        print("Trovato")
    sys.stderr = old_stderr


if __name__ == "__main__":
    old_stderr = sys.stderr
    new_stderr = StringIO()
    sys.stderr = new_stderr
    main()
