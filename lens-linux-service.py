#!/usr/bin/env python

import sys
import time
import daemon
import lens

ln = lens.load_source('Lens', './src/Lens.py')
dm = daemon.load_source('Daemon', './src/Daemon.py')

class LensDaemon(dm.Daemon):
    def init(self):
        print "init in LensDaemon calling super class init"
        # Get lens config from environment variable or fail
        self.lens = ln.Lens()

    def run(self):
        while True:
            time.sleep(10)
            self.lens.analyze()


if __name__ == "__main__":
    print "instantiating LensDaemon!"
    daemon = LensDaemon('/tmp/daemon-example.pid')
    daemon.init()
    print "instatiation complete"
    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            print "starting..."
            daemon.start()
        elif 'stop' == sys.argv[1]:
            daemon.stop()
        elif 'restart' == sys.argv[1]:
            daemon.restart()
        else:
            print "Unknown command"
            sys.exit(2)
        sys.exit(0)

    else:
        print "usage: %s start|stop|restart" % sys.argv[0]
        sys.exit(2)
