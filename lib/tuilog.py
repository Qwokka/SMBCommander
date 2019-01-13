#!/usr/bin/env python
#
# Author: Jack Baker (https://github.com/qwokka/smbcommander)
#
# This product includes software developed by
# SecureAuth Corporation (https://www.secureauth.com/)."
#

import logging
import utils

LOG_COLOR_INFO      = 5
LOG_COLOR_WARN      = 4
LOG_COLOR_ERR       = 2
LOG_COLOR_SUCCESS   = 3
LOG_COLOR_DEBUG     = 4

class TUILogFormatter(logging.Formatter):
    def __init__(self):
        logging.Formatter.__init__(self,'%(bullet)s %(message)s', None)

    def format(self, record):
        if record.levelno == logging.INFO:
            record.bullet = '[*]'
        elif record.levelno == logging.WARNING:
            record.bullet = '[!]'
        elif record.levelno == logging.DEBUG:
            record.bullet = '[*]'
        else:
            record.bullet = '[+]'

        return logging.Formatter.format(self, record)

# This handler is meant to funnel Impacket output into the curses UI without
# having to change all the libraries manually
class CursesLogHandler(logging.Handler):
    def __init__(self, stdout, debug=False):
        logging.Handler.__init__(self)
        self.stdout = stdout
        self.debug  = debug

    def emit(self, record):
        msg = self.format(record)

        if record.levelno == logging.INFO:
            color = LOG_COLOR_INFO
        elif record.levelno == logging.WARNING:
            color = LOG_COLOR_WARN
        elif record.levelno == logging.ERROR:
            color = LOG_COLOR_ERR
        elif record.levelno == logging.CRITICAL:
            color = LOG_COLOR_ERR
        elif record.levelno == logging.DEBUG:
            if not utils.commander.debug:
                return
            color = LOG_COLOR_DEBUG
        else:
            color = LOG_COLOR_SUCCESS

        self.stdout.write(msg, color=color)
