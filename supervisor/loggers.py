"""
Logger implementation loosely modeled on PEP 282.  We don't use the
PEP 282 logger implementation in the stdlib ('logging') because it's
idiosyncratic and a bit slow for our purposes (we don't use threads).
"""

# This module must not depend on any non-stdlib modules to
# avoid circular import problems

import os
import errno
import sys
import threading
import time
import traceback
from logging.handlers import SYSLOG_UDP_PORT
import socket

from supervisor.compat import syslog
from supervisor.compat import long
from supervisor.compat import is_text_stream
from supervisor.compat import as_string


class LevelsByName:
    CRIT = 50  # messages that probably require immediate user attention
    ERRO = 40  # messages that indicate a potentially ignorable error condition
    WARN = 30  # messages that indicate issues which aren't errors
    INFO = 20  # normal informational output
    DEBG = 10  # messages useful for users trying to debug configurations
    TRAC = 5  # messages useful to developers trying to debug plugins
    BLAT = 3  # messages useful for developers trying to debug supervisor


class LevelsByDescription:
    critical = LevelsByName.CRIT
    error = LevelsByName.ERRO
    warn = LevelsByName.WARN
    info = LevelsByName.INFO
    debug = LevelsByName.DEBG
    trace = LevelsByName.TRAC
    blather = LevelsByName.BLAT


def _levelNumbers():
    bynumber = {}
    for name, number in LevelsByName.__dict__.items():
        if not name.startswith('_'):
            bynumber[number] = name
    return bynumber


LOG_LEVELS_BY_NUM = _levelNumbers()


def getLevelNumByDescription(description):
    num = getattr(LevelsByDescription, description, None)
    return num


class Handler:
    lock = None
    fmt = '%(message)s'
    level = LevelsByName.INFO

    def __init__(self, stream=None):
        self.stream = stream
        self.closed = False

    def setFormat(self, fmt):
        self.fmt = fmt

    def setLevel(self, level):
        self.level = level

    def flush(self):
        try:
            self.stream.flush()
        except IOError as why:
            # if supervisor output is piped, EPIPE can be raised at exit
            if why.args[0] != errno.EPIPE:
                raise

    def close(self):
        if not self.closed:
            if hasattr(self.stream, 'fileno'):
                try:
                    fd = self.stream.fileno()
                except IOError:
                    # on python 3, io.IOBase objects always have fileno()
                    # but calling it may raise io.UnsupportedOperation
                    pass
                else:
                    if fd < 3:  # don't ever close stdout or stderr
                        return
            self.stream.close()
            self.closed = True

    def emit(self, record):
        try:
            binary = (self.fmt == '%(message)s' and
                      isinstance(record.msg, bytes) and
                      (not record.kw or record.kw == {'exc_info': None}))
            binary_stream = not is_text_stream(self.stream)
            if binary:
                msg = record.msg
            else:
                msg = self.fmt % record.asdict()
                if binary_stream:
                    msg = msg.encode('utf-8')
            try:
                self.stream.write(msg)
            except UnicodeError:
                # TODO sort out later
                # this only occurs because of a test stream type
                # which deliberately raises an exception the first
                # time it's called. So just do it again
                self.stream.write(msg)
            self.flush()
        except:
            self.handleError()

    def handleError(self):
        ei = sys.exc_info()
        traceback.print_exception(ei[0], ei[1], ei[2], None, sys.stderr)
        del ei


class StreamHandler(Handler):
    def __init__(self, strm=None):
        Handler.__init__(self, strm)

    def remove(self):
        if hasattr(self.stream, 'clear'):
            self.stream.clear()

    def reopen(self):
        pass


class BoundIO:
    def __init__(self, maxbytes, buf=b''):
        self.maxbytes = maxbytes
        self.buf = buf

    def flush(self):
        pass

    def close(self):
        self.clear()

    def write(self, b):
        blen = len(b)
        if len(self.buf) + blen > self.maxbytes:
            self.buf = self.buf[blen:]
        self.buf += b

    def getvalue(self):
        return self.buf

    def clear(self):
        self.buf = b''


class FileHandler(Handler):
    """File handler which supports reopening of logs.
    """

    def __init__(self, filename, mode='ab'):
        Handler.__init__(self)

        try:
            self.stream = open(filename, mode)
        except OSError as e:
            if mode == 'ab' and e.errno == errno.ESPIPE:
                # Python 3 can't open special files like
                # /dev/stdout in 'a' mode due to an implicit seek call
                # that fails with ESPIPE. Retry in 'w' mode.
                # See: http://bugs.python.org/issue27805
                mode = 'wb'
                self.stream = open(filename, mode)
            else:
                raise

        self.baseFilename = filename
        self.mode = mode

    def reopen(self):
        self.close()
        self.stream = open(self.baseFilename, self.mode)
        self.closed = False

    def remove(self):
        self.close()
        try:
            os.remove(self.baseFilename)
        except OSError as why:
            if why.args[0] != errno.ENOENT:
                raise


class RotatingFileHandler(FileHandler):
    def __init__(self, filename, mode='ab', maxBytes=512 * 1024 * 1024,
                 backupCount=10):
        """
        Open the specified file and use it as the stream for logging.

        By default, the file grows indefinitely. You can specify particular
        values of maxBytes and backupCount to allow the file to rollover at
        a predetermined size.

        Rollover occurs whenever the current log file is nearly maxBytes in
        length. If backupCount is >= 1, the system will successively create
        new files with the same pathname as the base file, but with extensions
        ".1", ".2" etc. appended to it. For example, with a backupCount of 5
        and a base file name of "app.log", you would get "app.log",
        "app.log.1", "app.log.2", ... through to "app.log.5". The file being
        written to is always "app.log" - when it gets filled up, it is closed
        and renamed to "app.log.1", and if files "app.log.1", "app.log.2" etc.
        exist, then they are renamed to "app.log.2", "app.log.3" etc.
        respectively.

        If maxBytes is zero, rollover never occurs.
        """
        if maxBytes > 0:
            mode = 'ab'  # doesn't make sense otherwise!
        FileHandler.__init__(self, filename, mode)
        self.maxBytes = maxBytes
        self.backupCount = backupCount
        self.counter = 0
        self.every = 10

    def emit(self, record):
        """
        Emit a record.

        Output the record to the file, catering for rollover as described
        in doRollover().
        """
        FileHandler.emit(self, record)
        self.doRollover()

    def _remove(self, fn):  # pragma: no cover
        # this is here to service stubbing in unit tests
        return os.remove(fn)

    def _rename(self, src, tgt):  # pragma: no cover
        # this is here to service stubbing in unit tests
        return os.rename(src, tgt)

    def _exists(self, fn):  # pragma: no cover
        # this is here to service stubbing in unit tests
        return os.path.exists(fn)

    def removeAndRename(self, sfn, dfn):
        if self._exists(dfn):
            try:
                self._remove(dfn)
            except OSError as why:
                # catch race condition (destination already deleted)
                if why.args[0] != errno.ENOENT:
                    raise
        try:
            self._rename(sfn, dfn)
        except OSError as why:
            # catch exceptional condition (source deleted)
            # E.g. cleanup script removes active log.
            if why.args[0] != errno.ENOENT:
                raise

    def doRollover(self):
        """
        Do a rollover, as described in __init__().
        """
        if self.maxBytes <= 0:
            return

        if not (self.stream.tell() >= self.maxBytes):
            return

        self.stream.close()
        if self.backupCount > 0:
            for i in range(self.backupCount - 1, 0, -1):
                sfn = "%s.%d" % (self.baseFilename, i)
                dfn = "%s.%d" % (self.baseFilename, i + 1)
                if os.path.exists(sfn):
                    self.removeAndRename(sfn, dfn)
            dfn = self.baseFilename + ".1"
            self.removeAndRename(self.baseFilename, dfn)
        self.stream = open(self.baseFilename, 'wb')


class LogRecord:
    def __init__(self, level, msg, **kw):
        self.level = level
        self.msg = msg
        self.kw = kw
        self.dictrepr = None

    def asdict(self):
        if self.dictrepr is None:
            now = time.time()
            msecs = (now - long(now)) * 1000
            part1 = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
            asctime = '%s,%03d' % (part1, msecs)
            levelname = LOG_LEVELS_BY_NUM[self.level]
            msg = as_string(self.msg)
            if self.kw:
                msg = msg % self.kw
            self.dictrepr = {'message': msg, 'levelname': levelname,
                             'asctime': asctime}
        return self.dictrepr


class Logger:
    def __init__(self, level=None, handlers=None):
        if level is None:
            level = LevelsByName.INFO
        self.level = level

        if handlers is None:
            handlers = []
        self.handlers = handlers

    def close(self):
        for handler in self.handlers:
            handler.close()

    def blather(self, msg, **kw):
        if LevelsByName.BLAT >= self.level:
            self.log(LevelsByName.BLAT, msg, **kw)

    def trace(self, msg, **kw):
        if LevelsByName.TRAC >= self.level:
            self.log(LevelsByName.TRAC, msg, **kw)

    def debug(self, msg, **kw):
        if LevelsByName.DEBG >= self.level:
            self.log(LevelsByName.DEBG, msg, **kw)

    def info(self, msg, **kw):
        if LevelsByName.INFO >= self.level:
            self.log(LevelsByName.INFO, msg, **kw)

    def warn(self, msg, **kw):
        if LevelsByName.WARN >= self.level:
            self.log(LevelsByName.WARN, msg, **kw)

    def error(self, msg, **kw):
        if LevelsByName.ERRO >= self.level:
            self.log(LevelsByName.ERRO, msg, **kw)

    def critical(self, msg, **kw):
        if LevelsByName.CRIT >= self.level:
            self.log(LevelsByName.CRIT, msg, **kw)

    def log(self, level, msg, **kw):
        record = LogRecord(level, msg, **kw)
        for handler in self.handlers:
            if level >= handler.level:
                handler.emit(record)

    def addHandler(self, hdlr):
        self.handlers.append(hdlr)

    def getvalue(self):
        raise NotImplementedError


level_to_syslog = {
    LevelsByName.CRIT: syslog.LOG_CRIT,
    LevelsByName.ERRO: syslog.LOG_ERR,
    LevelsByName.WARN: syslog.LOG_WARNING,
    LevelsByName.INFO: syslog.LOG_NOTICE,
    LevelsByName.DEBG: syslog.LOG_DEBUG,
}


class SyslogHandler(Handler):
    LOG_EMERG = 0  # system is unusable
    LOG_ALERT = 1  # action must be taken immediately
    LOG_CRIT = 2  # critical conditions
    LOG_ERR = 3  # error conditions
    LOG_WARNING = 4  # warning conditions
    LOG_NOTICE = 5  # normal but significant condition
    LOG_INFO = 6  # informational
    LOG_DEBUG = 7  # debug-level messages

    #  facility codes
    LOG_KERN = 0  # kernel messages
    LOG_USER = 1  # random user-level messages
    LOG_MAIL = 2  # mail system
    LOG_DAEMON = 3  # system daemons
    LOG_AUTH = 4  # security/authorization messages
    LOG_SYSLOG = 5  # messages generated internally by syslogd
    LOG_LPR = 6  # line printer subsystem
    LOG_NEWS = 7  # network news subsystem
    LOG_UUCP = 8  # UUCP subsystem
    LOG_CRON = 9  # clock daemon
    LOG_AUTHPRIV = 10  # security/authorization messages (private)
    LOG_FTP = 11  # FTP daemon

    #  other codes through 15 reserved for system use
    LOG_LOCAL0 = 16  # reserved for local use
    LOG_LOCAL1 = 17  # reserved for local use
    LOG_LOCAL2 = 18  # reserved for local use
    LOG_LOCAL3 = 19  # reserved for local use
    LOG_LOCAL4 = 20  # reserved for local use
    LOG_LOCAL5 = 21  # reserved for local use
    LOG_LOCAL6 = 22  # reserved for local use
    LOG_LOCAL7 = 23  # reserved for local use

    priority_names = {
        "alert": LOG_ALERT,
        "crit": LOG_CRIT,
        "critical": LOG_CRIT,
        "debug": LOG_DEBUG,
        "emerg": LOG_EMERG,
        "err": LOG_ERR,
        "error": LOG_ERR,  # DEPRECATED
        "info": LOG_INFO,
        "notice": LOG_NOTICE,
        "panic": LOG_EMERG,  # DEPRECATED
        "warn": LOG_WARNING,  # DEPRECATED
        "warning": LOG_WARNING,
    }

    facility_names = {
        "auth": LOG_AUTH,
        "authpriv": LOG_AUTHPRIV,
        "cron": LOG_CRON,
        "daemon": LOG_DAEMON,
        "ftp": LOG_FTP,
        "kern": LOG_KERN,
        "lpr": LOG_LPR,
        "mail": LOG_MAIL,
        "news": LOG_NEWS,
        "security": LOG_AUTH,  # DEPRECATED
        "syslog": LOG_SYSLOG,
        "user": LOG_USER,
        "uucp": LOG_UUCP,
        "local0": LOG_LOCAL0,
        "local1": LOG_LOCAL1,
        "local2": LOG_LOCAL2,
        "local3": LOG_LOCAL3,
        "local4": LOG_LOCAL4,
        "local5": LOG_LOCAL5,
        "local6": LOG_LOCAL6,
        "local7": LOG_LOCAL7,
    }

    # The map below appears to be trivially lowercasing the key. However,
    # there's more to it than meets the eye - in some locales, lowercasing
    # gives unexpected results. See SF #1524081: in the Turkish locale,
    # "INFO".lower() != "info"
    priority_map = {
        "DEBUG": "debug",
        "INFO": "info",
        "WARNING": "warning",
        "ERROR": "error",
        "CRITICAL": "critical"
    }

    SYSLOG_UDP_PORT_UNPRVL = 1514

    def __init__(self, tag=None, pid=False, facility="daemon", priority=None,
                 address=('localhost', SYSLOG_UDP_PORT_UNPRVL), socktype=None):
        Handler.__init__(self)
        self.tag = tag or "supervisord"

        def _int_string_or_none(val):
            return val if isinstance(val, (int, type(None))) else (
                getattr(syslog, "LOG_" + val.upper(), None)
            )

        self.address = address
        self.socktype = socktype
        self.priority = _int_string_or_none(priority)
        self.facility = _int_string_or_none(facility)
        self.options = syslog.LOG_PID if pid else 0
        if isinstance(address, str):
            self.unixsocket = True
            # Syslog server may be unavailable during handler initialisation.
            # C's openlog() function also ignores connection errors.
            # Moreover, we ignore these errors while logging, so it not worse
            # to ignore it also here.
            try:
                self._connect_unixsocket(address)
            except OSError:
                pass
        else:
            self.unixsocket = False
            if socktype is None:
                socktype = socket.SOCK_DGRAM
            host, port = address
            ress = socket.getaddrinfo(host, port, 0, socktype)
            if not ress:
                raise OSError("getaddrinfo returns an empty list")
            for res in ress:
                af, socktype, proto, _, sa = res
                err = sock = None
                try:
                    sock = socket.socket(af, socktype, proto)
                    if socktype == socket.SOCK_STREAM:
                        sock.connect(sa)
                    break
                except OSError as exc:
                    err = exc
                    if sock is not None:
                        sock.close()
            if err is not None:
                raise err
            self.socket = sock
            self.socktype = socktype

    def _connect_unixsocket(self, address):
        use_socktype = self.socktype
        if use_socktype is None:
            use_socktype = socket.SOCK_DGRAM
        self.socket = socket.socket(socket.AF_UNIX, use_socktype)
        try:
            self.socket.connect(address)
            # it worked, so set self.socktype to the used type
            self.socktype = use_socktype
        except OSError:
            self.socket.close()
            if self.socktype is not None:
                # user didn't specify falling back, so fail
                raise
            use_socktype = socket.SOCK_STREAM
            self.socket = socket.socket(socket.AF_UNIX, use_socktype)
            try:
                self.socket.connect(address)
                # it worked, so set self.socktype to the used type
                self.socktype = use_socktype
            except OSError:
                self.socket.close()
                raise

    def encodePriority(self, facility, priority):
        """
        Encode the facility and priority. You can pass in strings or
        integers - if strings are passed, the facility_names and
        priority_names mapping dictionaries are used to convert them to
        integers.
        """
        if isinstance(facility, str):
            facility = self.facility_names[facility]
        if isinstance(priority, str):
            priority = self.priority_names[priority]
        return (facility << 3) | priority

    def acquire(self):
        """
        Acquire the I/O thread lock.
        """
        if self.lock:
            self.lock.acquire()

    def release(self):
        """
        Release the I/O thread lock.
        """
        if self.lock:
            self.lock.release()

    def close(self):
        """
        Closes the socket.
        """
        self.acquire()
        try:
            self.socket.close()
        finally:
            self.release()
            self.closed = True

    def mapPriority(self, levelName):
        """
        Map a logging level name to a key in the priority_names map.
        This is useful in two scenarios: when custom levels are being
        used, and in the case where you can't do a straightforward
        mapping by lowercasing the logging level name because of locale-
        specific issues (see SF #1524081).
        """
        return self.priority_map.get(levelName, "warning")

    append_nul = False  # some old syslog daemons expect a NUL terminator

    def reopen(self):
        pass

    def _syslog(self, priority, msg):  # pragma: no cover
        if self.tag:
            msg = self.tag + ' ' + msg
        if self.append_nul:
            msg += '\000'
        # We need to convert record level to lowercase, maybe this will
        # change in the future.
        prio = '<%d> ' % self.encodePriority(self.facility,
                                             priority)
        prio = prio.encode('utf-8')
        # Message is a string. Convert to bytes as required by RFC 5424
        msg = msg.encode('utf-8')
        msg = prio + msg
        if self.unixsocket:
            try:
                self.socket.send(msg)
            except OSError:
                self.socket.close()
                self._connect_unixsocket(self.address)
                self.socket.send(msg)
        elif self.socktype == socket.SOCK_DGRAM:
            self.socket.sendto(msg, self.address)
        else:
            self.socket.sendall(msg)

    def emit(self, record):
        try:
            params = record.asdict()
            priority = self.priority or level_to_syslog.get(
                record.level, syslog.LOG_WARNING
            )
            message = params['message']

            # syslog.openlog(self.tag, self.options, self.facility)
            for line in message.rstrip('\n').split('\n'):
                params['message'] = line
                msg = self.fmt % params
                try:
                    self._syslog(priority, msg)
                except UnicodeError:
                    self._syslog(priority, msg.encode("UTF-8"))
        except:
            self.handleError()


def getLogger(level=None):
    return Logger(level)


_2MB = 1 << 21


def handle_boundIO(logger, fmt, maxbytes=_2MB):
    """Attach a new BoundIO handler to an existing Logger"""
    io = BoundIO(maxbytes)
    handler = StreamHandler(io)
    handler.setLevel(logger.level)
    handler.setFormat(fmt)
    logger.addHandler(handler)
    logger.getvalue = io.getvalue


def handle_stdout(logger, fmt):
    """Attach a new StreamHandler with stdout handler to an existing Logger"""
    handler = StreamHandler(sys.stdout)
    handler.setFormat(fmt)
    handler.setLevel(logger.level)
    logger.addHandler(handler)


def handle_syslog(logger, fmt, tag=None, show_pid=None, facility=None,
                  priority=None):
    handler = SyslogHandler(tag, show_pid, facility, priority)
    handler.setFormat(fmt)
    handler.setLevel(logger.level)
    logger.addHandler(handler)


def handle_file(logger, filename, fmt, rotating=False, maxbytes=0, backups=0):
    """Attach a new file handler to an existing Logger. If the filename
    is the magic name of 'syslog' then make it a syslog handler instead."""
    if filename == 'syslog':  # TODO remove this
        handler = SyslogHandler()
    else:
        if rotating is False:
            handler = FileHandler(filename)
        else:
            handler = RotatingFileHandler(filename, 'a', maxbytes, backups)
    handler.setFormat(fmt)
    handler.setLevel(logger.level)
    logger.addHandler(handler)
