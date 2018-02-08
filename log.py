#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import logging
import logging.handlers

__all__ = [
    'getLogger', 'log',
]

_msgtype_prefixes = {
  'status'       : 'x',
  'success'      : '+',
  'failure'      : '-',
  'debug'        : 'DEBUG',
  'info'         : '*',
  'warning'      : '!',
  'error'        : 'ERROR',
  'exception'    : 'ERROR',
  'critical'     : 'CRITICAL',
  'info_once'    : '*',
  'warning_once' : '!',
  }

class Logger(object):
  """
  A class akin to the :class:`logging.LoggerAdapter` class.  All public
  methods defined on :class:`logging.Logger` instances are defined on this
  class.
  Adds ``mypwn``-specific information for coloring, indentation and progress
  logging via log records ``extra`` field.
  Loggers instantiated with :func:`getLogger` will be of this class.
  """
  _one_time_infos    = set()
  _one_time_warnings = set()

  def __init__(self, logger=None):
    if logger is None:
      logger = logging.getLogger('mypwn')
    self._logger = logger

  def _getlevel(self, levelString):
    if isinstance(levelString, int):
      return levelString
    return logging._levelNames[levelString.upper()]

  def _log(self, level, msg, args, kwargs, msgtype):
    extra = kwargs.get('extra', {})
    extra.setdefault('mypwn_msgtype', msgtype)
    kwargs['extra'] = extra
    self._logger.log(level, msg, *args, **kwargs)

  def indented(self, message, *args, **kwargs):
    """indented(message, *args, level = logging.INFO, **kwargs)
    Log a message but don't put a line prefix on it.
    Arguments:
      level(int): Alternate log level at which to set the indented
            message.  Defaults to :const:`logging.INFO`.
    """
    level = self._getlevel(kwargs.pop('level', logging.INFO))
    self._log(level, message, args, kwargs, 'indented')

  def success(self, message, *args, **kwargs):
    """success(message, *args, **kwargs)
    Logs a success message.
    """
    self._log(logging.INFO, message, args, kwargs, 'success')

  def failure(self, message, *args, **kwargs):
    """failure(message, *args, **kwargs)
    Logs a failure message.
    """
    self._log(logging.INFO, message, args, kwargs, 'failure')

  def info_once(self, message, *args, **kwargs):
    """info_once(message, *args, **kwargs)
    Logs an info message.  The same message is never printed again.
    """
    m = message % args
    if m not in self._one_time_infos:
      if self.isEnabledFor(logging.INFO):
        self._one_time_infos.add(m)
      self._log(logging.INFO, message, args, kwargs, 'info_once')

  def warning_once(self, message, *args, **kwargs):
    """warning_once(message, *args, **kwargs)
    Logs a warning message.  The same message is never printed again.
    """
    m = message % args
    if m not in self._one_time_warnings:
      if self.isEnabledFor(logging.INFO):
        self._one_time_warnings.add(m)
      self._log(logging.WARNING, message, args, kwargs, 'warning_once')

  def warn_once(self, *args, **kwargs):
    """Alias for :meth:`warning_once`."""
    return self.warning_once(*args, **kwargs)

  # logging functions also exposed by `logging.Logger`

  def debug(self, message, *args, **kwargs):
    """debug(message, *args, **kwargs)
    Logs a debug message.
    """
    self._log(logging.DEBUG, message, args, kwargs, 'debug')

  def info(self, message, *args, **kwargs):
    """info(message, *args, **kwargs)
    Logs an info message.
    """
    self._log(logging.INFO, message, args, kwargs, 'info')

  def hexdump(self, message, *args, **kwargs):
    pass

  def warning(self, message, *args, **kwargs):
    """warning(message, *args, **kwargs)
    Logs a warning message.
    """
    self._log(logging.WARNING, message, args, kwargs, 'warning')

  def warn(self, *args, **kwargs):
    """Alias for :meth:`warning`."""
    return self.warning(*args, **kwargs)

  def error(self, message, *args, **kwargs):
    """error(message, *args, **kwargs)
    To be called outside an exception handler.
    Logs an error message, then raises a ``Exception``.
    """
    self._log(logging.ERROR, message, args, kwargs, 'error')
    raise Exception(message % args)

  def exception(self, message, *args, **kwargs):
    """exception(message, *args, **kwargs)
    To be called from an exception handler.
    Logs a error message, then re-raises the current exception.
    """
    kwargs["exc_info"] = 1
    self._log(logging.ERROR, message, args, kwargs, 'exception')
    raise

  def critical(self, message, *args, **kwargs):
    """critical(message, *args, **kwargs)
    Logs a critical message.
    """
    self._log(logging.CRITICAL, message, args, kwargs, 'critical')

  def log(self, level, message, *args, **kwargs):
    """log(level, message, *args, **kwargs)
    Logs a message with log level `level`.  The ``mypwn`` formatter will
    use the default :mod:`logging` formater to format this message.
    """
    self._log(level, message, args, kwargs, None)

  def isEnabledFor(self, level):
    """isEnabledFor(level) -> bool
    See if the underlying logger is enabled for the specified level.
    """
    effectiveLevel = self._logger.getEffectiveLevel()

    if effectiveLevel == 1:
      effectiveLevel = context.log_level
    return effectiveLevel <= level

  def setLevel(self, level):
    """setLevel(level)
    Set the logging level for the underlying logger.
    """
    with context.local(log_level=level):
      self._logger.setLevel(context.log_level)

  def addHandler(self, handler):
    """addHandler(handler)
    Add the specified handler to the underlying logger.
    """
    self._logger.addHandler(handler)

  def removeHandler(self, handler):
    """removeHandler(handler)
    Remove the specified handler from the underlying logger.
    """
    self._logger.removeHandler(handler)

  @property
  def level(self):
    return self._logger.level
  @level.setter
  def level(self, value):
    with context.local(log_level=value):
      self._logger.level = context.log_level


class Formatter(logging.Formatter):
  """
  Logging formatter which performs custom formatting for log records
  containing the ``'mypwn_msgtype'`` attribute.  Other records are formatted
  using the `logging` modules default formatter.
  If ``'mypwn_msgtype'`` is set, it performs the following actions:
  * A prefix looked up in `_msgtype_prefixes` is prepended to the message.
  * The message is prefixed such that it starts on column four.
  * If the message spans multiple lines they are split, and all subsequent
    lines are indented.
  This formatter is used by the handler installed on the ``'mypwn'`` logger.
  """

  # Indentation from the left side of the terminal.
  # All log messages will be indented at list this far.
  indent    = '    '

  # Newline, followed by an indent.  Used to wrap multiple lines.
  nlindent  = '\n' + indent

  def format(self, record):
    # use the default formatter to actually format the record
    msg = super(Formatter, self).format(record)

    # then put on a prefix symbol according to the message type

    msgtype = getattr(record, 'mypwn_msgtype', None)

    # if 'mypwn_msgtype' is not set (or set to `None`) we just return the
    # message as it is
    if msgtype is None:
      return msg

    if msgtype in _msgtype_prefixes:
      symb = _msgtype_prefixes[msgtype]
      prefix = '[%s] ' % symb
    elif msgtype == 'indented':
      prefix = self.indent
    elif msgtype == 'animated':
      # the handler will take care of updating the spinner, so we will
      # not include it here
      prefix = ''
    else:
      # this should never happen
      prefix = '[?] '

    msg = prefix + msg
    msg = self.nlindent.join(msg.splitlines())
    return msg


def getLogger(name='root', loglevel='INFO'):
  logger = logging.getLogger(name)

  # if logger 'name' already exists, return it to avoid logging duplicate
  # messages by attaching multiple handlers of the same type
  if logger.handlers:
    return logger
  # if logger 'name' does not already exist, create it and attach handlers
  else:
    # set logLevel to loglevel or to INFO if requested level is incorrect
    loglevel = getattr(logging, loglevel.upper(), logging.INFO)
    logger.setLevel(loglevel)

    handler = logging.StreamHandler()
    formatter = Formatter()
    handler.setFormatter(formatter)
    logger.addHandler(handler)

  return Logger(logger)

log = getLogger('mypwn')
