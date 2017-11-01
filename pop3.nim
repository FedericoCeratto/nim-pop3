#
## Nim POP3 client library
#
# https://tools.ietf.org/html/rfc1939
#
# This software is licensed under LGPLv3, see LICENSE
# Federico Ceratto <federico.ceratto@gmail.com>

## Usage:
## let c = newPOP3Client(host="pop.gmail.com")
##
## c.user("<email_addr>")
## c.pass("<password>")
## echo c.list()
## echo c.list(msg_num=1)
## echo c.retr(msg_num=1).body
## c.quit()

# TODO: implement key/cert
#          keyfile - PEM formatted file that contains your private key
#          certfile - PEM formatted certificate chain file

import logging
import net
import strutils
import tables

const
  DEFAULT_PORT = 110.Port
  DEFAULT_SSL_PORT = 995.Port
  DEFAULT_TIMEOUT = 30
  CRLF = "\x0D\x0A"

when not defined(ssl):
  type SSLContext = ref object
  let defaultSSLContext: SSLContext = nil
else:
  let defaultSSLContext = newContext(verifyMode = CVerifyNone)

proc error_proto(msg: string): ref IOError =
  return newException(IOError, msg)


type
  POP3Client* = ref object of RootObj
    greeting_banner: string
    host: string
    port: Port
    sock: Socket
    use_tls: bool

  POP3Response = tuple[status: string, body: seq[string]]

proc get_resp(self: POP3Client): POP3Response

proc connect(self: POP3Client, host:string, port:Port, use_ssl=true) =
  self.sock = newSocket()
  when not defined(ssl):
    if use_ssl:
      raise newException(Exception, "SSL support required")

  if use_ssl:
    logging.debug "connecting with SSL to $#:$#" % [$host, $port]

    when defined(ssl):
      defaultSSLContext.wrapSocket(self.sock)

  else:
    logging.debug "connecting without SSL to $#:$#" % [$host, $port]

  self.sock.connect(address=host, port=port)
  debug "get ban"
  self.greeting_banner = self.get_resp().status


proc newPOP3Client*(host:string, port=0.Port, use_ssl=true, timeout=DEFAULT_TIMEOUT): POP3Client =
  new(result)
  let dport =
    if port == 0.Port:
      if use_ssl: DEFAULT_SSL_PORT else: DEFAULT_PORT
    else:
      port

  result.connect(host, dport, use_ssl)

proc getline(self: POP3Client): TaintedString =
  ## Fetch one line
  result = ""
  self.sock.readline(result)
  if len(result) == 0:
    raise newException(IOError, "-ERR EOF")

proc get_resp(self: POP3Client): POP3Response =
  ## Fetch a 1-line POP3 response
  ## Raise an exception if the response contains a failure code
  let line = self.getline()
  if not line.startswith("+OK"):
    raise error_proto(line)

  result = (line[3..<len(line)].strip(), @[])
  logging.debug "short resp: '$#'" % [line]

proc get_long_resp(self: POP3Client): POP3Response  =
  ## Fetch a multiline POP3 response
  ## Raise an exception if the response contains a failure code
  result = self.get_resp()
  while true:
    var line = self.getline()
    if line.startswith(".."):
      line = line[1..<len(line)]
    elif line == ".":
      break
    result.body.add("$#" % line)

  logging.debug "long resp: $#" % [$result.status]

proc short_cmd(self: POP3Client, line: string): POP3Response =
  logging.debug "short cmd: '$#'" % line
  self.sock.send(line)
  self.sock.send(CRLF)
  return self.get_resp()

proc long_cmd(self: POP3Client, line: string): POP3Response =
  logging.debug "long cmd: '$#'" % line
  self.sock.send(line)
  self.sock.send(CRLF)
  return self.get_long_resp()

proc user*(self: POP3Client, user: string): POP3Response {.discardable.} =
  ## USER, send the user name
  return self.short_cmd("USER $#" % user)

proc pass*(self: POP3Client, pwd: string): POP3Response {.discardable.} =
  ## PASS, send the password
  return self.short_cmd("PASS $#" % pwd)

type Stat = tuple[numMessages, sizeMessages: int]

proc stat*(self: POP3Client): Stat =
  ## STAT, Get mailbox status
  let retval = self.short_cmd("STAT")
  let rets = retval.status.split()
  return (rets[0].parseInt, rets[1].parseInt)

proc list*(self: POP3Client, msg_num:int=0): tuple =
  ## LIST, request mailbox listing
  if msg_num == 0:
    return self.long_cmd("LIST")

  return self.short_cmd("LIST $#" % $msg_num)

proc retr*(self: POP3Client, msg_num: int): POP3Response =
  ## RETR, retrieve a message
  return self.long_cmd("RETR $#" % $msg_num)

proc dele*(self: POP3Client, msg_num: int): POP3Response {.discardable.} =
  ## DELE, delete a message
  return self.short_cmd("DELE $#" % $msg_num)

proc noop*(self: POP3Client): POP3Response {.discardable.} =
  ## NOOP, do nothing
  return self.short_cmd("NOOP")

proc rset*(self: POP3Client): POP3Response {.discardable.} =
  ## RSET, unmark messages marked for deletion
  return self.short_cmd("RSET")

proc quit*(self: POP3Client): POP3Response {.discardable.} =
  ## QUIT, commit changes, unlock mailbox and close connection
  let resp = self.short_cmd("QUIT")
  self.sock.close()
  return resp

proc apop(self: POP3Client, user, password: string): POP3Response =
  ## APOP authentication
  # use PEGS
  # FIXME
  discard """
  peg"\+OK.*(<[^>]+>)"
  m = self.timestamp.match(self.greeting_banner)
  if not m:
      raise error_proto("-ERR APOP not supported by server")
  import hashlib
  digest = m.group(1)+secret
  digest = hashlib.md5(digest).hexdigest()
  return self.short_cmd("APOP $# $#" % (user, digest))
  """

proc top*(self: POP3Client, msg_num:int, max_lines:int): POP3Response =
  ## TOP, retrieve lines from a message up to max_lines
  return self.long_cmd("TOP $# $#" % [$msg_num, $max_lines])

proc uidl*(self: POP3Client, msg_num: int): POP3Response =
  ## UIDL, return message digest
  return self.short_cmd("UIDL $#" % $msg_num)

proc list_uidl*(self: POP3Client): POP3Response =
  ## UIDL, return message digests
  return self.long_cmd("UIDL")

proc capa*(self: POP3Client): seq[string] =
  ## CAPA, return server capabilities
  let resp = self.long_cmd("CAPA")
  return resp.body
