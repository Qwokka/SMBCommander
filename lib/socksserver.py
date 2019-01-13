#!/usr/bin/env python
#
# Author: Jack Baker (https://github.com/qwokka/smbcommander)
#
# This product includes software developed by
# SecureAuth Corporation (https://www.secureauth.com/)."
#

import logging
import socket
import SocketServer

from struct import unpack, pack

from impacket.dcerpc.v5.enum import Enum
from impacket.examples.ntlmrelayx.servers.socksplugins import SOCKS_RELAYS
from impacket.structure import Structure

class replyField(Enum):
    SUCCEEDED             = 0
    SOCKS_FAILURE         = 1
    NOT_ALLOWED           = 2
    NETWORK_UNREACHABLE   = 3
    HOST_UNREACHABLE      = 4
    CONNECTION_REFUSED    = 5
    TTL_EXPIRED           = 6
    COMMAND_NOT_SUPPORTED = 7
    ADDRESS_NOT_SUPPORTED = 8

class ATYP(Enum):
    IPv4 = 1
    DOMAINNAME = 3
    IPv6 = 4

class SOCKS5_GREETINGS(Structure):
    structure = (
        ('VER','B=5'),
        #('NMETHODS','B=0'),
        ('METHODS','B*B'),
    )


class SOCKS5_GREETINGS_BACK(Structure):
    structure = (
        ('VER','B=5'),
        ('METHODS','B=0'),
    )

class SOCKS5_REQUEST(Structure):
    structure = (
        ('VER','B=5'),
        ('CMD','B=0'),
        ('RSV','B=0'),
        ('ATYP','B=0'),
        ('PAYLOAD',':'),
    )

class SOCKS5_REPLY(Structure):
    structure = (
        ('VER','B=5'),
        ('REP','B=5'),
        ('RSV','B=0'),
        ('ATYP','B=1'),
        ('PAYLOAD',':="AAAAA"'),
    )

class SOCKS4_REQUEST(Structure):
    structure = (
        ('VER','B=4'),
        ('CMD','B=0'),
        ('PORT','>H=0'),
        ('ADDR','4s="'),
        ('PAYLOAD',':'),
    )

class SOCKS4_REPLY(Structure):
    structure = (
        ('VER','B=0'),
        ('REP','B=0x5A'),
        ('RSV','<H=0'),
        ('RSV','<L=0'),
    )

class SocksRequestHandler(SocketServer.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.__socksServer = server
        self.__ip, self.__port = client_address
        self.__connSocket= request
        self.__socksVersion = 5
        self.targetHost = None
        self.targetPort = None
        self.__NBSession= None
        SocketServer.BaseRequestHandler.__init__(self, request, client_address, server)

    def sendReplyError(self, error = replyField.CONNECTION_REFUSED):

        if self.__socksVersion == 5:
            reply = SOCKS5_REPLY()
            reply['REP'] = error.value
        else:
            reply = SOCKS4_REPLY()
            if error.value != 0:
                reply['REP'] = 0x5B
        return self.__connSocket.sendall(reply.getData())

    def handle(self):
        logging.debug("SOCKS: New Connection from %s(%s)", self.__ip, self.__port)

        data = self.__connSocket.recv(8192)
        grettings = SOCKS5_GREETINGS_BACK(data)
        self.__socksVersion = grettings['VER']

        if self.__socksVersion == 5:
            # We need to answer back with a no authentication response. We're not dealing
            # with auth for now
            self.__connSocket.sendall(str(SOCKS5_GREETINGS_BACK()))
            data = self.__connSocket.recv(8192)
            request = SOCKS5_REQUEST(data)
        else:
            # We're in version 4, we just received the request
            request = SOCKS4_REQUEST(data)

        # Let's process the request to extract the target to connect.
        # SOCKS5
        if self.__socksVersion == 5:
            if request['ATYP'] == ATYP.IPv4.value:
                self.targetHost = socket.inet_ntoa(request['PAYLOAD'][:4])
                self.targetPort = unpack('>H',request['PAYLOAD'][4:])[0]
            elif request['ATYP'] == ATYP.DOMAINNAME.value:
                hostLength = unpack('!B',request['PAYLOAD'][0])[0]
                self.targetHost = request['PAYLOAD'][1:hostLength+1]
                self.targetPort = unpack('>H',request['PAYLOAD'][hostLength+1:])[0]
            else:
                logging.error('No support for IPv6 yet!')
        # SOCKS4
        else:
            self.targetPort = request['PORT']

            # SOCKS4a
            if request['ADDR'][:3] == "\x00\x00\x00" and request['ADDR'][3] != "\x00":
                nullBytePos = request['PAYLOAD'].find("\x00")

                if nullBytePos == -1:
                    logging.error('Error while reading SOCKS4a header!')
                else:
                    self.targetHost = request['PAYLOAD'].split('\0', 1)[1][:-1]
            else:
                self.targetHost = socket.inet_ntoa(request['ADDR'])

        logging.debug('SOCKS: Target is %s(%s)', self.targetHost, self.targetPort)

        # Format the list of matching clients the way the SocksRelay classes expect it
        clients = {}
        clients[self.targetHost] = {}
        clients[self.targetHost][self.targetPort] = {}

        if self.targetPort != 53:
            matches = 0

            for cli in self.__socksServer.commander.clients:
                if cli is None:
                    continue

                if cli.targetHost == self.targetHost and \
                   cli.targetPort == self.targetPort:
                    info = {
                        'protocolClient':   cli,
                        'inUse':            False,
                        'data':             cli.data
                    }

                    username = ("%s/%s" % (cli.domain, cli.username)).upper()
                    scheme = cli.scheme
                    data = cli.data

                    clients[self.targetHost][self.targetPort][username] = info
                    clients[self.targetHost][self.targetPort]['scheme'] = scheme
                    clients[self.targetHost][self.targetPort]['data']   = data

                    matches += 1

            if matches == 0:
                logging.error("SOCKS: Don't have a relay for %s(%s)",
                              self.targetHost,
                              self.targetPort)
                self.sendReplyError(replyField.CONNECTION_REFUSED)
                return
        else:
            # TODO Not tested. Probably doesn't work

            # Somebody wanting a DNS request. Should we handle this?
            s = socket.socket()
            try:
                logging.debug('SOCKS: Connecting to %s(%s)', self.targetHost, self.targetPort)
                s.connect((self.targetHost, self.targetPort))
            except Exception, e:
                logging.error('SOCKS: %s', str(e))
                self.sendReplyError(replyField.CONNECTION_REFUSED)
                return

            if self.__socksVersion == 5:
                reply = SOCKS5_REPLY()
                reply['REP'] = replyField.SUCCEEDED.value
                addr, port = s.getsockname()
                reply['PAYLOAD'] = socket.inet_aton(addr) + pack('>H', port)
            else:
                reply = SOCKS4_REPLY()

            self.__connSocket.sendall(reply.getData())

            while True:
                try:
                    data = self.__connSocket.recv(8192)
                    if data == '':
                        break
                    s.sendall(data)
                    data = s.recv(8192)
                    self.__connSocket.sendall(data)
                except Exception, e:
                    logging.error('SOCKS: ' + str(e))

        # Let's look if there's a relayed connection for our host/port
        scheme = clients[self.targetHost][self.targetPort]['scheme']

        if scheme is not None:
            logging.debug('Handler for port %s found %s',
                          self.targetPort,
                          self.__socksServer.socksPlugins[scheme])

            relay = self.__socksServer.socksPlugins[scheme](
                                                    self.targetHost,
                                                    self.targetPort,
                                                    self.__connSocket,
                                                    clients[self.targetHost][self.targetPort])

            try:
                relay.initConnection()

                # Let's answer back saying we've got the connection. Data is fake
                if self.__socksVersion == 5:
                    reply = SOCKS5_REPLY()
                    reply['REP'] = replyField.SUCCEEDED.value
                    addr, port = self.__connSocket.getsockname()
                    reply['PAYLOAD'] = socket.inet_aton(addr) + pack('>H', port)
                else:
                    reply = SOCKS4_REPLY()

                self.__connSocket.sendall(reply.getData())

                if relay.skipAuthentication() is not True:
                    # Something didn't go right
                    # Close the socket
                    self.__connSocket.close()
                    return

                relay.tunnelConnection()
            except Exception, e:
                logging.debug('SOCKS: %s', str(e))
                if str(e).find('Broken pipe') >= 0 or str(e).find('reset by peer') >=0 or \
                                str(e).find('Invalid argument') >= 0:
                    logging.debug('Removing active relay for %s@%s:%s',
                                  relay.username,
                                  self.targetHost,
                                  self.targetPort)

                    self.sendReplyError(replyField.CONNECTION_REFUSED)
                    return
        else:
            logging.error('SOCKS: I don\'t have a handler for this port')

        logging.debug('SOCKS: Shutting down connection')
        try:
            self.sendReplyError(replyField.CONNECTION_REFUSED)
        except Exception, e:
            logging.debug('SOCKS END: %s', str(e))

class CommanderSOCKS(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    def __init__(self,
                 commander_server,
                 server_address=('0.0.0.0', 1080),
                 handler_class=SocksRequestHandler):

        logging.info('SOCKS proxy started. Listening at port %d', server_address[1] )

        self.commander = commander_server
        self.socksPlugins = {}
        self.supportedSchemes = []
        SocketServer.TCPServer.allow_reuse_address = True
        SocketServer.TCPServer.__init__(self, server_address, handler_class)

        for relay in SOCKS_RELAYS:
            logging.info('%s loaded..', relay.PLUGIN_NAME)
            self.socksPlugins[relay.PLUGIN_SCHEME] = relay
            self.supportedSchemes.append(relay.PLUGIN_SCHEME)

    def shutdown(self):
        return SocketServer.TCPServer.shutdown(self)
