#!/usr/bin/env python
#
# Author: Jack Baker (https://github.com/qwokka/smbcommander)
#
# This product includes software developed by
# SecureAuth Corporation (https://www.secureauth.com/)."
#

import logging

from threading import Thread, Lock

from impacket.structure import Structure

lock = Lock()

class RemComMessage(Structure):
    structure = (
        ('Command','4096s=""'),
        ('WorkingDir','260s=""'),
        ('Priority','<L=0x20'),
        ('ProcessID','<L=0x01'),
        ('Machine','260s=""'),
        ('NoWait','<L=0'),
    )

class RemComResponse(Structure):
    structure = (
        ('ErrorCode','<L=0'),
        ('ReturnCode','<L=0'),
    )

RemComSTDOUT         = "RemCom_stdout"
RemComSTDIN          = "RemCom_stdin"
RemComSTDERR         = "RemCom_stderr"

class CommanderPipes(Thread):
    def __init__(self, connection, pipe, permissions, share=None):
        Thread.__init__(self)
        self.server = connection
        self.tid = 0
        self.fid = 0
        self.share = share
        #self.port = transport.get_dport()
        self.pipe = pipe
        self.permissions = permissions
        self.daemon = True

    def connectPipe(self):
        try:
            lock.acquire()

            self.tid = self.server.connectTree('IPC$')

            self.server.waitNamedPipe(self.tid, self.pipe)
            self.fid = self.server.openFile(self.tid,self.pipe,self.permissions,
                                            creationOption = 0x40,
                                            fileAttributes = 0x80)
            self.server.setTimeout(1000000)
        except:
            import traceback
            traceback.print_exc()
            logging.error("Something wen't wrong connecting the pipes(%s), try again",
                          self.__class__)

class CommanderRemoteStdInPipe(CommanderPipes):
    def __init__(self, connection, pipe, permisssions, share=None):
        self.shell = None
        CommanderPipes.__init__(self, connection, pipe, permisssions, share)

    def run(self):
        self.connectPipe()

        #self.shell = RemoteShell(self.server,
        #                         self.port,
        #                         self.credentials,
        #                         self.tid,
        #                         self.fid,
        #                         self.share,
        #                         self.transport)

        #self.shell.cmdloop()

class CommanderRemoteStdOutPipe(CommanderPipes):
    def __init__(self, connection, pipe, permisssions):
        CommanderPipes.__init__(self, connection, pipe, permisssions)

    def run(self):
        self.connectPipe()
        while True:
            try:
                ans = self.server.readFile(self.tid,self.fid, 0, 1024)
            except:
                pass
            else:
                try:
                    global LastDataSent
                    if ans != LastDataSent:
                        sys.stdout.write(ans.decode('cp437'))
                        sys.stdout.flush()
                    else:
                        LastDataSent = ''

                    if LastDataSent > 10:
                        LastDataSent = ''
                except:
                    pass

class CommanderRemoteStdErrPipe(CommanderPipes):
    def __init__(self, connection, pipe, permisssions):
        CommanderPipes.__init__(self, connection, pipe, permisssions)

    def run(self):
        self.connectPipe()
        while True:
            try:
                ans = self.server.readFile(self.tid,self.fid, 0, 1024)
            except:
                pass
            else:
                try:
                    sys.stderr.write(str(ans))
                    sys.stderr.flush()
                except:
                    pass
