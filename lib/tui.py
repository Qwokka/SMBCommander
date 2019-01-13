#!/usr/bin/env python
#
# Author: Jack Baker (https://github.com/qwokka/smbcommander)
#
# This product includes software developed by
# SecureAuth Corporation (https://www.secureauth.com/)."
#

from __future__ import division
from math import ceil

import curses
import curses.panel
import curses.textpad
import cmd
import logging
import os
import tuilog
import utils

HISTORY_BUF_SIZE    = 100

SELECT_SHELL        = 0
SELECT_SESS         = 1
SELECT_SERV         = 2

class CursesStdin(object):
    def __init__(self, stdscr, timeout=10):
        self.stdscr = stdscr
        self.buf    = ""

        self.stdscr.timeout(timeout)

    def get(self):
        return self.buf

    def get_char(self):
        return self.stdscr.getch()

    def clear(self):
        self.buf = ""

class CursesStdout(object):
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.buf    = [ (None, None) for _ in range(0, 100) ]

    def write(self, msg, color=0):
        del self.buf[0]
        self.buf.append((str(msg), color))

    def clear(self):
        self.buf = [ (None, None) for _ in range(0, 100) ]

    def get(self):
        return self.buf[::-1]

class CursesShell(cmd.Cmd):
    use_rawinput    = False

    done            = False

    prompt          = "> "

    # Tab completion options
    options         = {}

    cmd_history     = [ None for _ in range(0, HISTORY_BUF_SIZE) ]
    cmd_index       = -1
    cmd_saved       = ""

    # Modified version of Cmd.cmdloop() meant to be called once per curses frame
    def cmd_loop_once(self):
        if self.cmdqueue:
            line = self.cmdqueue.pop(0)
        else:
            line = self.readline()
            if line is None:
                return
            else:
                line = line.rstrip('\r\n')
                self.write_prompt(line)
        line = self.precmd(line)
        stop = self.onecmd(line)
        stop = self.postcmd(stop, line)

    # Used to write previous prompt value to shell output
    def write_prompt(self, line):
        self.stdout.write(self.prompt + line)

    # TODO Line wrapping
    # TODO Prefill as much as possilbe (EG, pressing tab when two options start with "auto")
    def text_complete(self, text):
        response = None

        pieces = text.split(" ")

        prefix = " ".join(pieces[:-1])

        if len(prefix):
            prefix += " "

        options = self.options

        for piece in pieces[:-1]:
            if piece in options:
                options = options[piece]

        current = pieces[-1]

        if current:
            matches = [ s
                        for s in options
                        if s and s.startswith(current) ]
        else:
            matches = [ i for i in options ]

        return prefix, matches

    def _cmd_history_append(self, line):
        del self.cmd_history[-1]
        self.cmd_history.insert(0, line)

    def readline(self):
        inbuf = self.stdin.get()

        if "\n" in inbuf:
            res = inbuf[:inbuf.index("\n")]

            self._cmd_history_append(res)
            self.cmd_index = -1

            self.stdin.clear()

            return res

        return None

    def handle_input(self, code):
        # Backspace
        if code == 0x8 or code == 0x7F or code == curses.KEY_BACKSPACE:
            self.stdin.buf = self.stdin.buf[:-1]

        # Tab
        elif code == 0x9:
            prefix, matches = self.text_complete(self.stdin.buf)

            if len(matches) == 1:
                self.stdin.buf = prefix + matches[0] + " "

            elif len(matches):
                new_prefix = prefix + os.path.commonprefix(matches)

                if new_prefix is not "":
                    self.stdin.buf = new_prefix

                suggest_str = ""

                # TODO Fix line wrapping
                for match in matches:
                    suggest_str += match + "   "

                self.write_prompt(self.stdin.buf)
                self.stdout.write(suggest_str)

        # TODO CTRL+P/CTRL+N
        elif code == curses.KEY_UP:
            self.cmd_index += 1

            if self.cmd_index >= HISTORY_BUF_SIZE:
                self.cmd_index = HISTORY_BUF_SIZE - 1

            if self.cmd_history[self.cmd_index] is None:
                self.cmd_index -= 1
            else:
                if self.cmd_index == 0:
                    self.cmd_saved = self.stdin.get()

                self.stdin.buf = self.cmd_history[self.cmd_index]

        elif code == curses.KEY_DOWN:
            self.cmd_index -= 1

            if self.cmd_index < -1:
                self.cmd_index = -1

            if self.cmd_index >= 0:
                self.stdin.buf = self.cmd_history[self.cmd_index]
            else:
                self.stdin.buf = self.cmd_saved

        elif code in range(0, 0xff):
            self.stdin.buf += chr(code)

class TUI(cmd.Cmd):
    stdscr = None

    def __init__(self, shell=None, server=None):
        if shell is not None:
            self._shell_class = shell
        else:
            self._shell_class = CursesShell

        self.server = server

        self.select = SELECT_SHELL

    def make_panel(self, h, l, y, x):
        win = curses.newwin(h, l, y, x)
        win.erase()
        win.box()

        panel = curses.panel.new_panel(win)

        return win, panel

    def get_input(self):
        try:
            code = self.stdscr.getch()
        except KeyboardInterrupt:
            self.shell.write_prompt(self.shell_stdin.get() + "^C")
            self.shell_stdin.buf = ""
            return

        if code == curses.KEY_BTAB:
            self.select = SELECT_SHELL if self.select is SELECT_SESS else SELECT_SESS
            return

        if self.select == SELECT_SHELL:
            self.shell.handle_input(code)
        else:
            self._handle_session_input(code)

    def _handle_session_input(self, code):
        if code == curses.KEY_UP:
            sessions = self.server.getSessions()

            min_index = min(sessions, key=int)

            if self.sessions_index > min_index:
                self.sessions_index -= 1
                while not sessions.has_key(self.sessions_index):
                    self.sessions_index -= 1

            if self.sessions_index < min_index:
                self.sessions_index = min_index

        elif code == curses.KEY_DOWN:
            sessions = self.server.getSessions()

            max_index = max(sessions, key=int)

            if self.sessions_index < max_index:
                self.sessions_index += 1
                while not sessions.has_key(self.sessions_index):
                    self.sessions_index += 1

            if self.sessions_index > max(sessions, key=int):
                self.sessions_index = max(sessions, key=int)

        elif code == 0xA:
            if self.sessions_index in self.sessions_expanded:
                self.sessions_expanded.remove(self.sessions_index)
            else:
                self.sessions_expanded.append(self.sessions_index)

    # TODO
    def _draw_sessions_scroll_bar(self):
        return

    def draw_shell_window(self):
        win = self.right_window

        win.erase()

        win.box()

        in_text = self.shell.prompt + self.shell_stdin.get()

        if len(in_text) > self.right_width - 3:
            start = len(in_text) - (self.right_width - 3)

            in_text = in_text[start:]

        win.addstr(self.height - 2, 1, in_text)

        nextrow = 0

        for s, c in self.shell_stdout.get():
            if s is None:
                continue

            columns = self.right_width - 2
            row_count = int(ceil(len(s) / columns))

            for row in range(1, row_count + 1):
                arow = row_count - row + 1
                y = self.height - (nextrow + row) - 2

                if y < 1:
                    break

                win.addstr(y,
                           1,
                           s[(arow * columns) - columns : arow * columns],
                           curses.color_pair(c))

            nextrow = nextrow + row_count

            if nextrow > self.height:
                break

        cursorx = self.left_space + len(self.shell.stdin.buf) + len(self.shell.prompt) + 1

        if cursorx > self.width - len(self.shell.prompt):
            cursorx = self.width - len(self.shell.prompt)

        self.stdscr.move(self.height - 2, cursorx)

        win.refresh()

    def draw_server_window(self):
        win = self.top_window
        panel = self.top_panel

        win.erase()

        win.box()

        nextrow = 0

        # Draw server output
        for s, c in self.server_stdout.get():
            if s is None:
                continue

            columns = self.top_width - 2
            row_count = int(ceil(len(s) / columns))

            for row in range(1, row_count + 1):
                arow = row_count - row + 1
                y = self.top_height - (nextrow + row)

                if y < 1:
                    break

                try:
                    win.addstr(y,
                               1,
                               s[(arow * columns) - columns : arow * columns],
                               curses.color_pair(c))

                except TypeError:
                    pass

            nextrow = nextrow + row_count

            if nextrow > self.height:
                break

        header_values = [
            ("SERVER",          "RUNNING" if utils.commander.server_running else "STOPPED"),
            ("TARGET",          utils.commander.server.target),
            ("AUTODUMP",        str(utils.commander.server.auto_secretsdump)),
            ("AUTOEXEC",        str(utils.commander.server.auto_exec)),
            ("AUTOEXEC_FILE",   str(utils.commander.server.auto_exec_file)),
        ]

        xindex = 2

        # Draw server header
        for key, value in header_values:
            keylen = len(key)
            vallen = len(value)

            space_to_go = self.top_width - xindex

            max_val_size = min(20, space_to_go - keylen - 2)

            if max_val_size < 3:
                break

            if vallen > max_val_size:
                value = value[:max_val_size - 3] + "..."
                vallen = len(value)

            win.addstr(1, xindex, key)

            win.chgat(1, xindex, keylen, curses.A_BOLD)

            xindex += keylen + 1

            win.addstr(1, xindex, value)

            xindex += vallen + 2

        win.refresh()

    def _get_sessions_output(self):
        output      = []
        anchors     = {}
        cursor      = None

        self.scroll_bottom = self.scroll_top + self.btm_height - 4

        nextrow = 2

        sessions = self.server.getSessions()

        for index, session in sessions.iteritems():
            if session is None:
                continue

            entry = "[%s] %s %s\\%s" % (index,
                                        session.get_remote_host(),
                                        session.domain.decode("utf-16"),
                                        session.username.decode("utf-16"))

            columns = self.right_width - 2
            row_count = int(ceil(len(entry) / columns))

            details = []

            for row in range(1, row_count + 1):
                arow = row_count - row + 1
                y = nextrow + row

                if y < 1:
                    break

                msg = entry[(arow * columns) - columns : arow * columns]

                details.append(msg)
                anchors[index] = y - 3

            nextrow = nextrow + row_count

            if index in self.sessions_expanded:
                details.append("Login:\t%s\\%s" %
                               (session.domain.decode("utf-16"),
                                session.username.decode("utf-16")))

                details.append("Shares:")

                # TODO Shares are not updated after session is established
                for share in session.shares:
                    status = "No Access"

                    if share.readable:
                        if share.writable:
                            status = "WRITABLE"
                        else:
                            status = "READABLE"

                    detail = ("\t%s (%s)\t%s" %
                              (share["shi1_netname"][:-1],
                               share["shi1_remark"][:-1],
                               status))

                    details.append(detail)

            session_details = []

            for s in details:
                columns = self.right_width - 2
                row_count = int(ceil(len(s) / columns))

                for row in range(1, row_count + 1):
                    arow = row_count - row + 1
                    y = nextrow + row

                    if y < 1:
                        break

                    session_details.append(s[(arow * columns) - columns : arow * columns])

                nextrow = nextrow + row_count

            output.append(session_details)

        if self.select == SELECT_SESS and len(sessions) > 0:
                max_index = max(sessions, key=int)
                min_index = min(sessions, key=int)

                if self.sessions_index > max_index:
                    self.sessions_index = max_index
                elif self.sessions_index < min_index:
                    self.sessions_index = min_index
                elif not sessions.has_key(self.sessions_index):
                    self.sessions_index += 1

                    while not sessions.has_key(self.sessions_index):
                        self.sessions_index += 1

                cursor = anchors[self.sessions_index]

        return output, cursor

    def draw_sessions_window(self):
        win = self.btm_window

        win.erase()

        win.box()

        sessions = self.server.getSessions()

        s = "Open Sessions: %s" % len(sessions)

        win.addstr(1, 1, s)
        win.chgat(1, 1, len(s), curses.A_BOLD)

        while self.sessions_cursor < self.scroll_top and self.sessions_cursor >= 0:
            self.scroll_top -= 1
            self.scroll_bottom = self.scroll_top + self.btm_height - 3

        while self.sessions_cursor > self.scroll_bottom:
            self.scroll_top += 1
            self.scroll_bottom = self.scroll_top + self.btm_height - 5

        miny = 3
        maxy = self.btm_height - 1

        real_index = 0

        for entry_index, entry in enumerate(self.sessions_output):
            for line_index, line in enumerate(entry):
                realy = miny + real_index - self.scroll_top

                real_index += 1

                if realy < miny or realy > maxy:
                    continue

                win.addstr(realy, 1, line)

                if line_index == 0 and entry_index == self.sessions_index:
                    win.chgat(realy, 1, len(line), curses.A_REVERSE)

                if realy > maxy:
                    self._draw_sessions_scroll_bar()
                    break

        win.refresh()

    def step(self):
        self.stdscr.refresh()
        curses.panel.update_panels()

        self.sessions_output, self.sessions_cursor = self._get_sessions_output()

        self.get_input()

        if self.select == SELECT_SHELL:
            curses.curs_set(1)
        else:
            curses.curs_set(0)

        self.shell.cmd_loop_once()

        self.draw()

class TUILarge(TUI):
    shell = None

    def run(self, stdscr):

        self.stdscr = stdscr

        self.server_stdout      = CursesStdout(stdscr)

        self.shell_stdin        = CursesStdin(stdscr)
        self.shell_stdout       = CursesStdout(stdscr)

        self.sessions_index     = 0
        self.sessions_expanded  = []

        self.sessions_output    = []
        self.sessions_cursor    = None

        self.scroll_top         = 0
        self.scroll_bottom      = 0

        self.logger             = tuilog.CursesLogHandler(self.server_stdout)

        self.logger.setFormatter(tuilog.TUILogFormatter())

        logging.getLogger().addHandler(self.logger)

        if self.shell is None:
            self.shell = self._shell_class(stdin=self.shell_stdin,
                                           stdout=self.shell_stdout)
        curses.start_color()
        curses.use_default_colors()
        curses.echo()

        for i in range(0, curses.COLORS):
            curses.init_pair(i + 1, i, -1)

        self.height, self.width = self.stdscr.getmaxyx()

        self.half_height = self.height // 2
        self.half_width  = self.width  // 2

        self.right_window, self.right_panel = self.make_panel(self.height,
                                                              self.half_width,
                                                              0,
                                                              self.half_width)

        self.top_window, self.top_panel = self.make_panel(self.half_height + 1,
                                                          self.half_width,
                                                          0,
                                                          0)

        self.btm_window, self.btm_panel = self.make_panel(self.half_height + 1,
                                                          self.half_width,
                                                          self.half_height,
                                                          0)

        self.right_width    = self.half_width
        self.right_height   = self.height
        self.top_width      = self.half_width
        self.top_height     = self.half_height
        self.btm_width      = self.half_width
        self.btm_height     = self.half_height

        self.left_space = self.top_width

        try:
            while not self.shell.done:
                self.step()
            curses.endwin()
        except KeyboardInterrupt:
            curses.endwin()

    def draw(self):
        self.draw_sessions_window()
        self.draw_server_window()
        self.draw_shell_window()

        self.stdscr.refresh()

class TUISmall(TUI):
    shell = None

    def run(self, stdscr):

        self.stdscr = stdscr

        self.server_stdout  = CursesStdout(stdscr)

        self.shell_stdin    = CursesStdin(stdscr)
        self.shell_stdout   = CursesStdout(stdscr)

        self.sessions_index     = 0
        self.sessions_expanded  = []

        self.sessions_output    = []
        self.sessions_cursor    = None

        self.scroll_top         = 0
        self.scroll_bottom      = 0

        self.logger         = tuilog.CursesLogHandler(self.server_stdout)

        self.logger.setFormatter(tuilog.TUILogFormatter())

        logging.getLogger().addHandler(self.logger)

        if self.shell is None:
            self.shell = self._shell_class(stdin=self.shell_stdin,
                                           stdout=self.shell_stdout)
        curses.start_color()
        curses.use_default_colors()
        curses.echo()

        for i in range(0, curses.COLORS):
            curses.init_pair(i + 1, i, -1)

        self.height, self.width = self.stdscr.getmaxyx()

        self.half_height = self.height // 2
        self.half_width  = self.width  // 2

        self.top_window, self.top_panel = self.make_panel(self.half_height + 1,
                                                          self.width,
                                                          0,
                                                          0)

        self.btm_window, self.btm_panel = self.make_panel(self.half_height + 1,
                                                          self.width,
                                                          self.half_height,
                                                          0)

        self.right_window, self.right_panel = self.make_panel(self.height,
                                                              self.width,
                                                              0,
                                                              0)

        self.right_width    = self.width
        self.right_height   = self.height
        self.top_width      = self.width
        self.top_height     = self.half_height
        self.btm_width      = self.width
        self.btm_height     = self.half_height

        self.left_space = 0

        self.shell.output_warning("Terminal width is too small for full TUI. " +
                                  "Using small TUI. Press <SHIFT> + <TAB> to switch " +
                                  "between views.")

        try:
            while not self.shell.done:
                self.step()
            curses.endwin()
        except KeyboardInterrupt:
            curses.endwin()

    def draw(self):
        if self.select == SELECT_SESS:
            self.draw_sessions_window()
            self.draw_server_window()
        else:
            self.draw_shell_window()

        self.stdscr.refresh()

class TUITiny(TUI):
    shell = None

    def run(self, stdscr):

        self.stdscr = stdscr

        self.server_stdout  = CursesStdout(stdscr)

        self.shell_stdin    = CursesStdin(stdscr)
        self.shell_stdout   = CursesStdout(stdscr)

        self.sessions_index     = 0
        self.sessions_expanded  = []

        self.sessions_output    = []
        self.sessions_cursor    = None

        self.scroll_top         = 0
        self.scroll_bottom      = 0

        self.logger         = tuilog.CursesLogHandler(self.server_stdout)

        self.logger.setFormatter(tuilog.TUILogFormatter())

        logging.getLogger().addHandler(self.logger)

        if self.shell is None:
            self.shell = self._shell_class(stdin=self.shell_stdin,
                                           stdout=self.shell_stdout)
        curses.start_color()
        curses.use_default_colors()
        curses.echo()

        for i in range(0, curses.COLORS):
            curses.init_pair(i + 1, i, -1)

        self.height, self.width = self.stdscr.getmaxyx()

        self.top_window, self.top_panel = self.make_panel(self.height,
                                                          self.width,
                                                          0,
                                                          0)

        self.btm_window, self.btm_panel = self.make_panel(self.height,
                                                          self.width,
                                                          0,
                                                          0)

        self.right_window, self.right_panel = self.make_panel(self.height,
                                                              self.width,
                                                              0,
                                                              0)

        self.right_width    = self.width
        self.right_height   = self.height
        self.top_width      = self.width
        self.top_height     = self.height - 1
        self.btm_width      = self.width
        self.btm_height     = self.height

        self.left_space = 0

        self.shell.output_warning("Terminal size is too small for full TUI. " +
                                  "Using tiny TUI. Press <SHIFT> + <TAB> to switch " +
                                  "between views.")

        try:
            while not self.shell.done:
                self.step()
            curses.endwin()
        except KeyboardInterrupt:
            curses.endwin()

    def get_input(self):
        try:
            code = self.stdscr.getch()
        except KeyboardInterrupt:
            self.shell.write_prompt(self.shell_stdin.get() + "^C")
            self.shell_stdin.buf = ""
            return

        if code == curses.KEY_BTAB:
            if self.select == SELECT_SHELL:
                self.select = SELECT_SESS
            elif self.select == SELECT_SESS:
                self.select = SELECT_SERV
            elif self.select == SELECT_SERV:
                self.select = SELECT_SHELL
            return

        if self.select == SELECT_SHELL:
            self.shell.handle_input(code)
        else:
            self._handle_session_input(code)

    def draw(self):
        if self.select == SELECT_SESS:
            self.draw_sessions_window()
        elif self.select == SELECT_SHELL:
            self.draw_shell_window()
        else:
            self.draw_server_window()

        self.stdscr.refresh()
