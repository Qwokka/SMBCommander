# Introduction

SMBCommander is an ncurses frontend for smbrelayx.py from [Impacket Tools](https://github.com/SecureAuthCorp/impacket/). 

SMBCommander aims to simplify the complexity of handling SMB relay sessions by organizing output, simplifying  configuration, and making session exploitation tools more easily accessible.

# Requirements

 * [Impacket Tools](https://github.com/SecureAuthCorp/impacket/)
 * ncurses libraries

# Setup

```
git clone https://github.com/qwokka/smbcommander
```

# Running SMBCommander

```
cd SMBCommander/
./commander.py
```

# Basic Usage

Windows
------------
SMBCommander's terminal UI is made up of three windows.

 * The **shell** window used to control SMBCommander
 * The **server** window used to display output from the SMB relay server
 * The **sessions** window used to keep track of open sessions

You can shift focus between the **shell** and **sessions** windows using **SHIFT+TAB**. (The **server** window does not take any input and therefore cannot be selected this way).

# Shell Window

Help can be found within SMBCommander using **help** or **help [command]**

Core Commands
--------------------

**exit/quit/q** - Close sessions and exit
**SHIFT+TAB** - Switch window focus

Server Commands
----------------------

**run** - Start server with current configuration settings

**sessions** - Show open sessions

**set** - Set configuration options (Metasploit style)
```
set [option] [value]
```
**show** - Show options/sessions
```
show options
show sessions
```

Session Commands
-----------------------

**close**   - Close session
```
close [session id]
```
**psexec_cmd** - Execute command on session via PSEXEC. Requires admin. (TODO)
```
psexec_cmd [session_id] [command]
```
**psexec_file** - Upload and execute file on session via PSEXEC. Requires admin.
```
psexec_file [session_id] [file]
```
**secretsdump** - Execute [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) on session. Requires admin.
```
secretsdump [session_id]
```
**smbclient** - Open smbclient shell on session.
```
smbclient [session_id]
```

# Sessions Window

Basic Usage
--------------

 * Navigate sessions with arrow keys
 * Expand/shrink session details with **ENTER**

# Configuration Settings

Command Line Arguments
--------------------------------

Most command line arguments (Except for **SOCKS** and **DEBUG**) can also be configured while SMBCommander is running. Most command line arguments are identical to [smbrelayx.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbrelayx.py).

```
  --help                Show this help message and exit
  -debug                Turn DEBUG output ON
  -h HOST               Host to relay the credentials to, if not it will relay
                        it back to the client
  -socks                Launch a SOCKS proxy for the connection relayed
  -one-shot             After successful authentication, only execute the
                        attack once for each target
  -outputfile OUTPUTFILE
                        Base output filename for encrypted hashes. Suffixes
                        will be added for ntlm and ntlmv2
  -machine-account MACHINE_ACCOUNT
                        Domain machine account to use when interacting with
                        the domain to grab a session key for signing, format
                        is domain/machine_name
  -machine-hashes LMHASH:NTHASH
                        Domain machine hashes, format is LMHASH:NTHASH
  -domain DOMAIN        Domain FQDN or IP to connect using NETLOGON
  -r                    Start SMB server immediately (Requires -h options)
```

Server Configuration
-------------------------

These arguments are configured using the **set** command detailed above. New config settings take effect immediately - you do not need to restart the server for them to be applied.

**TARGET** - Host to relay requests to (Same as **-h** command line argument).
```
set TARGET [ip address]
```

**ONESHOT** - After successful authentication, only execute attack once per target (Same as **-one-shot** command line argument)
```
set ONESHOT true/false
```

**SVCNAME** - Name to give created services. Default: random string starting with "smbcom"

```
set SVCNAME [service name]
```

**AUTODUMP** - Execute secretsdump on each new session automatically

```
set AUTODUMP true/false
```

**AUTOEXEC** - PSExec file on each new session automatically (Requires **AUTOEXEC_FILE** to be set)

```
set AUTODUMP true/false
```

**AUTOEXEC_FILE** - File to PSExec on each new session (Requires **AUTOEXEC** = **True**)

```
set AUTOEXEC_FILE [path to local file]
```

**MACHINEACCT** - Domain machine account to use when interacting with the domain to grab a session key for signing, format is domain/machine_name (Same as **-machine-accounts** command line argument)

```
set MACHINEACCT [domain/machine_name]
```

**MACHINEHASHES** - Domain machine hashes, format is LMHASH:NTHASH (Same as **-machine-hashes** command line argument)

```
set MACHINEHASHES [lmhash:nthash]
```

**DOMAIN** - Domain FQDN or IP to connect using NETLOGON (Same as **-domain** command line argument)

```
set DOMAIN [domain]
```

