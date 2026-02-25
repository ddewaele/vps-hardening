# Check if SSH is working before hardening

```
sudo systemctl status ssh
sudo apt install openssh-server
sudo systemctl status ssh
```

you should see this

```
ubuntu@ubuntu-2404-server:~$ sudo systemctl status ssh
● ssh.service - OpenBSD Secure Shell server
     Loaded: loaded (/usr/lib/systemd/system/ssh.service; disabled; preset: enabled)
     Active: active (running) since Wed 2026-02-25 20:53:10 UTC; 2min 25s ago
TriggeredBy: ● ssh.socket
       Docs: man:sshd(8)
             man:sshd_config(5)
    Process: 1045 ExecStartPre=/usr/sbin/sshd -t (code=exited, status=0/SUCCESS)
   Main PID: 1046 (sshd)
      Tasks: 1 (limit: 2209)
     Memory: 3.7M (peak: 4.7M)
        CPU: 101ms
     CGroup: /system.slice/ssh.service
             └─1046 "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"

Feb 25 20:53:10 ubuntu-2404-server systemd[1]: Starting ssh.service - OpenBSD Secure Shell server...
Feb 25 20:53:10 ubuntu-2404-server sshd[1046]: Server listening on 0.0.0.0 port 22.
Feb 25 20:53:10 ubuntu-2404-server sshd[1046]: Server listening on :: port 22.
Feb 25 20:53:10 ubuntu-2404-server systemd[1]: Started ssh.service - OpenBSD Secure Shell server.
Feb 25 20:53:12 ubuntu-2404-server sshd[1048]: Accepted password for ubuntu from 192.168.0.174 port 62069 ssh2
Feb 25 20:53:12 ubuntu-2404-server sshd[1048]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by ubuntu(uid=0)
Feb 25 20:53:51 ubuntu-2404-server sshd[1179]: Accepted password for ubuntu from 192.168.0.174 port 62107 ssh2
Feb 25 20:53:51 ubuntu-2404-server sshd[1179]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by ubuntu(uid=0)
```