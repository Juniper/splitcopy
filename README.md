# splitcopy

Splits a given file into pieces in a tmp directory, copies these to a junos
host then reassembles them. Tested to be 15x faster to transfer an 845MB
file than regular ftp/scp.

Requires 'system services ssh' configuration on remote host.
If using ftp (default) to copy files then 'system services ftp' is also
required.

Requires python 3.4+ to run.
    3x faster in 3.6 than 3.4

install required module via:
    pip3 install junos-eznc

Script overhead is 5-10 seconds on 64bit RE's, longer on RE2000's
and PPC based models like MX80.
This includes authentication, sha1 generation/comparison,
disk space check, file split and join.
It will be slower than ftp/scp for small files as a result.

Because it opens 13-40 (depending on BSD version/protocol) simultaneous
connections, if the router has a connection and/or rate limit set similar to the example below, the tool will disable the appropriate lines in the device's configuration to
allow the process to continue and will display an appropriate warning message advising the changes:

```
system {
    services {
        ssh { # or ftp
            connection-limit 10;
            rate-limit 10;
        }
    }
}
```

In essence, the script initiates CLI commands to deactivate the rate-limit and/or connection-limit lines in the device's configuration to prevent any bandwidth or connectivity issues.

# Arguments

`filepath`          Mandatory, the path to the file you want to copy  
`host`              Mandatory, the host to connect to, with sshd listening on port 22  
`user`              Mandatory, the username to connect with  
`-p or --password`  Optional, if you'd rather not have your password stored  
                    in shell history, you can omit this and it'll prompt you instead  
`-d or --remotedir` Optional, remote directory to put file  
`-s or --scp`       Optional, use scp instead of ftp to transfer files  

# Example

```
$ ./splitcopy.py ~/Downloads/network-agent-x86-32-17.3R1.10-C1.tgz 192.168.1.1 lab --scp
Password:
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzap': 67092 / 67092 (100%)
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzaa': 67092 / 67092 (100%)
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzak': 67092 / 67092 (100%)
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzan': 67092 / 67092 (100%)
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzae': 67092 / 67092 (100%)
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzaq': 67092 / 67092 (100%)
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzam': 67092 / 67092 (100%)
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzaj': 67092 / 67092 (100%)
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzab': 67092 / 67092 (100%)
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzac': 67092 / 67092 (100%)
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzag': 67092 / 67092 (100%)
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzat': 67092 / 67092 (100%)
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzal': 67092 / 67092 (100%)
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzao': 67092 / 67092 (100%)
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzau': 18 / 18 (100%)
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzah': 67092 / 67092 (100%)
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzaf': 67092 / 67092 (100%)
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzad': 67092 / 67092 (100%)
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzar': 67092 / 67092 (100%)
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzas': 67092 / 67092 (100%)
192.168.1.1: b'network-agent-x86-32-17.3R1.10-C1.tgzai': 67092 / 67092 (100%)
performing file joins...
deleting remote tmp directory...
generating sha1 and verifying...
file has been successfully copied to 192.168.1.1:/var/tmp/network-agent-x86-32-17.3R1.10-C1.tgz, sha1 matches
data transfer time = 0:00:08.462824
total runtime = 0:00:18.350813
```

# NOTES

In FreeBSD 10 based releases each scp chunk creates 2 pids on a junos box.  
In FreeBSD 6 based releases each scp chunk would create 3 pids on a junos box:

lab 78625  0.0  0.1  2984  2144  ??  Ss    5:29AM   0:00.01 cli -c scp -t /var/tmp/splitcopy_jinstall-11.4R5.5-domestic-signed.tgz/  
lab 78626  0.0  0.0  2252  1556  ??  S     5:29AM   0:00.00 sh -c scp -t /var/tmp/splitcopy_jinstall-11.4R5.5-domestic-signed.tgz/  
lab 78627  0.0  0.1  3500  1908  ??  S     5:29AM   0:00.01 scp -t /var/tmp/splitcopy_jinstall-11.4R5.5-domestic-signed.tgz/  

This could result in maxproc limit being hit with 21 ssh sessions:

May  2 04:46:59   /kernel: maxproc limit exceeded by uid 2001, please see tuning(7) and login.conf(5).

```
% limit
cputime      unlimited
filesize     unlimited
datasize     65536 kbytes
stacksize    8192 kbytes
coredumpsize unlimited
memoryuse    30720 kbytes
vmemoryuse   unlimited
descriptors  64
memorylocked 10240 kbytes
maxproc      64
sbsize       unlimited
```

As a result the script modulates the number of sessions depending on the BSD version

FTP only creates one pid per chunk, hence it is now the default transfer method
