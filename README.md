# Splitcopy

Speeds up copying files to/from JUNOS/Evo/Linux/FreeBSD hosts.

Splits a given file into chunks in a tmp directory,
copies these chunks and recombines them.  
Requires 'system services ssh' configuration on remote host.  
If using ftp to copy files (default) then 'system services ftp' is also required  
Requires python 3.4 to run, 3.5 is faster, 3.6 is faster again  

install required module dependencies via:
```
python3 -m pip install junos-eznc
```
Script overheads include authentication, sha1 generation/comparison, disk space check, file split and join.  
It can be slower than normal ftp/scp for small files as a result.

Because it opens a number of simultaneous connections,
if the router has connection/rate limits configured like this:

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

The script will deactivate these limits so it can proceed, then activate them again.  

# Arguments

`filepath`          Mandatory, the path to the file you want to copy  
`host`              Mandatory, the host to connect to, with sshd listening on port 22  
`user`              Mandatory, the username to connect with  
`-p or --password`  Optional, if you'd rather not have your password stored in shell history, you can omit this and it'll prompt you instead  
`-d or --destdir`   Optional, directory to put file  
`-s or --scp`       Optional, use scp instead of ftp to transfer files  
`-g or --get`       Optional, copy from remote to local host  

# Example FTP transfer (default method)

```
$ ./splitcopy.py jselective-update-ppc-J1.1-14.2R5-S3-J1.1.tgz 192.168.1.1 lab
Password:
checking remote port(s) are open...
using FTP for file transfer
checking remote storage...
sha1 not found, generating sha1...
splitting file...
starting transfer...
10% done
20% done
30% done
40% done
50% done
60% done
70% done
80% done
90% done
100% done
transfer complete
joining files...
deleting remote tmp directory...
generating remote sha1...
local and remote sha1 match
file has been successfully copied to 192.168.1.1:/var/tmp/jselective-update-ppc-J1.1-14.2R5-S3-J1.1.tgz
data transfer = 0:00:16.831192
total runtime = 0:00:31.520914
```

# Example SCP transfer  

```
$ ./splitcopy.py jselective-update-ppc-J1.1-14.2R5-S3-J1.1.tgz 192.168.1.1 lab --scp
Password:
checking remote port(s) are open...
using SCP for file transfer
checking remote storage...
sha1 not found, generating sha1...
splitting file...
starting transfer...
10% done
20% done
30% done
40% done
50% done
60% done
70% done
80% done
90% done
100% done
transfer complete
joining files...
deleting remote tmp directory...
generating remote sha1...
local and remote sha1 match
file has been successfully copied to 192.168.1.1:/var/tmp/jselective-update-ppc-J1.1-14.2R5-S3-J1.1.tgz
data transfer = 0:00:29.509159
total runtime = 0:00:43.886565
```

# Notes on using FTP

FTP is the default transfer method.  
FTP progress on --get operations is supported from py-junos-eznc v2.2.2  

The version of Python used has a big impact.  
If using < 3.6 the maximum number of simultaneous transfers is 5.  
If using 3.6+ it will allow 5 simultaneous transfers per cpu   

Using FTP method will generate the following processes on the remote host:
- for mgmt session: 1x sshd, 1x cli, 1x mgd, 1x csh
- for transfers: up to 40x ftpd processes (depends on Python version and number of cpus as described above)

In theory, this could result in the per-user maxproc limit of 64 being exceeded:
```
May  2 04:46:59   /kernel: maxproc limit exceeded by uid 2001, please see tuning(7) and login.conf(5).
```
The script modulates the number of chunks to match the maximum number of simultaneous transfers possible (based on Python version and number of cpus).   
The maximum number of user owned processes that could be created is <= 44

# Notes on using SCP

The version of Python used has a big impact.  
If using < 3.6 the maximum number of simultaneous transfers is 5.  
If using 3.6+ it will allow 5 simultaneous transfers per cpu 

Using SCP method will generate the following processes on the remote host:
- for mgmt session: 1x sshd, 1x cli, 1x mgd, 1x csh
- for transfers:  depends on Python version, number of cpus (see above) and Junos FreeBSD version (see below)

In FreeBSD 10 based Junos each scp transfer creates 2 user owned processes and 1 root owned process: 
```
root 28626   0.0  0.0   63248   5724  -  Ss   11:59AM     0:00.11 sshd: labroot@notty (sshd)
lab  28639   0.0  0.0  734108   4004  -  Is   12:00PM     0:00.01 cli -c scp -t /var/tmp/splitcopy_jinstall-11.4R5.5-domestic-signed.tgz/
lab  28640   0.0  0.0   24768   3516  -  S    12:00PM     0:00.01 scp -t /var/tmp/splitcopy_jinstall-11.4R5.5-domestic-signed.tgz/
```
In FreeBSD 6 based Junos each scp transfer creates 3 user owned processes:
```
lab  78625  0.0  0.1  2984  2144  ??  Ss    5:29AM   0:00.01 cli -c scp -t /var/tmp/splitcopy_jinstall-11.4R5.5-domestic-signed.tgz/  
lab  78626  0.0  0.0  2252  1556  ??  S     5:29AM   0:00.00 sh -c scp -t /var/tmp/splitcopy_jinstall-11.4R5.5-domestic-signed.tgz/  
lab  78627  0.0  0.1  3500  1908  ??  S     5:29AM   0:00.01 scp -t /var/tmp/splitcopy_jinstall-11.4R5.5-domestic-signed.tgz/  
```
In theory, this could result in the per-user maxproc limit of 64 being exceeded:
```
May  2 04:46:59   /kernel: maxproc limit exceeded by uid 2001, please see tuning(7) and login.conf(5).
```
The script modulates the number of chunks to match the maximum number of simultaneous transfers possible (based on Python version, number of cpus and Junos FreeBSD version).  
The maximum number of user owned processes that could be created is <= 44
