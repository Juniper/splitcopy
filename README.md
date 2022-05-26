# Splitcopy

Improves file transfer rates when copying files to/from JUNOS/EVO/\*nix hosts.
  
At a minimum, sshd must be running on the remote host.  
On JUNOS/EVO this requires 'system services ssh' configuration.  

If using ftp to copy files then an ftp daemon must be running on the remote host.   
On JUNOS this requires 'system services ftp' configuration.  
FTP is the default transfer method due to its lower resource usage and its ability to restart transfers.   

Script overheads include authentication, sha hash generation/comparison, disk space check, file split and join.  
It can be slower than normal ftp/scp for small files as a result.

Because it opens a number of simultaneous connections,
if the JUNOS/EVO host has connection/rate limits configured like this:

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
or system login retry-options:

```
system {
    login {
        retry-options {
            <..>
        }
    }
}
```

The script will deactivate these limits so it can proceed, then rollback these changes upon completion.  

## Arguments 

`source`     Mandatory  
`target`     Mandatory  
`--pwd`      Optional, password  
`--scp`      Optional, use scp instead of ftp to transfer files  
`--ssh_key`  Optional, path to private ssh key (only required if not located in ~/.ssh/)  
`--log`      Optional, enables additional logging, specify a logging level as argument  
`--noverify` Optional, skips sha1 hash comparison of src and dst file  
`--split_timeout` Optional, time to wait for remote file split operation to complete, default 120s  
`--ssh_port` Optional, ssh port number to connect to  
`--nocurses` Optional, disables the use of a curses window to show per-file progress statistics  

The format of source and target arguments match those of the 'scp' cmd.  
Both accept either a local path, or a remote path in the format - user@host:path or host@path  

### To copy from local host to remote host:
    splitcopy  <local path> <user>@<host>:<path>
### To copy from remote host to local host:
    splitcopy  <user>@<host>:<path> <local path>

Supports connecting through jumphosts via 'ProxyCommand' entries in ~/.ssh/config. Example:  
```
Host myserver  
  ProxyCommand ssh myjumphost.mydomain.com -W %h:%p
```

# INSTALLATION

Installation requires Python >= 3.6 and associated `pip` tool  

    python3 -m pip install splitcopy

Installing from Git is also supported (OS must have git installed).

    To install the latest MASTER code
    python3 -m pip install git+https://github.com/Juniper/splitcopy.git
    -or-
    To install a specific version, branch, tag, etc.
    python3 -m pip install git+https://github.com/Juniper/splitcopy.git@<branch,tag,commit>

Upgrading has the same requirements as installation and has the same format with the addition of --upgrade

    python3 -m pip install splitcopy --upgrade


# Usage Examples 
## FTP transfer (default method)

```
$ splitcopy /var/tmp/jselective-update-ppc-J1.1-14.2R5-S3-J1.1.tgz lab@192.168.1.1:/var/tmp/
Password:
checking remote port(s) are open...
using FTP for file transfer
checking remote storage...
sha1 not found, generating sha1...
splitting file...
starting transfer...
100% done
transfer complete
joining files...
deleting remote tmp directory...
generating remote sha hash...
local and remote sha hash match
file has been successfully copied to 192.168.1.1:/var/tmp/jselective-update-ppc-J1.1-14.2R5-S3-J1.1.tgz
data transfer = 0:00:16.831192
total runtime = 0:00:31.520914
```

## SCP transfer

```
$ splitcopy lab@192.168.1.1/var/log/messages /var/tmp/ --scp  
ssh auth succeeded
checking remote storage...
checking local storage...
sha1 not found, generating sha1...
splitting file...
starting transfer...
100% done
transfer complete
joining files...
deleting remote tmp directory...
generating remote sha hash...
local and remote sha hash match
file has been successfully copied to /var/tmp/messages
data transfer = 0:00:18.768987
total runtime = 0:00:44.891370
```

## Notes on using FTP

FTP is the default transfer method.  
The processing of each file chunk is performed by a dedicated thread  
Each cpu core is allowed up to 5 threads, with a system max of 32 threads used  

Using FTP method will generate the following processes on the remote host:
- for mgmt session: 1x sshd, 1x cli, 1x mgd, 1x csh
- for transfers: up to 40x ftpd processes (depends on Python version and number of cpus as described above)

In theory, this could result in the per-user maxproc limit of 64 being exceeded:
```
May  2 04:46:59   /kernel: maxproc limit exceeded by uid 2001, please see tuning(7) and login.conf(5).
```
The script modulates the number of chunks to match the number of threads available   
The maximum number of user owned processes that could be created is <= 44

## Notes on using SCP

The processing of each file chunk is performed by a dedicated thread  
Each cpu core is allowed up to 5 threads, with a system max of 32 threads used  

Using SCP method will generate the following processes on the remote host:
- for mgmt session: 1x sshd, 1x cli, 1x mgd, 1x csh
- for transfers:  depends on Python version, number of cpus (see above), OpenSSH and Junos FreeBSD version (see below)

In FreeBSD 11 based Junos each scp transfer creates 2 user owned processes: 
```
lab 30366   0.0  0.0  475056   7688  -  Ss   10:39      0:00.03 cli -c scp -t /var/tmp/
lab 30367   0.0  0.0   61324   4860  -  S    10:39      0:00.01 scp -t /var/tmp/
```
In FreeBSD 10 based Junos each scp transfer creates 2 user owned processes
```
lab  28639   0.0  0.0  734108   4004  -  Is   12:00PM     0:00.01 cli -c scp -t /var/tmp/splitcopy_jinstall-11.4R5.5-domestic-signed.tgz/
lab  28640   0.0  0.0   24768   3516  -  S    12:00PM     0:00.01 scp -t /var/tmp/splitcopy_jinstall-11.4R5.5-domestic-signed.tgz/
```
In FreeBSD 6 based Junos each scp transfer creates 3 user owned processes: 
```
lab  78625  0.0  0.1  2984  2144  ??  Ss    5:29AM   0:00.01 cli -c scp -t /var/tmp/splitcopy_jinstall-11.4R5.5-domestic-signed.tgz/  
lab  78626  0.0  0.0  2252  1556  ??  S     5:29AM   0:00.00 sh -c scp -t /var/tmp/splitcopy_jinstall-11.4R5.5-domestic-signed.tgz/  
lab  78627  0.0  0.1  3500  1908  ??  S     5:29AM   0:00.01 scp -t /var/tmp/splitcopy_jinstall-11.4R5.5-domestic-signed.tgz/  
```
In addition, if OpenSSH version is >= 7.4, an additional user owned process is created:
```
lab  2287  2.4  0.1 11912  2348  ??  S     3:49AM   0:00.15 sshd: lab@notty (sshd)
```
This could result in the per-user maxproc limit of 64 being exceeded:
```
May  2 04:46:59   /kernel: maxproc limit exceeded by uid 2001, please see tuning(7) and login.conf(5).
```
To mitigate this, the script modulates the number of chunks to match the maximum number of simultaneous transfers possible (based on OpenSSH, Junos FreeBSD versions and the number of cpu's).  
The maximum number of user owned processes that could be created is <= 45



## LICENSE

Apache 2.0

## CONTRIBUTORS

Juniper Networks is actively contributing to and maintaining this repo. Please contact jnpr-community-netdev@juniper.net for any queries.

*Contributors:*

[Chris Jenn](https://github.com/ipmonk)
