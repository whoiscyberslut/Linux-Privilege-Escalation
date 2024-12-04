When enumerating a system, it is important to note down any credentials. These may be found in configuration files (`.conf`, `.config`, `.xml`, etc.), shell scripts, a user's bash history file, backup (`.bak`) files, within database files or even in text files. Credentials may be useful for escalating to other users or even root, accessing databases and other systems within the environment.

The /var directory typically contains the web root for whatever web server is running on the host. The web root may contain database credentials or other types of credentials that can be leveraged to further access. A common example is MySQL database credentials within WordPress configuration files:

```shell-session
cyberslut@NIX02:~$ cat wp-config.php | grep 'DB_USER\|DB_PASSWORD'

define( 'DB_USER', 'wordpressuser' );
define( 'DB_PASSWORD', 'WPadmin123!' );
```

The spool or mail directories, if accessible, may also contain valuable information or even credentials. It is common to find credentials stored in files in the web root (i.e. MySQL connection strings, WordPress configuration files).

```shell-session
cyberslut@NIX02:~$  find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null

/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/python3/debian_config
/etc/kbd/config
/etc/manpath.config
/boot/config-4.4.0-116-generic
/boot/grub/i386-pc/configfile.mod
/sys/devices/pci0000:00/0000:00:00.0/config
/sys/devices/pci0000:00/0000:00:01.0/config
<SNIP>
```


If we've gathered any passwords we should try them at this time for all users present on the system. Password re-use is common so we might get lucky!
