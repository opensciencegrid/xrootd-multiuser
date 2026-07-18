
Multi-user OSS and CKS (checksum) plugin for Xrootd
================================

A filesystem plugin to allow Xrootd to interact with underlying POSIX filesystems as
different Unix users.

This plugin will change the thread's filesystem UID to match Xrootd's user name, meaning a user with a login session
mapped to user name `atlas` will read and write to the filesystem as the UID associated with the Unix user `atlas`.
Without this plugin, Xrootd will always read and write as the Unix user `xrootd`.


Configuration
-------------

To configure the multi-user plugin, add the following line to the Xrootd configuration file (XRootD 5.0+):

```
ofs.osslib ++ libXrdMultiuser.so
```

To enable the checksum (only on XRootD 5.2+):

```
ofs.ckslib * libXrdMultiuser.so
```

The following optional directives can also be set in the Xrootd configuration file:

| Directive | Default | Description |
| --- | --- | --- |
| `multiuser.umask <octal>` | (unset) | Apply this umask to files and directories created through the plugin. |
| `multiuser.checksumonwrite <on\|off>` | `off` | Compute checksums while a file is being written. |
| `multiuser.minuid <n>` | `500` | Minimum UID a mapped username may resolve to; usernames mapping to a lower UID are treated as system accounts and denied. |
| `multiuser.mingid <n>` | `500` | Minimum GID a mapped username may resolve to; usernames mapping to a lower GID are treated as system accounts and denied. |

For example, to allow users and groups with IDs as low as 100 (e.g., groups
imported from a Lustre file system):

```
multiuser.minuid 100
multiuser.mingid 100
```

Startup
-------

The Xrootd process must be started with the privileged Linux capabilities in order to successfully
read and write as different users (i.e., execute the `setfsuid` and `setfsgid` calls).  To support this, we have a
separate systemd unit called `xrootd-privileged@.service`.

To start the configuration in `/etc/xrootd/xrootd-clustered.cfg` with the multiuser plugin enabled, execute:

```
systemctl start xrootd-privileged@clustered
```
