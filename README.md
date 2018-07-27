
Multi-user SFS plugin for Xrootd
================================

A filesystem plugin to allow Xrootd to interact with underlying POSIX filesystems as
different users.

This plugin will change the thread's filesystem UID to match the logged in user name, meaning a user logging into
the `xrootd` as user `atlas` will read and write to the filesystem as the UID associated with the Unix user `atlas`;
without this, Xrootd will always read and write as the Unix user `xrootd`.

To configure, add the following line to the Xrootd configuration file:

```
xrootd.fslib libXrdMultiuser.so default
```

Additionally, the Xrootd process must be started with the appropriate Linux capabilities in order to successfully
read and write as different users (i.e., execute the `setfsuid` and `setfsgid` calls).  To suppor this, we have a
separate systemd unit called `xrootd-privileged@.service`.

So, to start the configuration in `/etc/xrootd/xrootd-clusterd.cfg` with the multiuser plugin enabled, execute:

```
systemctl start xrootd-privileged@clustered
```
