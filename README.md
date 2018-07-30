
Multi-user SFS plugin for Xrootd
================================

A filesystem plugin to allow Xrootd to interact with underlying POSIX filesystems as
different Unix users.

This plugin will change the thread's filesystem UID to match Xrootd's user name, meaning a user with a login session
mapped to user name `atlas` will read and write to the filesystem as the UID associated with the Unix user `atlas`.
Without this plugin, Xrootd will always read and write as the Unix user `xrootd`.


Configuration
-------------

To configure the multi-user plugin, add the following line to the Xrootd configuration file:

```
xrootd.fslib libXrdMultiuser.so default
```

The plugin can also be used to manage the `umask` when creating files or directories.  To set a `umask`
(for example, to `0022`), add the following line to the Xrootd configuration file:

```
multiuser.umask 0022
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
