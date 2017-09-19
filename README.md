
Multi-user SFS plugin for Xrootd
================================

A filesystem plugin to allow Xrootd to interact with underlying POSIX filesystems as
different users.

This plugin will change the thread's filesystem UID to match the logged in user name, meaning a user logging into
the `xrootd` as user `atlas` will read and write to the filesystem as the UID associated with the Unix user `atlas`;
without this, Xrootd will always read and write as the Unix user `xrootd`.

To configure, add the following line to the Xrootd configuration file:

```
ofs.authlib libXrdAccSciTokens.so default
```

Additionally, the Xrootd process must be started with the appropriate Linux capabilities in order to successfully
execute the `setfsuid` and `setfsgid` calls.  To do this, first set the capabilities on the file `/usr/bin/xrootd` itself:

```
setcap 'cap_setgid+ep cap_setuid+ep' /usr/bin/xrootd
```

Alternately, you may want to copy this to a different binary, such as `/usr/bin/xrootd-privileged`.  Symlinks do not work with capabilities.

Then, override the systemd unit by creating an override directory:

```
# mkdir /etc/systemd/system/xrootd@multiuser.service.d/
```

Then, in `/etc/systemd/system/xrootd@multiuser.service.d/override.conf`:

```
[Service]
CapabilityBoundingSet=CAP_SETUID CAP_SETGID
```

This is assuming that you are trying to start with the configuration in `/etc/xrootd/xrootd-multiuser.cfg`.
