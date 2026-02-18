
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

### Write Buffering

To reduce IOPS from small sequential writes, you can enable write buffering:

```
multiuser.writebuffersize <bytes>
```

Where `<bytes>` is the buffer size in bytes. Default is 0 (disabled). When enabled:
- Sequential writes smaller than the buffer size are accumulated in memory
- The buffer is flushed when full, when a non-sequential write occurs, or when the file is closed
- Buffering is automatically disabled for a file if non-sequential writes are detected

Example: Buffer up to 1MB of writes:
```
multiuser.writebuffersize 1048576
```

**Note:** Buffering is only suitable for sequential write workloads. Non-sequential writes will cause the buffer to be flushed and buffering disabled for that file.

Startup
-------

The Xrootd process must be started with the privileged Linux capabilities in order to successfully
read and write as different users (i.e., execute the `setfsuid` and `setfsgid` calls).  To support this, we have a
separate systemd unit called `xrootd-privileged@.service`.

To start the configuration in `/etc/xrootd/xrootd-clustered.cfg` with the multiuser plugin enabled, execute:

```
systemctl start xrootd-privileged@clustered
```
