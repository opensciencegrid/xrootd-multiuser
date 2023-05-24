/**
 * Handling of supplementary GIDs for XRootD multiuser.
 *
 * The multiuser plugin extensively utilizes the "filesystem UID/GID" within Linux.
 * Unfortunately, this only allows for a *single* GID to be set.  These functions
 * help emulate the POSIX logic around multiple GIDs to determine what GID should be
 * used for a filesystem operation.
 */
#pragma once

#include <string>

// Forward dec'ls.
class XrdOss;
class XrdOucEnv;
class XrdSysError;

/**
 * Given a username and a path, determine which supplemental GID should
 * be used to access the path as the filesystem GID.
 *
 * Returns a non-negative GID on success; on failure, returns the -errno
 * that should be used for the filesystem call.
 */
int DetermineGID(XrdOss &oss, XrdOucEnv &env, XrdSysError &log,
                 const std::string &username, int pgid, const std::string &path,
                 bool &sticky_gid);
