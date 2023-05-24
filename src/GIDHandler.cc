#include "GIDHandler.hh"
#include "UserSentry.hh"
#include "XrdOss/XrdOss.hh"
#include "XrdSys/XrdSysError.hh"

#include <grp.h>

#include <algorithm>

namespace {

int RightStrip(const std::string &filename, size_t start_off)
{
    auto off = start_off;
    while (true) {
        if (filename[off] == '/') {
            if (off == 0) {return -1;}
            off -= 1;
        } else {
            break;
        }
    }
    return off; 
}

bool GetParentDir(const std::string file, std::string &parent_output)
{
    std::string parent = file;
    auto off = RightStrip(parent, parent.size() - 1);
    if (off == -1) {return false;}

    auto last_slash = parent.rfind('/', off);
    if (last_slash == std::string::npos) {
        return false;
    }

    off = RightStrip(parent, last_slash - 1);
    if (off == -1) {
        parent_output = "/";
        return true;
    }

    parent_output = file.substr(0, off + 1);
    return true;
}

int DetermineGID_impl_stat(XrdOss &oss, XrdOucEnv &env, XrdSysError &log,
    const std::string &username, int pgid, const std::string &path, struct stat &buff,
    bool &sticky_gid, int &result);

int DetermineGID_impl(XrdOss &oss, XrdOucEnv &env, XrdSysError &log,
    const std::string &username, int pgid, const std::string &path, bool is_root, bool &sticky_gid)
{
    // First, invoke 'stat' on the file as root; if not present, we don't
    // need to lookup any GIDs.  Note we have the stat done in a small helper
    // function to avoid repetition.
    struct stat buff;
    int res, result;
    if (is_root) {
        res = DetermineGID_impl_stat(oss, env, log, username, pgid, path, buff, sticky_gid, result);
    } else {
        DacOverrideSentry sentry(log);
        res = DetermineGID_impl_stat(oss, env, log, username, pgid, path, buff, sticky_gid, result);
    }
    if (res == -ENOENT) {return result;}
    sticky_gid = (S_ISGID & buff.st_mode) == S_ISGID;

    // We now know the group ownership and the mode.
    // Before DetermineGID got called, we got a permission denied so we know the
    // user- and owner-based access doesn't permit the operation to occur.  Hence,
    // we should see if group-based access is allowed for one of the groups this user
    // is a member of.
    std::vector<gid_t> groups;
    groups.resize(16, -1);
    int actual_ngroups = 16;
    if (getgrouplist(username.c_str(), pgid, &groups[0], &actual_ngroups) == -1) {
        groups.resize(actual_ngroups, -1);
        if (getgrouplist(username.c_str(), pgid, &groups[0], &actual_ngroups) == -1) {
            return -EIO;
        }
    }
    groups.resize(actual_ngroups, -1);
    const auto iter = std::find(groups.begin(), groups.end(), buff.st_gid);
    if (iter != groups.end()) return buff.st_gid;
    return -EACCES;
}

int DetermineGID_impl_stat(XrdOss &oss, XrdOucEnv &env, XrdSysError &log,
    const std::string &username, int pgid, const std::string &path,
    struct stat &buff, bool &sticky_gid, int &result)
{
    int res = oss.Stat(path.c_str(), &buff, 0, &env);
    if (res == -ENOENT) {
        // In this case, we need to look at the parent directory to see if it is
        // readable by the desired user; recurse until we find a parent directory that exists.
        std::string parent;
        if (!GetParentDir(path, parent)) {
            return -EINVAL;
        }   
        result = DetermineGID_impl(oss, env, log, username, pgid, parent, true, sticky_gid);
    } else {
        sticky_gid = false;
    }
    return res;
}

}


int DetermineGID(XrdOss &oss, XrdOucEnv &env, XrdSysError &log, const std::string &username, int pgid, const std::string &path, bool &sticky_gid)
{
    sticky_gid = false;
    return DetermineGID_impl(oss, env, log, username, pgid, path, false, sticky_gid);
}
