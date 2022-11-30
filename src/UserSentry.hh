#ifndef __MULTIUSERUSERSENTRY_HH__
#define __MULTIUSERUSERSENTRY_HH__

#include "XrdAcc/XrdAccAuthorize.hh"
#include "XrdOuc/XrdOucEnv.hh"
#include "XrdOuc/XrdOucPinPath.hh"
#include "XrdOuc/XrdOucStream.hh"
#include "XrdSec/XrdSecEntity.hh"
#include "XrdSec/XrdSecEntityAttr.hh"
#include "XrdSfs/XrdSfsInterface.hh"
#include "XrdVersion.hh"
#include "XrdOss/XrdOss.hh"
#include "XrdCks/XrdCksWrapper.hh"

#include <dlfcn.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/capability.h>
#include <sys/fsuid.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// TODO: set this via library parameters.
static const int g_minimum_uid = 500;
static const int g_minimum_gid = 500;


/**
 * Note: originally, we tried to use CAP_DAC_READ_SEARCH as that provides exactly what we need -
 * the ability to override the read/execute permissions of directories.  However, it turns out
 * that shared filesystems (at least, NFS and CephFS) don't understand Linux capabilities, ignore
 * the setting, and go solely by the FS UID/GID.  Hence, we *must* use the big hammer of setfsuid
 * instead of the svelte CAP_DAC_READ_SEARCH.
 */
class DacOverrideSentry {
public:
    DacOverrideSentry(XrdSysError &log) :
        m_log(log)
    {
        //m_log.Emsg("UserSentry", "Switching FS uid for root");
        m_orig_uid = setfsuid(0);
        if (m_orig_uid < 0) {
            //m_log.Emsg("UserSentry", "Failed to switch FS uid for root");
            return;
        }
    }

    ~DacOverrideSentry()
    {
        if ((m_orig_uid != -1) && (-1 == setfsuid(m_orig_uid))) {
            m_log.Emsg("UserSentry", "Failed to return fsuid to original state", strerror(errno));
        }
    }

    bool IsValid() const {return m_orig_uid != -1;}

private:
    int m_orig_uid{-1};
    XrdSysError &m_log;
};


class UserSentry {
public:
    UserSentry(const XrdSecEntity *client, XrdSysError &log) :
        m_log(log)
    {
        if (!client) {
            log.Emsg("UserSentry", "No security entity object provided");
            return;
        }
        // get the username from the extra attributes in the client
        std::string username;
        auto got_token = client->eaAPI->Get("request.name", username);
        if (!got_token && (!client->name || !client->name[0])) {
            // Anonymous client; no user set
            this->Init("", log);
            return;
        }

        // If we fail to get the username from the scitokens, then get it from
        // the depreciated way, client->name
        if (!got_token) {
            username = client->name;
        }
        this->Init(username, log);
    }

    UserSentry(const std::string username, XrdSysError &log) :
        m_log(log)
    {
        this->Init(username, log);
    }

    static bool ConfigCaps(XrdSysError &log, XrdOucEnv *envP);

    static bool IsCmsd() {return m_is_cmsd;}

    void Init(const std::string username, XrdSysError &log)
    {
        struct passwd pwd, *result = nullptr;

        // TODO: cache the lot of this.
        int buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (buflen < 0) {buflen = 16384;}
        std::vector<char> buf(buflen);

        int retval;

        if (username.empty()) {
            log.Emsg("UserSentry", "Anonymous client; no user set, cannot change FS UIDs");
            m_is_anonymous = true;
            return;
        }

        do {
            retval = getpwnam_r(username.c_str(), &pwd, &buf[0], buflen, &result);
            if ((result == nullptr) && (retval == ERANGE)) {
                buflen *= 2;
                buf.resize(buflen);
                continue;
            }
            break;
        } while (1);
        if (result == nullptr) {
            if (retval) {  // There's an actual error in the lookup.
                m_log.Emsg("UserSentry", "Failure when looking up UID for username", username.c_str(), strerror(retval));
            } else {  // Username doesn't exist.
                m_log.Emsg("UserSentry", "XRootD mapped request to username that does not exist:", username.c_str());
            }
            return;
        }
        if (pwd.pw_uid < g_minimum_uid) {
            m_log.Emsg("UserSentry", "Username", username.c_str(), "maps to a system UID; rejecting lookup");
            return;
        }
        if (pwd.pw_gid < g_minimum_gid) {
            m_log.Emsg("UserSentry", "Username", username.c_str(), "maps to a system GID; rejecting lookup");
            return;
        }

        // Note: Capabilities need to be set per thread, so we need to do this
        ConfigCaps(m_log, nullptr);

        // TODO: One log line per FS open seems noisy -- could make this configurable.
        m_log.Emsg("UserSentry", "Switching FS uid for user", username.c_str());
        m_orig_uid = setfsuid(result->pw_uid);
        if (m_orig_uid < 0) {
            m_log.Emsg("UserSentry", "Failed to switch FS uid for user", username.c_str());
            return;
        }
        m_orig_gid = setfsgid(result->pw_gid);
    }

    ~UserSentry() {
        if ((m_orig_uid != -1) && (-1 == setfsuid(m_orig_uid))) {
            m_log.Emsg("UserSentry", "Failed to return fsuid to original state", strerror(errno));
        }
        if ((m_orig_gid != -1) && (-1 == setfsgid(m_orig_gid))) {
            m_log.Emsg("UserSentry", "Failed to return fsgid to original state", strerror(errno));
        }
    }

    bool IsValid() const {return ((m_orig_gid != -1) && (m_orig_uid != -1)) || m_is_anonymous;}

private:
    // Note I am not using `uid_t` and `gid_t` here in order
    // to have the ability to denote an invalid ID (-1)
    int m_orig_uid{-1};
    int m_orig_gid{-1};
    bool m_is_anonymous{false};

    static bool m_is_cmsd;

    XrdSysError &m_log;
};

#endif
