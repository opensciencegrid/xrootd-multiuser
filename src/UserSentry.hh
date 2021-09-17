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

static bool check_caps(XrdSysError &log) {
    // See if we have the appropriate capabilities to run this plugin.
    cap_t caps = cap_get_proc();
    if (caps == NULL) {
        log.Emsg("Initialize", "Failed to query xrootd daemon thread's capabilities", strerror(errno));
        return false;
    }
    cap_value_t cap_list[2];
    int caps_to_set = 0;
    cap_flag_value_t test_flag = CAP_CLEAR;
    // We must be at least permitted to acquire the needed capabilities.
    cap_get_flag(caps, CAP_SETUID, CAP_PERMITTED, &test_flag);
    if (test_flag == CAP_CLEAR) {
        log.Emsg("check_caps", "CAP_SETUID not in xrootd daemon's permitted set");
        cap_free(caps);
        return false;
    }
    cap_get_flag(caps, CAP_SETGID, CAP_PERMITTED, &test_flag);
    if (test_flag == CAP_CLEAR) {
       log.Emsg("check_caps", "CAP_SETGID not in xrootd daemon's permitted set");
        cap_free(caps);
       return false;
    }

    // Determine which new capabilities are needed to be added to the effective set.
    cap_get_flag(caps, CAP_SETUID, CAP_EFFECTIVE, &test_flag);
    if (test_flag == CAP_CLEAR) {
        //log.Emsg("Initialize", "Will request effective capability for CAP_SETUID");
        cap_list[caps_to_set] = CAP_SETUID;
        caps_to_set++;
    }
    cap_get_flag(caps, CAP_SETGID, CAP_EFFECTIVE, &test_flag);
    if (test_flag == CAP_CLEAR) {
        //log.Emsg("Initialize", "Will request effective capability for CAP_SETGID");
        cap_list[caps_to_set] = CAP_SETGID;
        caps_to_set++;
    }
    if (caps_to_set && cap_set_flag(caps, CAP_EFFECTIVE, caps_to_set, cap_list, CAP_SET) == -1) {
        log.Emsg("Initialize", "Failed to add capabilities to the requested list.");
        cap_free(caps);
        return false;
    }
    if (caps_to_set && (cap_set_proc(caps) == -1)) {
        log.Emsg("Initialize", "Failed to acquire necessary capabilities for thread");
        cap_free(caps);
        return false;
    }
    cap_free(caps);
    return true;
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
            log.Emsg("UserSentry", "Anonymous client; no user set, cannot change FS UIDs");
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

    void Init(const std::string username, XrdSysError &log)
    {
        struct passwd pwd, *result = nullptr;

        // TODO: cache the lot of this.
        int buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (buflen < 0) {buflen = 16384;}
        std::vector<char> buf(buflen);

        int retval;

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
            m_log.Emsg("UserSentry", "Failed to lookup UID for username", username.c_str(), strerror(retval));
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

        if (!check_caps(m_log)) {
            m_log.Emsg("UserSentry", "Unable to get correct capabilities for this thread - filesystem action likely to fail.");
        }

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

private:
    // Note I am not using `uid_t` and `gid_t` here in order
    // to have the ability to denote an invalid ID (-1)
    int m_orig_uid{-1};
    int m_orig_gid{-1};

    XrdSysError &m_log;
};

#endif