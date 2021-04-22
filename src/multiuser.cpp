
#include "XrdAcc/XrdAccAuthorize.hh"
#include "XrdOuc/XrdOucEnv.hh"
#include "XrdOuc/XrdOucPinPath.hh"
#include "XrdOuc/XrdOucStream.hh"
#include "XrdSec/XrdSecEntity.hh"
#include "XrdSec/XrdSecEntityAttr.hh"
#include "XrdSfs/XrdSfsInterface.hh"
#include "XrdVersion.hh"
#include "XrdOss/XrdOss.hh"

#include <exception>
#include <memory>
#include <mutex>
#include <vector>
#include <sstream>
#include <iomanip>

#include <dlfcn.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/capability.h>
#include <sys/fsuid.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

XrdVERSIONINFO(XrdOssGetFileSystem, Multiuser);

// The status-quo to retrieve the default object is to copy/paste the
// linker definition and invoke directly.
extern XrdAccAuthorize *XrdAccDefaultAuthorizeObject(XrdSysLogger   *lp,
                                                     const char     *cfn,
                                                     const char     *parm,
                                                     XrdVersionInfo &myVer);

// TODO: set this via library parameters.
static const int g_minimum_uid = 500;
static const int g_minimum_gid = 500;


class ErrorSentry
{
public:
    ErrorSentry(XrdOucErrInfo &dst_err, XrdOucErrInfo &src_err, bool forOpen = false)
        : m_dst_err(dst_err), m_src_err(src_err)
    {
        unsigned long long cbArg;
        XrdOucEICB *cbVal = dst_err.getErrCB(cbArg);

        if (forOpen)
        {
            src_err.setUCap(dst_err.getUCap());
        }
        src_err.setErrCB(cbVal, cbArg);
    }

    ~ErrorSentry()
    {
        if (m_src_err.getErrInfo())
        {
            m_dst_err = m_src_err;
        }
        else
        {
            m_dst_err.Reset();
        }
    }

private:
    XrdOucErrInfo &m_dst_err;
    XrdOucErrInfo &m_src_err;
};


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
}

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
        struct passwd pwd, *result = nullptr;

        // TODO: cache the lot of this.
        int buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (buflen < 0) {buflen = 16384;}
        std::vector<char> buf(buflen);

        int retval;

        // If we fail to get the username from the scitokens, then get it from
        // the depreciated way, client->name
        if (!got_token) {
            username = client->name;
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

class MultiuserFile : public XrdOssDF {
public:
    MultiuserFile(const char *user, std::unique_ptr<XrdOssDF> ossDF, XrdSysError &log) :
        XrdOssDF(user),
        m_wrapped(std::move(ossDF)),
        m_log(log)
    {}

    virtual ~MultiuserFile() {}

    int     Open(const char *path, int Oflag, mode_t Mode, XrdOucEnv &env) override
    {
        m_client = env.secEnv();
        UserSentry sentry(m_client, m_log);
        return m_wrapped->Open(path, Oflag, Mode, env);
    }

    int     Fchmod(mode_t mode) override
    {
        return m_wrapped->Fchmod(mode);
    }

    void    Flush() override
    {
        return m_wrapped->Flush();
    }

    int     Fstat(struct stat *buf) override
    {
        return m_wrapped->Fstat(buf);
    }

    int     Fsync() override
    {
        return m_wrapped->Fsync();
    }

    int     Fsync(XrdSfsAio *aiop) override
    {
        return m_wrapped->Fsync(aiop);
    }

    int     Ftruncate(unsigned long long size) override
    {
        return m_wrapped->Ftruncate(size);
    }

    off_t   getMmap(void **addr) override
    {
        return m_wrapped->getMmap(addr);
    }

    int     isCompressed(char *cxidp=0) override
    {
        return m_wrapped->isCompressed(cxidp);
    }

    ssize_t pgRead (void* buffer, off_t offset, size_t rdlen,
                        uint32_t* csvec, uint64_t opts) override
    {
        return m_wrapped->pgRead(buffer, offset, rdlen, csvec, opts);
    }

    int     pgRead (XrdSfsAio* aioparm, uint64_t opts) override
    {
        return m_wrapped->pgRead(aioparm, opts);
    }

    ssize_t pgWrite(void* buffer, off_t offset, size_t wrlen,
                        uint32_t* csvec, uint64_t opts) override
    {
        return m_wrapped->pgWrite(buffer, offset, wrlen, csvec, opts);
    }

    int     pgWrite(XrdSfsAio* aioparm, uint64_t opts) override
    {
        return m_wrapped->pgWrite(aioparm, opts);
    }

    ssize_t Read(off_t offset, size_t size) override
    {
        return m_wrapped->Read(offset, size);
    }

    ssize_t Read(void *buffer, off_t offset, size_t size) override
    {
        return m_wrapped->Read(buffer, offset, size);
    }

    int     Read(XrdSfsAio *aiop) override
    {
        return m_wrapped->Read(aiop);
    }

    ssize_t ReadRaw(void *buffer, off_t offset, size_t size) override
    {
        return m_wrapped->ReadRaw(buffer, offset, size);
    }

    ssize_t ReadV(XrdOucIOVec *readV, int rdvcnt) override
    {
        return m_wrapped->ReadV(readV, rdvcnt);
    }

    ssize_t Write(const void *buffer, off_t offset, size_t size) override
    {
        return m_wrapped->Write(buffer, offset, size);
    }

    int     Write(XrdSfsAio *aiop) override
    {
        return m_wrapped->Write(aiop);
    }

    ssize_t WriteV(XrdOucIOVec *writeV, int wrvcnt) override
    {
        return m_wrapped->WriteV(writeV, wrvcnt);
    }

    int Close(long long *retsz=0) 
    {
        return m_wrapped->Close(retsz);
    }


private:
    std::unique_ptr<XrdOssDF> m_wrapped;
    XrdSysError &m_log;
    const XrdSecEntity* m_client;
};

class MultiuserDirectory : public XrdOssDF {
public:
    MultiuserDirectory(const char *user, std::unique_ptr<XrdOssDF> ossDF, XrdSysError &log) :
        XrdOssDF(user),
        m_wrappedDir(std::move(ossDF)),
        m_log(log)
    {
    }

    virtual ~MultiuserDirectory() {}

    virtual int
    Opendir(const char *path,
            XrdOucEnv &env) override 
    {
        //ErrorSentry err_sentry(error, m_oss->error);
        m_client = env.secEnv();
        UserSentry sentry(m_client, m_log);
        return m_wrappedDir->Opendir(path, env);
    }

    int Readdir(char *buff, int blen) 
    {
        return m_wrappedDir->Readdir(buff, blen);
    }

    int StatRet(struct stat *statStruct) 
    {
        return m_wrappedDir->StatRet(statStruct);
    }

    int Close(long long *retsz=0) 
    {
        return m_wrappedDir->Close(retsz);
    }


private:
    std::unique_ptr<XrdOssDF> m_wrappedDir;
    XrdSysError m_log;
    const XrdSecEntity* m_client;

};

class MultiuserFileSystem : public XrdOss {
public:

    MultiuserFileSystem(XrdOss *oss, XrdSysLogger *lp, const char *configfn, XrdOucEnv *envP) :
        m_umask_mode(-1),
        m_oss(oss),
        m_env(envP),
        m_log(lp, "multiuser_")
    {
        if (!oss) {
            throw std::runtime_error("The multi-user plugin must be chained with another filesystem.");
        }
        m_log.Say("------ Initializing the multi-user plugin.");
    }

    virtual ~MultiuserFileSystem() {
    }

    // Object Allocation Functions
    //
    XrdOssDF *newDir(const char *user=0)
    {
        // Call the underlying OSS newDir
        std::unique_ptr<XrdOssDF> wrapped(m_oss->newDir(user));
        return (MultiuserDirectory *)new MultiuserDirectory(user, std::move(wrapped), m_log);
    }

    XrdOssDF *newFile(const char *user=0)
    {
        // Call the underlying OSS newFile
        std::unique_ptr<XrdOssDF> wrapped(m_oss->newFile(user));
        return (MultiuserFile *)new MultiuserFile(user, std::move(wrapped), m_log);
    }

    int Chmod(const char * path, mode_t mode, XrdOucEnv *env=0)
    {
        std::unique_ptr<UserSentry> sentryPtr;
        if (env) {
            auto client = env->secEnv();
            sentryPtr.reset(new UserSentry(client, m_log));
        }
        return m_oss->Chmod(path, mode, env);
    }

    void      Connect(XrdOucEnv &env)
    {
        auto client = env.secEnv();
        UserSentry sentry(client, m_log);
        m_oss->Connect(env);
    }

    int       Create(const char *tid, const char *path, mode_t mode, XrdOucEnv &env,
                         int opts=0)
    {
        auto client = env.secEnv();
        UserSentry sentry(client, m_log);
        return m_oss->Create(tid, path, mode, env, opts);
    }

    void      Disc(XrdOucEnv &env)
    {
        auto client = env.secEnv();
        UserSentry sentry(client, m_log);
        m_oss->Disc(env);
    }

    void      EnvInfo(XrdOucEnv *env)
    {
        // This will be cleaned up automatically
        std::unique_ptr<UserSentry> sentryPtr;
        if (env) {
            auto client = env->secEnv();
            sentryPtr.reset(new UserSentry(client, m_log));
        }
        m_oss->EnvInfo(env);
    }

    uint64_t  Features()
    {
        return m_oss->Features();
    }

    int       FSctl(int cmd, int alen, const char *args, char **resp=0)
    {
        return m_oss->FSctl(cmd, alen, args, resp);
    }

    int       Init(XrdSysLogger *lp, const char *cfn)
    {
        // Should I init something here?
        return 0;
    }

    int       Init(XrdSysLogger *lp, const char *cfn, XrdOucEnv *env)
    {
        return Init(lp, cfn);
    }

    int       Mkdir(const char *path, mode_t mode, int mkpath=0,
                        XrdOucEnv  *env=0)
    {
        std::unique_ptr<UserSentry> sentryPtr;
        if (env) {
            auto client = env->secEnv();
            sentryPtr.reset(new UserSentry(client, m_log));
        }
        return m_oss->Mkdir(path, mode, mkpath, env);
    }

    int       Reloc(const char *tident, const char *path,
                        const char *cgName, const char *anchor=0)
    {
        return m_oss->Reloc(tident, path, cgName, anchor);
        
    }
    
    int       Remdir(const char *path, int Opts=0, XrdOucEnv *env=0)
    {
        std::unique_ptr<UserSentry> sentryPtr;
        if (env) {
            auto client = env->secEnv();
            sentryPtr.reset(new UserSentry(client, m_log));
        }
        return m_oss->Remdir(path, Opts, env);
    }

    int       Rename(const char *oPath, const char *nPath,
                         XrdOucEnv  *oEnvP=0, XrdOucEnv *nEnvP=0)
    {
        // How to handle the renaming?
        std::unique_ptr<UserSentry> sentryPtr;
        if (oEnvP) {
            auto client = oEnvP->secEnv();
            sentryPtr.reset(new UserSentry(client, m_log));
        }
        return m_oss->Rename(oPath, nPath, oEnvP, nEnvP);
    }
    
    int       Stat(const char *path, struct stat *buff,
                       int opts=0, XrdOucEnv *env=0)
    {
        std::unique_ptr<UserSentry> sentryPtr;
        if (env) {
            auto client = env->secEnv();
            sentryPtr.reset(new UserSentry(client, m_log));
        }
        return m_oss->Stat(path, buff, opts, env);
    }

    int       Stats(char *buff, int blen)
    {
        return m_oss->Stats(buff, blen);
    }

    int       StatFS(const char *path, char *buff, int &blen,
                         XrdOucEnv  *env=0)
    {
        std::unique_ptr<UserSentry> sentryPtr;
        if (env) {
            auto client = env->secEnv();
            sentryPtr.reset(new UserSentry(client, m_log));
        }
        return m_oss->StatFS(path, buff, blen, env);
    }
    
    int       StatLS(XrdOucEnv &env, const char *path,
                         char *buff, int &blen)
    {
        auto client = env.secEnv();
        UserSentry sentry(client, m_log);
        return m_oss->StatLS(env, path, buff, blen);
    }
    
    int       StatPF(const char *path, struct stat *buff, int opts)
    {
        return m_oss->StatPF(path, buff, opts);
    }

    int       StatPF(const char *path, struct stat *buff)
    {
        return m_oss->StatPF(path, buff, 0);
    }

    int       StatVS(XrdOssVSInfo *vsP, const char *sname=0, int updt=0)
    {
        return m_oss->StatVS(vsP, sname, updt);
    }

    int       StatXA(const char *path, char *buff, int &blen,
                         XrdOucEnv *env=0)
    {
        std::unique_ptr<UserSentry> sentryPtr;
        if (env) {
            auto client = env->secEnv();
            sentryPtr.reset(new UserSentry(client, m_log));
        }
        return m_oss->StatXA(path, buff, blen, env);
    }

    int       StatXP(const char *path, unsigned long long &attr,
                         XrdOucEnv  *env=0)
    {
        std::unique_ptr<UserSentry> sentryPtr;
        if (env) {
            auto client = env->secEnv();
            sentryPtr.reset(new UserSentry(client, m_log));
        }
        return m_oss->StatXP(path, attr, env);
    }
    
    int       Truncate(const char *path, unsigned long long fsize,
                           XrdOucEnv *env=0)
    {
        std::unique_ptr<UserSentry> sentryPtr;
        if (env) {
            auto client = env->secEnv();
            sentryPtr.reset(new UserSentry(client, m_log));
        }
        return m_oss->Truncate(path, fsize, env);
    }
    
    int       Unlink(const char *path, int Opts=0, XrdOucEnv *env=0)
    {
        std::unique_ptr<UserSentry> sentryPtr;
        if (env) {
            auto client = env->secEnv();
            sentryPtr.reset(new UserSentry(client, m_log));
        }
        return m_oss->Unlink(path, Opts, env);
    }

    int       Lfn2Pfn(const char *Path, char *buff, int blen)
    {
        return m_oss->Lfn2Pfn(Path, buff, blen);
    }
    
    const char       *Lfn2Pfn(const char *Path, char *buff, int blen, int &rc)
    {
        return m_oss->Lfn2Pfn(Path, buff, blen, rc);
    }


private:
    mode_t m_umask_mode;
    XrdOss *m_oss;  // NOTE: we DO NOT own this pointer; given by the caller.  Do not make std::unique_ptr!
    XrdOucEnv *m_env;
    XrdSysError m_log;
    std::shared_ptr<XrdAccAuthorize> m_authz;
    
};

extern "C" {

/*
    This function is called when we are wrapping something.  curr_oss is already initialized
*/
XrdOss *XrdOssAddStorageSystem2(XrdOss       *curr_oss,
                                XrdSysLogger *Logger,
                                const char   *config_fn,
                                const char   *parms,
                                XrdOucEnv    *envP)
{

    XrdSysError log(Logger, "multiuser_");

    if (!check_caps(log)) {
        return nullptr;
    }

    try {
        return new MultiuserFileSystem(curr_oss, Logger, config_fn, envP);
    } catch (std::runtime_error &re) {
        log.Emsg("Initialize", "Encountered a runtime failure:", re.what());
        return nullptr;
    }
}

/* 
    This function is called when it is the top level file system and we are not
    wrapping anything
*/
XrdOss *XrdOssGetStorageSystem2(XrdOss       *native_oss,
                                XrdSysLogger *Logger,
                                const char   *config_fn,
                                const char   *parms,
                                XrdOucEnv    *envP)
{
    XrdSysError log(Logger, "multiuser_");
    if (native_oss->Init(Logger, config_fn, envP) != 0) {
        log.Emsg("Initialize", "Multiuser failed to initialize the native.");
    }
    return XrdOssAddStorageSystem2(native_oss, Logger, config_fn, parms, envP);
}


XrdOss *XrdOssGetStorageSystem(XrdOss       *native_oss,
                               XrdSysLogger *Logger,
                               const char   *config_fn,
                               const char   *parms)
{
    XrdSysError log(Logger, "multiuser_");
    if (native_oss->Init(Logger, config_fn) != 0) {
        log.Emsg("Initialize", "Multiuser failed to initialize the native.");
    }
    return XrdOssAddStorageSystem2(native_oss, Logger, config_fn, parms, nullptr);
}



}

XrdVERSIONINFO(XrdOssGetStorageSystem,osg-multiuser);
XrdVERSIONINFO(XrdOssGetStorageSystem2,osg-multiuser);
XrdVERSIONINFO(XrdOssAddStorageSystem2,osg-multiuser);
