
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
#include "XrdChecksum.hh"
#include "MultiuserFileSystem.hh"
#include "MultiuserFile.hh"
#include "UserSentry.hh"
#include "GIDHandler.hh"

#include <exception>
#include <memory>
#include <mutex>
#include <vector>
#include <sstream>
#include <iomanip>

MultiuserFileSystem* g_multisuer_oss = nullptr;
ChecksumManager* g_checksum_manager = nullptr;

bool UserSentry::m_is_cmsd = false;

XrdVERSIONINFO(XrdOssGetFileSystem, Multiuser);

// The status-quo to retrieve the default object is to copy/paste the
// linker definition and invoke directly.
extern XrdAccAuthorize *XrdAccDefaultAuthorizeObject(XrdSysLogger   *lp,
                                                     const char     *cfn,
                                                     const char     *parm,
                                                     XrdVersionInfo &myVer);


bool UserSentry::ConfigCaps(XrdSysError &log, XrdOucEnv *envP) {

    char *argv0 = nullptr, *myProg = nullptr;
    XrdOucEnv *xrdEnvP = envP ? static_cast<XrdOucEnv *>(envP->GetPtr("xrdEnv*")) : nullptr;
    if (xrdEnvP && (argv0 = static_cast<char *>(xrdEnvP->GetPtr("argv[0]")))) {
        auto retc = strlen(argv0);
        while(retc--) if (argv0[retc] == '/') break;
        myProg = &argv0[retc+1];
    }
    m_is_cmsd = myProg && !strcmp(myProg, "cmsd");

    // See if we have the appropriate capabilities to run this plugin.
    cap_t caps = cap_get_proc();
    if (caps == NULL) {
        log.Emsg("Initialize", "Failed to query daemon thread's capabilities", strerror(errno));
        return false;
    }
    cap_value_t cap_list[2];
    int caps_to_set = 0;
    cap_flag_value_t test_flag = CAP_CLEAR;
    // We must be at least permitted to acquire the needed capabilities.
    cap_get_flag(caps, CAP_SETUID, CAP_PERMITTED, &test_flag);
    if (test_flag == CAP_CLEAR) {
        log.Emsg("check_caps", "CAP_SETUID not in daemon's permitted set");
        cap_free(caps);
        return false;
    }
    cap_get_flag(caps, CAP_SETGID, CAP_PERMITTED, &test_flag);
    if (test_flag == CAP_CLEAR) {
        log.Emsg("check_caps", "CAP_SETGID not in daemon's permitted set");
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


MultiuserFile::MultiuserFile(const char *user, std::unique_ptr<XrdOssDF> ossDF, XrdSysError &log, mode_t umask_mode, bool checksum_on_write, unsigned digests, MultiuserFileSystem *oss) :
    XrdOssDF(user),
    m_wrapped(std::move(ossDF)),
    m_log(log),
    m_umask_mode(umask_mode),
    m_state(NULL),
    m_nextoff(0),
    m_oss(oss),
    m_checksum_on_write(checksum_on_write),
    m_digests(digests)
{}

int     MultiuserFile::Open(const char *path, int Oflag, mode_t Mode, XrdOucEnv &env)
{
    if (((Mode & 0777) == (S_IRUSR | S_IWUSR)) && (m_umask_mode != static_cast<mode_t>(-1)))
    {
        Mode |= 0777;
    }
    m_fname = path;
    m_client = env.secEnv();
    UserSentry sentry(m_client, m_log);
    if (!sentry.IsValid()) return -EACCES;

    auto open_result = m_wrapped->Open(path, Oflag, Mode, env);
    if (open_result == -EACCES) {
        // If the file-open failed, then we go looking for secondary GIDs that might
        // provide us with access.
        bool sticky_gid;
        auto sgid_result = DetermineGID(*m_oss->GetWrappedOss(), env, m_log, sentry.username(),
            sentry.pgid(), path, sticky_gid);
        if (sgid_result >= 0) {
            GidSentry gsentry(sgid_result, m_log);
            if (!gsentry.IsValid()) return -EACCES;

            open_result = m_wrapped->Open(path, Oflag, Mode, env);
            if (open_result == XrdOssOK && sticky_gid) {
                fd = m_wrapped->getFD();
                // We call the POSIX `fchown` directly on the underlying fd as root;
                // this is necessary because the OSS API doesn't have a `fchown` of its own.
                if (fd >= 0) {
                    DacOverrideSentry dacsentry(m_log);
                    fchown(fd, -1, sentry.pgid());
                }
            }
        }
    }

    if ((Oflag & (O_WRONLY | O_RDWR)) && m_checksum_on_write)
    {
        m_state = new ChecksumState(m_digests);
        m_log.Emsg("Open", "Will create checksums");
    } else {
        m_log.Emsg("Open", "Will not create checksum");
    }

    return open_result;
}



ssize_t MultiuserFile::Write(const void *buffer, off_t offset, size_t size)
{

    if ((offset != m_nextoff) && m_state) 
    {   
        std::stringstream ss;
        ss << "Out-of-order writes not supported while running checksum. " << m_fname;
        m_log.Emsg("Write", ss.str().c_str());
        return -ENOTSUP;
    }

    auto result = m_wrapped->Write(buffer, offset, size);
    if (result >= 0) {m_nextoff += result;}
    if (m_state)
    {
        m_state->Update(static_cast<const unsigned char*>(buffer), size);
    }
    return result;
}



int MultiuserFile::Close(long long *retsz) 
{
    auto close_result = m_wrapped->Close(retsz);
    if (m_state)
    {
        m_state->Finalize();
        if (close_result == XrdOssOK) {
            // Only write checksum file if close() was successful
            {
                UserSentry sentry(m_client, m_log);
                if (sentry.IsValid()) {
                    g_checksum_manager->Set(m_fname.c_str(), *m_state);
                }
            }
            
        }
        delete m_state;
        m_state = NULL;
    }

    return close_result;
}

/*
 Multiuser compatible checksum wrapper.  Only available in XRootD 5.2+
*/
class MultiuserChecksum : public XrdCksWrapper
{
public:
    MultiuserChecksum(XrdCks &prevPI, XrdSysError *errP) :
    XrdCksWrapper(prevPI, errP),
    m_log(errP)
    {

    }

    virtual ~MultiuserChecksum() {}

    /*
        Generate the UserSentry object.
        The returned UserSentry is the responsibility of the caller.
    */
    UserSentry* GenerateUserSentry(XrdOucEnv* env) {
        if (env) {
            auto client = env->secEnv();
            if (client) {
                return new UserSentry(client, *m_log);
            } else {
                // Look up the username in the env
                auto username = env->Get("request.name");
                if (username) {
                    return new UserSentry(username, *m_log);
                } else {
                    return nullptr;
                }
            }
        }
        return nullptr;
    }

    virtual
    int        Calc( const char *Xfn, XrdCksData &Cks, int doSet=1)
    {
        std::unique_ptr<UserSentry> sentryPtr(GenerateUserSentry(Cks.envP));
        if (!sentryPtr->IsValid()) return -EACCES;
        return cksPI.Calc(Xfn, Cks, doSet);
    }

    virtual
    int        Calc( const char *Xfn, XrdCksData &Cks, XrdCksPCB *pcbP, int doSet=1)
    {
        (void)pcbP;
        return Calc(Xfn, Cks, doSet);
    }

    virtual
    int        Del(  const char *Xfn, XrdCksData &Cks)
    {
        std::unique_ptr<UserSentry> sentryPtr(GenerateUserSentry(Cks.envP));
        if (!sentryPtr->IsValid()) return -EACCES;
        return cksPI.Del(Xfn, Cks);
    }

    virtual
    int        Get(  const char *Xfn, XrdCksData &Cks)
    {
        std::unique_ptr<UserSentry> sentryPtr(GenerateUserSentry(Cks.envP));
        if (!sentryPtr->IsValid()) return -EACCES;
        return cksPI.Get(Xfn, Cks);
    }

    virtual
    int        Set(  const char *Xfn, XrdCksData &Cks, int myTime=0)
    {
        std::unique_ptr<UserSentry> sentryPtr(GenerateUserSentry(Cks.envP));
        if (!sentryPtr->IsValid()) return -EACCES;
        return cksPI.Set(Xfn, Cks, myTime);
    }

    virtual
    int        Ver(  const char *Xfn, XrdCksData &Cks)
    {
        std::unique_ptr<UserSentry> sentryPtr(GenerateUserSentry(Cks.envP));
        if (!sentryPtr->IsValid()) return -EACCES;
        return cksPI.Ver(Xfn, Cks);
    }

    virtual
    int        Ver(  const char *Xfn, XrdCksData &Cks, XrdCksPCB *pcbP)
    {
        (void)pcbP; 
        return Ver(Xfn, Cks);
    }

    virtual
    char      *List(const char *Xfn, char *Buff, int Blen, char Sep=' ')
    {
        //std::unique_ptr<UserSentry> sentryPtr(GenerateUserSentry(Cks.envP));
        return cksPI.List(Xfn, Buff, Blen, Sep);
    }

private:
    XrdSysError *m_log;

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

    if (!UserSentry::ConfigCaps(log, envP)) {
        return nullptr;
    }

    envP->Export("XRDXROOTD_NOPOSC", "1");

    try {
        g_multisuer_oss = new MultiuserFileSystem(curr_oss, Logger, config_fn, envP);
        return g_multisuer_oss;
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
        return nullptr;
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
        return nullptr;
    }
    return XrdOssAddStorageSystem2(native_oss, Logger, config_fn, parms, nullptr);
}

XrdCks *XrdCksAdd2(XrdCks      &pPI,
                   XrdSysError *eDest,
                   const char  *cFN,
                   const char  *Parm,
                   XrdOucEnv   *envP)
{
    //XrdSysError log(eDest, "multiuser_checksum_");

    if (!UserSentry::ConfigCaps(*eDest, envP)) {
        return nullptr;
    }

    try {
        return new MultiuserChecksum(pPI, eDest);
    } catch (std::runtime_error &re) {
        eDest->Emsg("Initialize", "Encountered a runtime failure:", re.what());
        return nullptr;
    }

}

XrdCks *XrdCksInit(XrdSysError *eDest,
                                  const char  *cFN,
                                  const char  *Parms
                                  )
{
    // ChecksumManager(XrdSysError *erP, int iosz,
        // XrdVersionInfo &vInfo, bool autoload=false):
    XrdVERSIONINFODEF(vInfo, ChecksumManager, XrdVNUMBER, XrdVERSION);
    ChecksumManager *manager = new ChecksumManager(eDest, 65000, vInfo);
    g_checksum_manager = manager;
    return XrdCksAdd2(*manager, eDest, cFN, Parms, nullptr);
}


}

XrdVERSIONINFO(XrdOssGetStorageSystem,osg-multiuser);
XrdVERSIONINFO(XrdOssGetStorageSystem2,osg-multiuser);
XrdVERSIONINFO(XrdOssAddStorageSystem2,osg-multiuser);
XrdVERSIONINFO(XrdCksAdd2,osg-multiuser);
XrdVERSIONINFO(XrdCksInit,osg-multiuser);
