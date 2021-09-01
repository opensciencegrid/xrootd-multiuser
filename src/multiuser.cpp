
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

#include <exception>
#include <memory>
#include <mutex>
#include <vector>
#include <sstream>
#include <iomanip>



XrdVERSIONINFO(XrdOssGetFileSystem, Multiuser);

// The status-quo to retrieve the default object is to copy/paste the
// linker definition and invoke directly.
extern XrdAccAuthorize *XrdAccDefaultAuthorizeObject(XrdSysLogger   *lp,
                                                     const char     *cfn,
                                                     const char     *parm,
                                                     XrdVersionInfo &myVer);




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




MultiuserFile::MultiuserFile(const char *user, std::unique_ptr<XrdOssDF> ossDF, XrdSysError &log, mode_t umask_mode, MultiuserFileSystem *oss) :
    XrdOssDF(user),
    m_wrapped(std::move(ossDF)),
    m_log(log),
    m_umask_mode(umask_mode),
    m_state(NULL),
    m_nextoff(0),
    m_oss(oss)
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

    auto open_result = m_wrapped->Open(path, Oflag, Mode, env);

    if (Oflag & (O_WRONLY | O_RDWR))
    {
        m_state = new ChecksumState(ChecksumManager::ALL);
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
        return ENOTSUP;
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
            ChecksumManager manager(NULL, &m_log);
            char pfnbuf[PATH_MAX];
            int rc;
            const char *pfn = m_oss->Lfn2Pfn(m_fname.c_str(), pfnbuf, PATH_MAX, rc);
            {
                UserSentry sentry(m_client, m_log);
                manager.Set(pfn, *m_state);
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
        return cksPI.Del(Xfn, Cks);
    }

    virtual
    int        Get(  const char *Xfn, XrdCksData &Cks)
    {
        std::unique_ptr<UserSentry> sentryPtr(GenerateUserSentry(Cks.envP));
        return cksPI.Get(Xfn, Cks);
    }

    virtual
    int        Set(  const char *Xfn, XrdCksData &Cks, int myTime=0)
    {
        std::unique_ptr<UserSentry> sentryPtr(GenerateUserSentry(Cks.envP));
        return cksPI.Set(Xfn, Cks, myTime);
    }

    virtual
    int        Ver(  const char *Xfn, XrdCksData &Cks)
    {
        std::unique_ptr<UserSentry> sentryPtr(GenerateUserSentry(Cks.envP));
        return cksPI.Ver(Xfn, Cks);
    }

    virtual
    int        Ver(  const char *Xfn, XrdCksData &Cks, XrdCksPCB *pcbP)
    {
        (void)pcbP; 
        return Ver(Xfn, Cks);
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

    if (!check_caps(log)) {
        return nullptr;
    }

    envP->Export("XRDXROOTD_NOPOSC", "1");

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

XrdCks *XrdCksAdd2(XrdCks      &pPI,
                   XrdSysError *eDest,
                   const char  *cFN,
                   const char  *Parm,
                   XrdOucEnv   *envP)
{
    //XrdSysError log(eDest, "multiuser_checksum_");

    if (!check_caps(*eDest)) {
        return nullptr;
    }

    try {
        return new MultiuserChecksum(pPI, eDest);
    } catch (std::runtime_error &re) {
        eDest->Emsg("Initialize", "Encountered a runtime failure:", re.what());
        return nullptr;
    }

}


}

XrdVERSIONINFO(XrdOssGetStorageSystem,osg-multiuser);
XrdVERSIONINFO(XrdOssGetStorageSystem2,osg-multiuser);
XrdVERSIONINFO(XrdOssAddStorageSystem2,osg-multiuser);
XrdVERSIONINFO(XrdCksAdd2,osg-multiuser);
