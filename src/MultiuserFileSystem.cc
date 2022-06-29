


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
#include "MultiuserDirectory.hh"
#include "UserSentry.hh"
#include "MultiuserFile.hh"

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



MultiuserFileSystem::MultiuserFileSystem(XrdOss *oss, XrdSysLogger *lp, const char *configfn, XrdOucEnv *envP) :
    m_umask_mode(-1),
    m_oss(oss),
    m_env(envP),
    m_log(lp, "multiuser_"),
    m_checksum_on_write(false),
    m_digests(0)
{
    if (!oss) {
        throw std::runtime_error("The multi-user plugin must be chained with another filesystem.");
    }
    m_log.Say("------ Initializing the multi-user plugin.");
    if (!Config(lp, configfn)) {
        throw std::runtime_error("Failed to configure multi-user plugin.");
    }
}

MultiuserFileSystem::~MultiuserFileSystem() {
}

bool
MultiuserFileSystem::Config(XrdSysLogger *lp, const char *configfn)
{
    XrdOucEnv myEnv;
    XrdOucStream Config(&m_log, getenv("XRDINSTANCE"), &myEnv, "=====> ");

    int cfgFD = open(configfn, O_RDONLY, 0);
    if (cfgFD < 0) {
        m_log.Emsg("Config", errno, "open config file", configfn);
        return false;
    }
    Config.Attach(cfgFD);
    const char *val;
    while ((val = Config.GetMyFirstWord())) {
        if (!strcmp("multiuser.umask", val)) {
            val = Config.GetWord();
            if (!val || !val[0]) {
                m_log.Emsg("Config", "multiuser.umask must specify a value");
                Config.Close();
                return false;
            }
            char *endptr = NULL;
            errno = 0;
            long int umask_val = strtol(val, &endptr, 0);
            if (errno) {
                m_log.Emsg("Config", "multiuser.umask must specify a valid octal value");
                Config.Close();
                return false;
            }
            if ((umask_val < 0) || (umask_val > 0777)) {
                m_log.Emsg("Config", "multiuser.umask does not specify a valid umask value");
                Config.Close();
                return false;
            }
            m_umask_mode = umask_val;
        }

        // Checksum on write
        if (!strcmp("multiuser.checksumonwrite", val)) {
            val = Config.GetWord();
            if (!val || !val[0]) {
                m_log.Emsg("Config", "multiuser.checksumonwrite must specify a value, on or off");
                Config.Close();
                return false;
            }
            if (!strcmp("on", val)) {
                m_checksum_on_write = true;
            }
            else if (!strcmp("off", val)) {
                m_checksum_on_write = false;
            }
            else {
                std::string errorMsg = "multiuser.checksumonwrite must be either on or off, not: ";
                errorMsg += val;
                m_log.Emsg("Config", errorMsg.c_str());
                Config.Close();
                return false;
            }
        }
        if (!strcmp("xrootd.chksum", val)) {
            m_digests = 0;
            val = Config.GetWord();
            while (val) {
                if (!strcmp("md5", val)) {
                    m_digests |= ChecksumManager::MD5;
                }
                else if (!strcmp("cvmfs", val)) {
                    m_digests |= ChecksumManager::CVMFS;
                }
                else if (!strcmp("crc32", val)) {
                    m_digests |= ChecksumManager::CRC32;
                }
                else if (!strcmp("adler32", val)) {
                    m_digests |= ChecksumManager::ADLER32;
                }
                else if (!strcmp("cksum", val)) {
                    m_digests |= ChecksumManager::CKSUM;
                }
                else {
                    std::string errorMsg = "Unreconginzied chksum value: ";
                    errorMsg += val;
                    m_log.Emsg("Config", errorMsg.c_str());
                }
                val = Config.GetWord();
            }
        }
    }

    int retc = Config.LastError();
    if (retc) {
        m_log.Emsg("Config", -retc, "read config file", configfn);
        Config.Close();
        return false;
    }
    Config.Close();

    if (m_umask_mode != static_cast<mode_t>(-1)) {
        std::stringstream ss;
        ss.setf(std::ios_base::showbase);
        ss << "Setting umask to " << std::oct << std::setfill('0') << std::setw(4) << m_umask_mode;
        m_log.Emsg("Config", ss.str().c_str());
        umask(m_umask_mode);
    }

    return true;

}
// Object Allocation Functions
//
XrdOssDF *MultiuserFileSystem::newDir(const char *user)
{
    // Call the underlying OSS newDir
    std::unique_ptr<XrdOssDF> wrapped(m_oss->newDir(user));
    return (MultiuserDirectory *)new MultiuserDirectory(user, std::move(wrapped), m_log);
}

XrdOssDF *MultiuserFileSystem::newFile(const char *user)
{
    // Call the underlying OSS newFile
    std::unique_ptr<XrdOssDF> wrapped(m_oss->newFile(user));
    return (MultiuserFile *)new MultiuserFile(user, std::move(wrapped), m_log, m_umask_mode, m_checksum_on_write, m_digests, this);
}

int MultiuserFileSystem::Chmod(const char * path, mode_t mode, XrdOucEnv *env)
{
    std::unique_ptr<UserSentry> sentryPtr;
    if (env) {
        auto client = env->secEnv();
        sentryPtr.reset(new UserSentry(client, m_log));
        if (!sentryPtr->IsValid()) return -EPERM;
    }
    return m_oss->Chmod(path, mode, env);
}

void      MultiuserFileSystem::Connect(XrdOucEnv &env)
{
    auto client = env.secEnv();
    UserSentry sentry(client, m_log);
    if (!sentry.IsValid()) return;
    m_oss->Connect(env);
}

int       MultiuserFileSystem::Create(const char *tid, const char *path, mode_t mode, XrdOucEnv &env,
                        int opts)
{
    auto client = env.secEnv();
    UserSentry sentry(client, m_log);
    if (!sentry.IsValid()) return -EACCES;
    return m_oss->Create(tid, path, mode, env, opts);
}

void      MultiuserFileSystem::Disc(XrdOucEnv &env)
{
    auto client = env.secEnv();
    UserSentry sentry(client, m_log);
    if (!sentry.IsValid()) return;
    m_oss->Disc(env);
}

void      MultiuserFileSystem::EnvInfo(XrdOucEnv *env)
{
    // This will be cleaned up automatically
    std::unique_ptr<UserSentry> sentryPtr;
    if (env) {
        auto client = env->secEnv();
        sentryPtr.reset(new UserSentry(client, m_log));
        if (!sentryPtr->IsValid()) return;
    }
    m_oss->EnvInfo(env);
}

uint64_t  MultiuserFileSystem::Features()
{
    return m_oss->Features();
}

int       MultiuserFileSystem::FSctl(int cmd, int alen, const char *args, char **resp)
{
    return m_oss->FSctl(cmd, alen, args, resp);
}

int       MultiuserFileSystem::Init(XrdSysLogger *lp, const char *cfn)
{
    // Should I init something here?
    return 0;
}

int       MultiuserFileSystem::Init(XrdSysLogger *lp, const char *cfn, XrdOucEnv *env)
{
    return Init(lp, cfn);
}

int       MultiuserFileSystem::Mkdir(const char *path, mode_t mode, int mkpath,
                    XrdOucEnv  *env)
{
    std::unique_ptr<UserSentry> sentryPtr;
    if (env) {
        auto client = env->secEnv();
        sentryPtr.reset(new UserSentry(client, m_log));
        if (!sentryPtr->IsValid()) return -EACCES;
    }

    // Heuristic - if the createMode is the default from Xrootd, apply umask.
    if (((mode & 0777) == S_IRWXU) && (m_umask_mode != static_cast<mode_t>(-1)))
    {
        mode |= 0777;
    }
    return m_oss->Mkdir(path, mode, mkpath, env);
}

int       MultiuserFileSystem::Reloc(const char *tident, const char *path,
                    const char *cgName, const char *anchor)
{
    return m_oss->Reloc(tident, path, cgName, anchor);
    
}

int       MultiuserFileSystem::Remdir(const char *path, int Opts, XrdOucEnv *env)
{
    std::unique_ptr<UserSentry> sentryPtr;
    if (env) {
        auto client = env->secEnv();
        sentryPtr.reset(new UserSentry(client, m_log));
        if (!sentryPtr->IsValid()) return -EACCES;
    }
    return m_oss->Remdir(path, Opts, env);
}

int       MultiuserFileSystem::Rename(const char *oPath, const char *nPath,
                        XrdOucEnv  *oEnvP, XrdOucEnv *nEnvP)
{
    // How to handle the renaming?
    std::unique_ptr<UserSentry> sentryPtr;
    if (oEnvP) {
        auto client = oEnvP->secEnv();
        sentryPtr.reset(new UserSentry(client, m_log));
        if (!sentryPtr->IsValid()) return -EACCES;
    }
    return m_oss->Rename(oPath, nPath, oEnvP, nEnvP);
}

int       MultiuserFileSystem::Stat(const char *path, struct stat *buff,
                    int opts, XrdOucEnv *env)
{
    std::unique_ptr<UserSentry> sentryPtr;
    std::unique_ptr<DacOverrideSentry> overridePtr;
    if (env) {
        auto client = env->secEnv();
        sentryPtr.reset(new UserSentry(client, m_log));
        if (!sentryPtr->IsValid()) return -EACCES;
    } else if (UserSentry::IsCmsd()) {
        // The cmsd must be able to override the access control as it needs
        // the ability to advertise the availability of any existing file.
        overridePtr.reset(new DacOverrideSentry(m_log));
        if (!overridePtr->IsValid()) return -EACCES;
    }
    return m_oss->Stat(path, buff, opts, env);
}

int       MultiuserFileSystem::Stats(char *buff, int blen)
{
    return m_oss->Stats(buff, blen);
}

int       MultiuserFileSystem::StatFS(const char *path, char *buff, int &blen,
                        XrdOucEnv  *env)
{
    std::unique_ptr<UserSentry> sentryPtr;
    if (env) {
        auto client = env->secEnv();
        sentryPtr.reset(new UserSentry(client, m_log));
        if (!sentryPtr->IsValid()) return -EACCES;
    }
    return m_oss->StatFS(path, buff, blen, env);
}

int       MultiuserFileSystem::StatLS(XrdOucEnv &env, const char *path,
                        char *buff, int &blen)
{
    auto client = env.secEnv();
    UserSentry sentry(client, m_log);
    if (!sentry.IsValid()) return -EACCES;
    return m_oss->StatLS(env, path, buff, blen);
}

int       MultiuserFileSystem::StatPF(const char *path, struct stat *buff, int opts)
{
    return m_oss->StatPF(path, buff, opts);
}

int       MultiuserFileSystem::StatPF(const char *path, struct stat *buff)
{
    return m_oss->StatPF(path, buff, 0);
}

int       MultiuserFileSystem::StatVS(XrdOssVSInfo *vsP, const char *sname, int updt)
{
    return m_oss->StatVS(vsP, sname, updt);
}

int       MultiuserFileSystem::StatXA(const char *path, char *buff, int &blen,
                        XrdOucEnv *env)
{
    std::unique_ptr<UserSentry> sentryPtr;
    if (env) {
        auto client = env->secEnv();
        sentryPtr.reset(new UserSentry(client, m_log));
        if (!sentryPtr->IsValid()) return -EACCES;
    }
    return m_oss->StatXA(path, buff, blen, env);
}

int       MultiuserFileSystem::StatXP(const char *path, unsigned long long &attr,
                        XrdOucEnv  *env)
{
    std::unique_ptr<UserSentry> sentryPtr;
    if (env) {
        auto client = env->secEnv();
        sentryPtr.reset(new UserSentry(client, m_log));
        if (!sentryPtr->IsValid()) return -EACCES;
    }
    return m_oss->StatXP(path, attr, env);
}

int       MultiuserFileSystem::Truncate(const char *path, unsigned long long fsize,
                        XrdOucEnv *env)
{
    std::unique_ptr<UserSentry> sentryPtr;
    if (env) {
        auto client = env->secEnv();
        sentryPtr.reset(new UserSentry(client, m_log));
        if (!sentryPtr->IsValid()) return -EACCES;
    }
    return m_oss->Truncate(path, fsize, env);
}

int       MultiuserFileSystem::Unlink(const char *path, int Opts, XrdOucEnv *env)
{
    std::unique_ptr<UserSentry> sentryPtr;
    if (env) {
        auto client = env->secEnv();
        sentryPtr.reset(new UserSentry(client, m_log));
        if (!sentryPtr->IsValid()) return -EACCES;
    }
    return m_oss->Unlink(path, Opts, env);
}

int       MultiuserFileSystem::Lfn2Pfn(const char *Path, char *buff, int blen)
{
    return m_oss->Lfn2Pfn(Path, buff, blen);
}

const char       *MultiuserFileSystem::Lfn2Pfn(const char *Path, char *buff, int blen, int &rc)
{
    return m_oss->Lfn2Pfn(Path, buff, blen, rc);
}
