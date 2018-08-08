
#include "XrdAcc/XrdAccAuthorize.hh"
#include "XrdOuc/XrdOucEnv.hh"
#include "XrdOuc/XrdOucPinPath.hh"
#include "XrdOuc/XrdOucStream.hh"
#include "XrdSec/XrdSecEntity.hh"
#include "XrdSfs/XrdSfsInterface.hh"
#include "XrdVersion.hh"

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

XrdVERSIONINFO(XrdSfsGetFileSystem, Multiuser);

// The status-quo to retrieve the default object is to copy/paste the
// linker definition and invoke directly.
static XrdVERSIONINFODEF(compiledVer, XrdAccTest, XrdVNUMBER, XrdVERSION);
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
    UserSentry(const XrdSecEntity *client, XrdSysError &log, XrdAccAuthorize *authz, const char *opaque, const char *path) :
        m_log(log)
    {
        if (!client) {
            log.Emsg("UserSentry", "No security entity object provided");
            return;
        }
        if (authz && (client->sessvar != reinterpret_cast<int *>(1)) && (!client->name || !client->name[0])) {
            const_cast<XrdSecEntity*>(client)->sessvar = reinterpret_cast<int *>(1);
            XrdOucEnv env(opaque, 0, client);
            authz->Access(client, path, AOP_Stat, &env);
        }
        if (!client->name || !client->name[0]) {
            log.Emsg("UserSentry", "Anonymous client; no user set, cannot change FS UIDs");
            return;
        }
        struct passwd pwd, *result = nullptr;

        // TODO: cache the lot of this.
        int buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (buflen < 0) {buflen = 16384;}
        std::vector<char> buf;
        buf.reserve(buflen);

        int retval;
        do {
            retval = getpwnam_r(client->name, &pwd, &buf[0], buflen, &result);
            if ((result == nullptr) && (retval == ERANGE)) {
                buflen *= 2;
                buf.reserve(buflen);
                continue;
            }
            break;
        } while (1);
        if (result == nullptr) {
            m_log.Emsg("UserSentry", "Failed to lookup UID for username", client->name, strerror(retval));
            return;
        }
        if (pwd.pw_uid < g_minimum_uid) {
            m_log.Emsg("UserSentry", "Username", client->name, "maps to a system UID; rejecting lookup");
            return;
        }
        if (pwd.pw_gid < g_minimum_gid) {
            m_log.Emsg("UserSentry", "Username", client->name, "maps to a system GID; rejecting lookup");
            return;
        }

        if (!check_caps(m_log)) {
            m_log.Emsg("UserSentry", "Unable to get correct capabilities for this thread - filesystem action likely to fail.");
        }

        m_log.Emsg("UserSentry", "Switching FS uid for user", client->name);
        m_orig_uid = setfsuid(result->pw_uid);
        if (m_orig_uid < 0) {
            m_log.Emsg("UserSentry", "Failed to switch FS uid for user", client->name);
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

class MultiuserFile : public XrdSfsFile {
public:
    MultiuserFile(char *user, int monid, std::unique_ptr<XrdSfsFile> sfs, XrdSysError &log, std::shared_ptr<XrdAccAuthorize> authz, mode_t umask_mode) :
        XrdSfsFile(user, monid),
        m_umask_mode(umask_mode),
        m_sfs(std::move(sfs)),
        m_log(log),
        m_authz(authz)
    {}

    virtual ~MultiuserFile() {}

    virtual int
    open(const char               *fileName,
               XrdSfsFileOpenMode  openMode,
               mode_t              createMode,
         const XrdSecEntity       *client,
         const char               *opaque = 0) override
    {
        // Heuristic - if the createMode is the default from Xrootd, apply umask.
        if (((createMode & 0777) == (S_IRUSR | S_IWUSR)) && (m_umask_mode != static_cast<mode_t>(-1)))
        {
            createMode |= 0777;
        }
        ErrorSentry err_sentry(error, m_sfs->error, true);
        UserSentry sentry(client, m_log, m_authz.get(), opaque, fileName);
        return m_sfs->open(fileName, openMode, createMode, client, opaque);
    }

    virtual int
    close() override
    {
        ErrorSentry sentry(error, m_sfs->error);
        return m_sfs->close();
    }

    virtual int
    fctl(const int            cmd,
        const char           *args,
              XrdOucErrInfo  &out_error) override
    {
        ErrorSentry sentry(error, m_sfs->error);
        // If out_error is aliased to our internal error object, then do the same
        // for our chained object.  This way, the chained object is in the same state
        // as if we didn't exist.
        return m_sfs->fctl(cmd, args, &out_error == &error ? m_sfs->error : out_error);
    }

    virtual const char *
    FName() override
    {
        ErrorSentry sentry(error, m_sfs->error);
        return m_sfs->FName();
    }

    virtual int
    getMmap(void **Addr, off_t &Size) override
    {
        ErrorSentry sentry(error, m_sfs->error);
        return m_sfs->getMmap(Addr, Size);
    }

    virtual int
    read(XrdSfsFileOffset   fileOffset,
         XrdSfsXferSize     amount) override
    {
        ErrorSentry sentry(error, m_sfs->error);
        return m_sfs->read(fileOffset, amount);
    }

    virtual XrdSfsXferSize
    read(XrdSfsFileOffset   fileOffset,
         char              *buffer,
         XrdSfsXferSize     buffer_size) override
    {
        ErrorSentry sentry(error, m_sfs->error);
        return m_sfs->read(fileOffset, buffer, buffer_size);
    }

    virtual int
    read(XrdSfsAio *aioparm) override
    {
        ErrorSentry sentry(error, m_sfs->error);
        return m_sfs->read(aioparm);
    }

    virtual XrdSfsXferSize
    write(XrdSfsFileOffset   fileOffset,
          const char        *buffer,
          XrdSfsXferSize     buffer_size) override
    {
        ErrorSentry sentry(error, m_sfs->error);
        return m_sfs->write(fileOffset, buffer, buffer_size);
    }

    virtual int
    write(XrdSfsAio *aioparm) override
    {
        ErrorSentry sentry(error, m_sfs->error);
        return m_sfs->write(aioparm);
    }

    virtual int
    sync() override
    {
        ErrorSentry sentry(error, m_sfs->error);
        return m_sfs->sync();
    }

    virtual int
    sync(XrdSfsAio *aiop) override
    {
        ErrorSentry sentry(error, m_sfs->error);
        return m_sfs->sync(aiop);
    }

    virtual int
    stat(struct stat *buf) override
    {
        ErrorSentry sentry(error, m_sfs->error);
        return m_sfs->stat(buf);
    }

    virtual int
    truncate(XrdSfsFileOffset   fileOffset) override
    {
        ErrorSentry sentry(error, m_sfs->error);
        return m_sfs->truncate(fileOffset);
    }

    virtual int
    getCXinfo(char cxtype[4], int &cxrsz) override
    {
        ErrorSentry sentry(error, m_sfs->error);
        return m_sfs->getCXinfo(cxtype, cxrsz);
    }

    virtual int
    SendData(XrdSfsDio         *sfDio,
             XrdSfsFileOffset   offset,
             XrdSfsXferSize     size) override
    {
        ErrorSentry sentry(error, m_sfs->error);
        return m_sfs->SendData(sfDio, offset, size);
    }

private:
    mode_t m_umask_mode;
    std::unique_ptr<XrdSfsFile> m_sfs;
    XrdSysError &m_log;
    std::shared_ptr<XrdAccAuthorize> m_authz;
};

class MultiuserDirectory : public XrdSfsDirectory {
public:
    MultiuserDirectory(char *user, int monid, std::unique_ptr<XrdSfsDirectory> sfs, XrdSysError &log, std::shared_ptr<XrdAccAuthorize> authz) :
        XrdSfsDirectory(user, monid),
        m_sfs(std::move(sfs)),
        m_log(log),
        m_authz(authz)
    {}

    virtual ~MultiuserDirectory() {}

    virtual int
    open(const char              *path,
         const XrdSecEntity      *client = 0,
         const char              *opaque = 0) override {
        ErrorSentry err_sentry(error, m_sfs->error);
        UserSentry sentry(client, m_log, m_authz.get(), opaque, path);
        return m_sfs->open(path, client, opaque);
    }

    virtual const char *
    nextEntry() override
    {
        ErrorSentry sentry(error, m_sfs->error);
        return m_sfs->nextEntry();
    }

    virtual int
    close() override
    {
        ErrorSentry sentry(error, m_sfs->error);
        return m_sfs->close();
    }

    virtual const char *
    FName() override
    {
        ErrorSentry sentry(error, m_sfs->error);
        return m_sfs->FName();
    }

    virtual int
    autoStat(struct stat *buf) override
    {
        ErrorSentry sentry(error, m_sfs->error);
        return m_sfs->autoStat(buf);
    }

private:
    std::unique_ptr<XrdSfsDirectory> m_sfs;
    XrdSysError &m_log;
    std::shared_ptr<XrdAccAuthorize> m_authz;
};

class MultiuserFileSystem : public XrdSfsFileSystem {
public:

    MultiuserFileSystem(XrdSfsFileSystem *sfs, XrdSysLogger *lp, const char *configfn) :
        m_umask_mode(-1),
        m_sfs(sfs),
        m_log(lp, "multiuser_")
    {
        if (!sfs) {
            throw std::runtime_error("The multi-user plugin must be chained with another filesystem.");
        }
        m_log.Say("------ Initializing the multi-user plugin.");
        if (!Config(lp, configfn)) {
            throw std::runtime_error("Failed to configure multi-user plugin.");
        }
    }

    virtual ~MultiuserFileSystem() {
        if (m_handle) {
            dlclose(m_handle);
        }
    }

    bool
    Config(XrdSysLogger *lp, const char *configfn)
    {
        XrdOucEnv myEnv;
        XrdOucStream Config(&m_log, getenv("XRDINSTANCE"), &myEnv, "=====> ");

        bool set_authorize{false};
        std::string authLib;
        std::string authLibParms;
        int cfgFD = open(configfn, O_RDONLY, 0);
        if (cfgFD < 0) {
            m_log.Emsg("Config", errno, "open config file", configfn);
            return false;
        }
        Config.Attach(cfgFD);
        const char *val;
        while ((val = Config.GetMyFirstWord())) {
            if (!strcmp("ofs.authorize", val)) {
                set_authorize = true;
                Config.Echo();
            }
            else if (!strcmp("ofs.authlib", val)) {
                val = Config.GetWord();
                if (!val || !val[0]) {
                    m_log.Emsg("Config", "ofs.authlib does not specify a library");
                    Config.Close();
                    return false;
                }
                authLib = val;
                std::vector<char> rest; rest.reserve(2048);
                if (!Config.GetRest(&rest[0], 2048)) {
                    m_log.Emsg("Config", "authlib parameters line too long");
                    Config.Close();
                    return false;
                }
                if (rest[0] != '\0') {
                    authLibParms = &rest[0];
                }
            } else if (!strcmp("multiuser.umask", val)) {
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
        }
        int retc = Config.LastError();
        if (retc) {
            m_log.Emsg("Config", -retc, "read config file", configfn);
            Config.Close();
            return false;
        }
        Config.Close();

        if (!set_authorize) {return true;}

        XrdAccAuthorize *(*ep)(XrdSysLogger *, const char *, const char *);
        if (authLib.empty()) {
            m_authz.reset(XrdAccDefaultAuthorizeObject(lp, configfn, authLibParms.c_str(), compiledVer));
        } else {
            char resolvePath[2048];
            bool usedAltPath{true};
            if (!XrdOucPinPath(authLib.c_str(), usedAltPath, resolvePath, 2048)) {
                m_log.Emsg("Config", "Failed to locate appropriately versioned authlib path for", authLib.c_str());
                return false;
            }
            m_handle = dlopen(resolvePath, RTLD_LOCAL|RTLD_NOW);
            if (m_handle == nullptr) {
                m_log.Emsg("Config", "Failed to load", resolvePath, dlerror());
                return false;
            }
            ep = (XrdAccAuthorize *(*)(XrdSysLogger *, const char *, const char *))
                             (dlsym(m_handle, "XrdAccAuthorizeObject"));
            if (ep) {
                m_authz.reset(ep(lp, configfn, authLibParms.c_str()));
                if (m_authz.get()) {
                    m_log.Emsg("Config", "Multiuser plugin loaded an authorization object from", resolvePath);
                }
            } else {
                m_log.Emsg("Config", "Failed to resolve symbol XrdAccAuthorizeObject",dlerror());
            }
        }
        if (!m_authz) {
            m_log.Emsg("Config", "Failed to configure and load authorization plugin");
            return false;
        }
        if (m_umask_mode != static_cast<mode_t>(-1)) {
            std::stringstream ss;
            ss.setf(std::ios_base::showbase);
            ss << "Setting umask to " << std::oct << std::setfill('0') << std::setw(4) << m_umask_mode;
            m_log.Emsg("Config", ss.str().c_str());
            umask(m_umask_mode);
        }
        return true;
    }

    virtual XrdSfsDirectory *
    newDir(char *user=nullptr, int monid=0) override {
        std::unique_ptr<XrdSfsDirectory> chained_dir(m_sfs->newDir(user, monid));
        return new MultiuserDirectory(user, monid, std::move(chained_dir), m_log, m_authz);
    }

    virtual XrdSfsFile *
    newFile(char *user=0, int monid=0) override {
        std::unique_ptr<XrdSfsFile> chained_file(m_sfs->newFile(user, monid));
        return new MultiuserFile(user, monid, std::move(chained_file), m_log, m_authz, m_umask_mode);
    }

    virtual int
    chksum(      csFunc         Func,
           const char          *csName,
           const char          *path,
                 XrdOucErrInfo &eInfo,
           const XrdSecEntity  *client = 0,
           const char          *opaque = 0) override {
        UserSentry sentry(client, m_log, m_authz.get(), opaque, path);
        return m_sfs->chksum(Func, csName, path, eInfo , client, opaque);
    }

    virtual int
    chmod(const char             *Name,
                XrdSfsMode        Mode,
                XrdOucErrInfo    &out_error,
          const XrdSecEntity     *client,
          const char             *opaque = 0) override {
        UserSentry sentry(client, m_log, m_authz.get(), opaque, Name);
        return m_sfs->chmod(Name, Mode, out_error, client, opaque);
    }

    virtual void
    Disc(const XrdSecEntity   *client = 0) override {
        // It seems that Xrootd calls this with a different object than elsewhere; to prevent
        // log spam, add an extra check.
        if (client && client->name) {
            UserSentry sentry(client, m_log, m_authz.get(), nullptr, "/");
            return m_sfs->Disc(client);
        } else {
            return m_sfs->Disc(client);
        }
    }

    virtual void
    EnvInfo(XrdOucEnv *envP) override {
        return m_sfs->EnvInfo(envP);
    }

    virtual int
    exists(const char                *fileName,
                 XrdSfsFileExistence &exists_flag,
                 XrdOucErrInfo       &out_error,
           const XrdSecEntity        *client,
           const char                *opaque = 0) override {
        UserSentry sentry(client, m_log, m_authz.get(), opaque, fileName);
        return m_sfs->exists(fileName, exists_flag, out_error, client, opaque);
    }

    virtual int
    fsctl(const int               cmd,
          const char             *args,
                XrdOucErrInfo    &out_error,
          const XrdSecEntity     *client) override {
        UserSentry sentry(client, m_log, m_authz.get(), nullptr, "/");
        return m_sfs->fsctl(cmd, args, out_error);
    }

    virtual int
    getStats(char *buff, int blen) override {
        return m_sfs->getStats(buff, blen);
    }

    virtual const char *
    getVersion() override {
        return m_sfs->getVersion();
    }

    virtual int
    mkdir(const char             *dirName,
                XrdSfsMode        Mode,
                XrdOucErrInfo    &out_error,
          const XrdSecEntity     *client,
          const char             *opaque = 0) override {
        UserSentry sentry(client, m_log, m_authz.get(), opaque, dirName);
        // Heuristic - if the createMode is the default from Xrootd, apply umask.
        if (((Mode & 0777) == S_IRWXU) && (m_umask_mode != static_cast<mode_t>(-1)))
        {
            Mode |= 0777;
        }
        return m_sfs->mkdir(dirName, Mode, out_error, client, opaque);
    }

    virtual int
    prepare(      XrdSfsPrep       &pargs,
                  XrdOucErrInfo    &out_error,
            const XrdSecEntity     *client = 0) override {
        UserSentry sentry(client, m_log, m_authz.get(), nullptr, "/");
        return m_sfs->prepare(pargs, out_error, client);
    }

    virtual int
    rem(const char             *path,
              XrdOucErrInfo    &out_error,
        const XrdSecEntity     *client,
        const char             *info = 0) override {
        UserSentry sentry(client, m_log, m_authz.get(), info, path);
        return m_sfs->rem(path, out_error, client, info);
    }

    virtual int
    remdir(const char             *dirName,
                 XrdOucErrInfo    &out_error,
           const XrdSecEntity     *client,
           const char             *info = 0) override {
        UserSentry sentry(client, m_log, m_authz.get(), info, dirName);
        return m_sfs->remdir(dirName, out_error, client, info);
    }

    virtual int
    rename(const char             *oldFileName,
           const char             *newFileName,
                 XrdOucErrInfo    &out_error,
           const XrdSecEntity     *client,
           const char             *infoO = 0,
           const char             *infoN = 0) override {
        UserSentry sentry(client, m_log, m_authz.get(), infoO, oldFileName);
        return m_sfs->rename(oldFileName, newFileName, out_error, client, infoO, infoN);
    }

    virtual int
    stat(const char             *Name,
               struct stat      *buf,
               XrdOucErrInfo    &out_error,
         const XrdSecEntity     *client,
         const char             *opaque = 0) override {
        UserSentry sentry(client, m_log, m_authz.get(), opaque, Name);
        return m_sfs->stat(Name, buf, out_error, client, opaque);
    }

    virtual int
    stat(const char             *Name,
               mode_t           &mode,
               XrdOucErrInfo    &out_error,
         const XrdSecEntity     *client,
         const char             *opaque = 0) override {
        UserSentry sentry(client, m_log, m_authz.get(), opaque, Name);
        return m_sfs->stat(Name, mode, out_error, client, opaque);
    }

    virtual int
    truncate(const char             *Name,
                   XrdSfsFileOffset fileOffset,
                   XrdOucErrInfo    &out_error,
             const XrdSecEntity     *client = 0,
             const char             *opaque = 0) override {
        UserSentry sentry(client, m_log, m_authz.get(), opaque, Name);
        return m_sfs->truncate(Name, fileOffset, out_error, client, opaque);
    }

private:
    mode_t m_umask_mode;
    XrdSfsFileSystem *m_sfs;  // NOTE: we DO NOT own this pointer; given by the caller.  Do not make unique_ptr!
    XrdSysError m_log;
    std::shared_ptr<XrdAccAuthorize> m_authz;
    void *m_handle{nullptr};
};

extern "C" {

XrdSfsFileSystem *
XrdSfsGetFileSystem(XrdSfsFileSystem *native_fs,
                    XrdSysLogger     *lp,
                    const char       *configfn)
{
    XrdSysError log(lp, "multiuser_");

    if (!check_caps(log)) {
        return nullptr;
    }

    try {
        return new MultiuserFileSystem(native_fs, lp, configfn);
    } catch (std::runtime_error &re) {
        log.Emsg("Initialize", "Encountered a runtime failure:", re.what());
        return nullptr;
    }
}

}
