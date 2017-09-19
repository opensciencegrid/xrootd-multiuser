
#include "XrdVersion.hh"
#include "XrdSec/XrdSecEntity.hh"
#include "XrdSfs/XrdSfsInterface.hh"

#include <memory>
#include <mutex>
#include <vector>

#include <pwd.h>
#include <sys/fsuid.h>
#include <sys/types.h>
#include <unistd.h>

XrdVERSIONINFO(XrdSfsGetFileSystem, Multiuser);

class UserSentry {
public:
    UserSentry(const XrdSecEntity *client, XrdSysError &log) :
        m_log(log)
    {
        if (!client) {return;}
        if (!client->name || !client->name[0]) {return;}
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

        m_orig_uid = setfsuid(result->pw_uid);
        // TODO: log failures.
        if (m_orig_uid < 0) {
            return;
        }
        m_orig_gid = setfsgid(result->pw_gid);
    }

    ~UserSentry() {
        if (m_orig_uid != -1) {setfsuid(m_orig_uid);}
        if (m_orig_gid != -1) {setfsuid(m_orig_gid);}
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
    MultiuserFile(std::unique_ptr<XrdSfsFile> sfs, XrdSysError &log) :
        m_sfs(std::move(sfs)),
        m_log(log)
    {}

    virtual ~MultiuserFile() {}

    virtual int
    open(const char               *fileName,
               XrdSfsFileOpenMode  openMode,
               mode_t              createMode,
         const XrdSecEntity       *client,
         const char               *opaque = 0) override
    {
        UserSentry sentry(client, m_log);
        return m_sfs->open(fileName, openMode, createMode, client, opaque);
    }

    virtual int
    close() override
    {
        return m_sfs->close();
    }

    virtual int
    fctl(const int            cmd,
        const char           *args,
              XrdOucErrInfo  &out_error) override
    {
        return m_sfs->fctl(cmd, args, out_error);
    }

    virtual const char *
    FName() override {return m_sfs->FName();}

    virtual int
    getMmap(void **Addr, off_t &Size) override
    {return m_sfs->getMmap(Addr, Size);}

    virtual int
    read(XrdSfsFileOffset   fileOffset,
         XrdSfsXferSize     amount) override
    {return m_sfs->read(fileOffset, amount);}

    virtual XrdSfsXferSize
    read(XrdSfsFileOffset   fileOffset,
         char              *buffer,
         XrdSfsXferSize     buffer_size) override
    {return m_sfs->read(fileOffset, buffer, buffer_size);}

    virtual int
    read(XrdSfsAio *aioparm) override
    {return m_sfs->read(aioparm);}

    virtual XrdSfsXferSize
    write(XrdSfsFileOffset   fileOffset,
          const char        *buffer,
          XrdSfsXferSize     buffer_size) override
    {return m_sfs->write(fileOffset, buffer, buffer_size);}

    virtual int
    write(XrdSfsAio *aioparm) override
    {return m_sfs->write(aioparm);}

    virtual int
    sync() override
    {return m_sfs->sync();}

    virtual int
    sync(XrdSfsAio *aiop) override
    {return m_sfs->sync(aiop);}

    virtual int
    stat(struct stat *buf) override
    {return m_sfs->stat(buf);}

    virtual int
    truncate(XrdSfsFileOffset   fileOffset) override
    {return m_sfs->truncate(fileOffset);}

    virtual int
    getCXinfo(char cxtype[4], int &cxrsz) override
    {return m_sfs->getCXinfo(cxtype, cxrsz);}

    virtual int
    SendData(XrdSfsDio         *sfDio,
             XrdSfsFileOffset   offset,
             XrdSfsXferSize     size) override
    {return m_sfs->SendData(sfDio, offset, size);}

private:
    std::unique_ptr<XrdSfsFile> m_sfs;
    XrdSysError &m_log;
};

class MultiuserDirectory : public XrdSfsDirectory {
public:
    MultiuserDirectory(std::unique_ptr<XrdSfsDirectory> sfs, XrdSysError &log) :
        m_sfs(std::move(sfs)),
        m_log(log)
    {}

    virtual ~MultiuserDirectory() {}

    virtual int
    open(const char              *path,
         const XrdSecEntity      *client = 0,
         const char              *opaque = 0) override {
        UserSentry sentry(client, m_log);
        return m_sfs->open(path, client, opaque);
    }

    virtual const char *
    nextEntry() override
    {return m_sfs->nextEntry();}

    virtual int
    close() override
    {return m_sfs->close();}

    virtual const char *
    FName() override
    {return m_sfs->FName();}

    virtual int
    autoStat(struct stat *buf) override
    {return m_sfs->autoStat(buf);}

private:
    std::unique_ptr<XrdSfsDirectory> m_sfs;
    XrdSysError &m_log;
};

class MultiuserFileSystem : public XrdSfsFileSystem {
public:

    MultiuserFileSystem(std::unique_ptr<XrdSfsFileSystem> sfs, XrdSysLogger * lp, const char * /*configfn*/) :
        m_sfs(std::move(sfs)),
        m_log(lp, "multiuser_")
    {
    }

    virtual ~MultiuserFileSystem() {}

    virtual XrdSfsDirectory *
    newDir(char *user=nullptr, int monid=0) override {
        std::unique_ptr<XrdSfsDirectory> chained_dir(m_sfs->newDir(user, monid));
        return new MultiuserDirectory(std::move(chained_dir), m_log);
    }

    virtual XrdSfsFile *
    newFile(char *user=0, int monid=0) override {
        std::unique_ptr<XrdSfsFile> chained_file(m_sfs->newFile(user, monid));
        return new MultiuserFile(std::move(chained_file), m_log);
    }

    virtual int
    chksum(      csFunc         Func,
           const char          *csName,
           const char          *path,
                 XrdOucErrInfo &eInfo,
           const XrdSecEntity  *client = 0,
           const char          *opaque = 0) override {
        UserSentry sentry(client, m_log);
        return m_sfs->chksum(Func, csName, path, eInfo, client, opaque);
    }

    virtual int
    chmod(const char             *Name,
                XrdSfsMode        Mode,
                XrdOucErrInfo    &out_error,
          const XrdSecEntity     *client,
          const char             *opaque = 0) override {
        UserSentry sentry(client, m_log);
        return m_sfs->chmod(Name, Mode, out_error, client, opaque);
    }

    virtual void
    Disc(const XrdSecEntity   *client = 0) override {
        UserSentry sentry(client, m_log);
        return m_sfs->Disc(client);
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
        UserSentry sentry(client, m_log);
        return m_sfs->exists(fileName, exists_flag, out_error, client, opaque);
    }

    virtual int
    fsctl(const int               cmd,
          const char             *args,
                XrdOucErrInfo    &out_error,
          const XrdSecEntity     *client) override {
        UserSentry sentry(client, m_log);
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
        UserSentry sentry(client, m_log);
        return m_sfs->mkdir(dirName, Mode, out_error, client, opaque);
    }

    virtual int
    prepare(      XrdSfsPrep       &pargs,
                  XrdOucErrInfo    &out_error,
            const XrdSecEntity     *client = 0) override {
        UserSentry sentry(client, m_log);
        return m_sfs->prepare(pargs, out_error, client);
    }

    virtual int
    rem(const char             *path,
              XrdOucErrInfo    &out_error,
        const XrdSecEntity     *client,
        const char             *info = 0) override {
        UserSentry sentry(client, m_log);
        return m_sfs->rem(path, out_error, client, info);
    }

    virtual int
    remdir(const char             *dirName,
                 XrdOucErrInfo    &out_error,
           const XrdSecEntity     *client,
           const char             *info = 0) override {
        UserSentry sentry(client, m_log);
        return m_sfs->remdir(dirName, out_error, client, info);
    }

    virtual int
    rename(const char             *oldFileName,
           const char             *newFileName,
                 XrdOucErrInfo    &out_error,
           const XrdSecEntity     *client,
           const char             *infoO = 0,
           const char             *infoN = 0) override {
        UserSentry sentry(client, m_log);
        return m_sfs->rename(oldFileName, newFileName, out_error, client, infoO, infoN);
    }

    virtual int
    stat(const char             *Name,
               struct stat      *buf,
               XrdOucErrInfo    &out_error,
         const XrdSecEntity     *client,
         const char             *opaque = 0) override {
        UserSentry sentry(client, m_log);
        return m_sfs->stat(Name, buf, out_error, client, opaque);
    }

    virtual int
    stat(const char             *Name,
               mode_t           &mode,
               XrdOucErrInfo    &out_error,
         const XrdSecEntity     *client,
         const char             *opaque = 0) override {
        UserSentry sentry(client, m_log);
        return m_sfs->stat(Name, mode, out_error, client, opaque);
    }

    virtual int
    truncate(const char             *Name,
                   XrdSfsFileOffset fileOffset,
                   XrdOucErrInfo    &out_error,
             const XrdSecEntity     *client = 0,
             const char             *opaque = 0) override {
        UserSentry sentry(client, m_log);
        return m_sfs->truncate(Name, fileOffset, out_error, client, opaque);
    }

private:
    std::unique_ptr<XrdSfsFileSystem> m_sfs;
    XrdSysError m_log;
};

extern "C" {

XrdSfsFileSystem *
XrdSfsGetFileSystem(XrdSfsFileSystem *native_fs,
                    XrdSysLogger     *lp,
                    const char       *configfn)
{
    std::unique_ptr<XrdSfsFileSystem> sfs(native_fs);
    return new MultiuserFileSystem(std::move(sfs), lp, configfn);
}

}
