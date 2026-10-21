#ifndef __MULTIUSERFILE_HH__
#define __MULTIUSERFILE_HH__

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
#include "MultiuserFileSystem.hh"
#include "XrdChecksum.hh"
#include "UserSentry.hh"

#include <memory>

class MultiuserFile : public XrdOssDF {
public:
    MultiuserFile(const char *user, std::unique_ptr<XrdOssDF> ossDF, XrdSysError &log, mode_t umask_mode, bool checksum_on_write, unsigned digests, MultiuserFileSystem *oss);

    virtual ~MultiuserFile() {
            if (m_state) {delete m_state;}
        };
    int     Open(const char *path, int Oflag, mode_t Mode, XrdOucEnv &env) override;

    // Operations on the open handle run as the user mapped at Open().  For the
    // XrdSfsAio variants this covers only the submission; I/O completed on
    // other threads still runs with the daemon's IDs.

    int     Fchmod(mode_t mode) override
    {
        UserSentry sentry(m_identity, m_log);
        if (!sentry.IsValid()) {return -EACCES;}
        return m_wrapped->Fchmod(mode);
    }

    void    Flush() override
    {
        UserSentry sentry(m_identity, m_log);
        m_wrapped->Flush();
    }

    int     Fstat(struct stat *buf) override
    {
        UserSentry sentry(m_identity, m_log);
        if (!sentry.IsValid()) {return -EACCES;}
        return m_wrapped->Fstat(buf);
    }

    int     Fsync() override
    {
        UserSentry sentry(m_identity, m_log);
        if (!sentry.IsValid()) {return -EACCES;}
        return m_wrapped->Fsync();
    }

    int     Fsync(XrdSfsAio *aiop) override
    {
        UserSentry sentry(m_identity, m_log);
        if (!sentry.IsValid()) {return -EACCES;}
        return m_wrapped->Fsync(aiop);
    }

    int     Ftruncate(unsigned long long size) override
    {
        UserSentry sentry(m_identity, m_log);
        if (!sentry.IsValid()) {return -EACCES;}
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
        UserSentry sentry(m_identity, m_log);
        if (!sentry.IsValid()) {return -EACCES;}
        return m_wrapped->pgRead(buffer, offset, rdlen, csvec, opts);
    }

    int     pgRead (XrdSfsAio* aioparm, uint64_t opts) override
    {
        UserSentry sentry(m_identity, m_log);
        if (!sentry.IsValid()) {return -EACCES;}
        return m_wrapped->pgRead(aioparm, opts);
    }

    ssize_t pgWrite(void* buffer, off_t offset, size_t wrlen,
                        uint32_t* csvec, uint64_t opts) override
    {
        UserSentry sentry(m_identity, m_log);
        if (!sentry.IsValid()) {return -EACCES;}
        return m_wrapped->pgWrite(buffer, offset, wrlen, csvec, opts);
    }

    int     pgWrite(XrdSfsAio* aioparm, uint64_t opts) override
    {
        UserSentry sentry(m_identity, m_log);
        if (!sentry.IsValid()) {return -EACCES;}
        return m_wrapped->pgWrite(aioparm, opts);
    }

    ssize_t Read(off_t offset, size_t size) override
    {
        UserSentry sentry(m_identity, m_log);
        if (!sentry.IsValid()) {return -EACCES;}
        return m_wrapped->Read(offset, size);
    }

    ssize_t Read(void *buffer, off_t offset, size_t size) override
    {
        UserSentry sentry(m_identity, m_log);
        if (!sentry.IsValid()) {return -EACCES;}
        return m_wrapped->Read(buffer, offset, size);
    }

    int     Read(XrdSfsAio *aiop) override
    {
        UserSentry sentry(m_identity, m_log);
        if (!sentry.IsValid()) {return -EACCES;}
        return m_wrapped->Read(aiop);
    }

    ssize_t ReadRaw(void *buffer, off_t offset, size_t size) override
    {
        UserSentry sentry(m_identity, m_log);
        if (!sentry.IsValid()) {return -EACCES;}
        return m_wrapped->ReadRaw(buffer, offset, size);
    }

    ssize_t ReadV(XrdOucIOVec *readV, int rdvcnt) override
    {
        UserSentry sentry(m_identity, m_log);
        if (!sentry.IsValid()) {return -EACCES;}
        return m_wrapped->ReadV(readV, rdvcnt);
    }

    ssize_t Write(const void *buffer, off_t offset, size_t size) override;

    int     Write(XrdSfsAio *aiop) override
    {
        UserSentry sentry(m_identity, m_log);
        if (!sentry.IsValid()) {return -EACCES;}
        return m_wrapped->Write(aiop);
    }

    ssize_t WriteV(XrdOucIOVec *writeV, int wrvcnt) override
    {
        UserSentry sentry(m_identity, m_log);
        if (!sentry.IsValid()) {return -EACCES;}
        return m_wrapped->WriteV(writeV, wrvcnt);
    }

    int Close(long long *retsz=0);

private:
    std::unique_ptr<XrdOssDF> m_wrapped;
    XrdSysError &m_log;
    const XrdSecEntity* m_client{nullptr};
    // IDs the client was mapped to at Open(); used for all handle operations.
    UserIdentity m_identity;
    mode_t m_umask_mode;
    ChecksumState *m_state;
    ssize_t m_nextoff;
    std::string m_fname;
    MultiuserFileSystem *m_oss;
    bool m_checksum_on_write;
    unsigned m_digests;

};

#endif