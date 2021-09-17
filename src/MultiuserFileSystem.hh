#ifndef __MULTIUSERFILESYSTEM_HH__
#define __MULTIUSERFILESYSTEM_HH__

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

#include <memory>

class MultiuserFileSystem : public XrdOss {
public:

    MultiuserFileSystem(XrdOss *oss, XrdSysLogger *lp, const char *configfn, XrdOucEnv *envP);
    virtual ~MultiuserFileSystem();

    bool
    Config(XrdSysLogger *lp, const char *configfn);

    XrdOssDF *newDir(const char *user=0);
    XrdOssDF *newFile(const char *user=0);
    int Chmod(const char * path, mode_t mode, XrdOucEnv *env=0);
    void      Connect(XrdOucEnv &env);
    int       Create(const char *tid, const char *path, mode_t mode, XrdOucEnv &env,
                         int opts=0);
    void      Disc(XrdOucEnv &env);
    void      EnvInfo(XrdOucEnv *env);
    uint64_t  Features();
    int       FSctl(int cmd, int alen, const char *args, char **resp=0);
    int       Init(XrdSysLogger *lp, const char *cfn);
    int       Init(XrdSysLogger *lp, const char *cfn, XrdOucEnv *env);
    int       Mkdir(const char *path, mode_t mode, int mkpath=0,
                        XrdOucEnv  *env=0);
    int       Reloc(const char *tident, const char *path,
                        const char *cgName, const char *anchor=0);
    int       Remdir(const char *path, int Opts=0, XrdOucEnv *env=0);
    int       Rename(const char *oPath, const char *nPath,
                         XrdOucEnv  *oEnvP=0, XrdOucEnv *nEnvP=0);
    int       Stat(const char *path, struct stat *buff,
                       int opts=0, XrdOucEnv *env=0);
    int       Stats(char *buff, int blen);
    int       StatFS(const char *path, char *buff, int &blen,
                         XrdOucEnv  *env=0);
    int       StatLS(XrdOucEnv &env, const char *path,
                         char *buff, int &blen);
    int       StatPF(const char *path, struct stat *buff, int opts);
    int       StatPF(const char *path, struct stat *buff);
    int       StatVS(XrdOssVSInfo *vsP, const char *sname=0, int updt=0);
    int       StatXA(const char *path, char *buff, int &blen,
                         XrdOucEnv *env=0);
    int       StatXP(const char *path, unsigned long long &attr,
                         XrdOucEnv  *env=0);
    int       Truncate(const char *path, unsigned long long fsize,
                           XrdOucEnv *env=0);
    int       Unlink(const char *path, int Opts=0, XrdOucEnv *env=0);
    int       Lfn2Pfn(const char *Path, char *buff, int blen);
    const char       *Lfn2Pfn(const char *Path, char *buff, int blen, int &rc);

private:
    mode_t m_umask_mode;
    XrdOss *m_oss;  // NOTE: we DO NOT own this pointer; given by the caller.  Do not make std::unique_ptr!
    XrdOucEnv *m_env;
    XrdSysError m_log;
    std::shared_ptr<XrdAccAuthorize> m_authz;
    bool m_checksum_on_write;
    unsigned m_digests;

};

#endif