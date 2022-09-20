#ifndef __MULTIUSERDIRECTORY_HH__
#define __MULTIUSERDIRECTORY_HH__

#include "XrdOuc/XrdOucEnv.hh"
#include "XrdOss/XrdOss.hh"
#include "UserSentry.hh"


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
        if (!sentry.IsValid()) {return -EACCES;}
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

#endif
