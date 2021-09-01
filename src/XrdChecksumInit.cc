
#include "XrdVersion.hh"

#include "XrdChecksum.hh"

#include "XrdOss/XrdOss.hh"
#include "XrdSfs/XrdSfsInterface.hh"
#include "XrdSec/XrdSecEntity.hh"
#include "XrdSys/XrdSysError.hh"
#include "XrdSys/XrdSysXAttr.hh"
#include "XrdCks/XrdCks.hh"

extern "C" {

XrdCks *XrdCksInit(XrdSysError *eDest,
                   const char *config_fn,
                   const char *params)
{
    XrdCks *cks = new ChecksumManager(NULL, eDest);
    eDest->Emsg("ChecksumManager", "Initializing checksum manager with config file", config_fn);
    cks->Init(config_fn);
    return cks;
}

XrdCks *XrdCksAdd2( XrdCks      &pPI,
                    XrdSysError *eDest,
                    const char  *cFN,
                    const char  *Parm,
                    XrdOucEnv   *envP
                    )
{
    XrdCks *cks = new ChecksumManager(&pPI, eDest);
    eDest->Emsg("ChecksumManager", "Initializing checksum manager with config file", cFN);
    cks->Init(cFN);
    return cks;
}

}