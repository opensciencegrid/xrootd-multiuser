


#include <sstream>
#include <algorithm>

#include "XrdVersion.hh"

#include "XrdChecksum.hh"

#include "XrdOss/XrdOss.hh"
#include "XrdSfs/XrdSfsInterface.hh"
#include "XrdSec/XrdSecEntity.hh"
#include "XrdSys/XrdSysError.hh"
#include "XrdSys/XrdSysXAttr.hh"
#include "XrdCks/XrdCks.hh"


XrdVERSIONINFO(XrdCksInit, XrdPosixChecksum)

extern XrdSysXAttr *XrdSysXAttrActive;





ChecksumManager::ChecksumManager(XrdCks *prevPI, XrdSysError *errP)
    : XrdCksWrapper(*prevPI, errP),
    m_log(*errP)
{
    m_cksPI = prevPI;
}

/*
 * Note - it is not apparent this is ever used, hence it is
 * just a stub in this implementation.
 */

XrdCksCalc *
ChecksumManager::Object(const char * name)
{
    return NULL;
}


int
ChecksumManager::Set(const char *pfn, const ChecksumState &state)
{
    ChecksumValues values;
    ChecksumValue value;
    value.first = "CKSUM";
    value.second = state.Get(ChecksumManager::CKSUM);
    if (value.second.size()) {values.push_back(value);}

    value.first = "ADLER32";
    value.second = state.Get(ChecksumManager::ADLER32);
    if (value.second.size()) {values.push_back(value);}

    value.first = "CRC32";
    value.second = state.Get(ChecksumManager::CRC32);
    if (value.second.size()) {values.push_back(value);}

    value.first = "MD5";
    value.second = state.Get(ChecksumManager::MD5);
    if (value.second.size()) {values.push_back(value);}

    value.first = "CVMFS";
    value.second = state.Get(ChecksumManager::CVMFS);
    if (value.second.size()) {values.push_back(value);}

    return SetMultiple(pfn, values); // Ignore return value - this is simply advisory.
}


int 
ChecksumManager::SetMultiple(const char *pfn, const ChecksumValues &values)
{
    int retval = 0;
    for (ChecksumValues::const_iterator iter = values.begin();
         iter != values.end();
         iter++)
    {
        std::string cur_checksum_name = iter->first;
        std::transform(cur_checksum_name.begin(), cur_checksum_name.end(),
                       cur_checksum_name.begin(), ::tolower);

        std::stringstream ss2;
        ss2 << "Got checksum (" << cur_checksum_name << ":" << iter->second << ") for " << pfn;
        m_log.Emsg("SetMultiple", ss2.str().c_str());
        XrdCksData cksData;
        cksData.Set(cur_checksum_name.c_str());
        cksData.Set(iter->second.c_str(), iter->second.length());
        int tmp_retval = this->Set(pfn, cksData);
        if (tmp_retval != 0) {
            retval = tmp_retval;
        }
        
    }

    std::stringstream ss;
    ss << "Return value: " << retval << " For file: " << pfn;
    m_log.Emsg("SetMultiple", ss.str().c_str());

    return retval;

}


int        ChecksumManager::Calc( const char *Xfn, XrdCksData &Cks, int doSet)
{return m_cksPI->Calc(Xfn, Cks, doSet);}

int        ChecksumManager::Calc( const char *Xfn, XrdCksData &Cks, XrdCksPCB *pcbP, int doSet)
            {(void)pcbP; return Calc(Xfn, Cks, doSet);}

int        ChecksumManager::Del(  const char *Xfn, XrdCksData &Cks)
            {return m_cksPI->Del(Xfn, Cks);}

char      *ChecksumManager::List(const char *Xfn, char *Buff, int Blen, char Sep)
            {return m_cksPI->List(Xfn, Buff, Blen, Sep);}

const char      *ChecksumManager::Name(int seqNum) {return m_cksPI->Name(seqNum);}

int        ChecksumManager::Size( const char  *Name) {return m_cksPI->Size(Name);}

int        ChecksumManager::Set(  const char *pfn, XrdCksData &Cks, int myTime)
{
    // Uppercase the name
    std::string checksum_name(Cks.Name);
    std::transform(checksum_name.begin(), checksum_name.end(),
                   checksum_name.begin(), ::toupper);

    // Prepend XRDCKS-
    checksum_name = "XRDCKS-" + checksum_name;

    char buf[512];
    int cks_length = Cks.Get(buf, 512);

    // Set the checksum
    int tmp_retval = XrdSysXAttrActive->Set(checksum_name.c_str(), 
                                                buf, 
                                                cks_length, 
                                                pfn);
    return tmp_retval;
}

int        ChecksumManager::Ver(  const char *Xfn, XrdCksData &Cks)
            {return m_cksPI->Ver(Xfn, Cks);}

int        ChecksumManager::Ver(  const char *Xfn, XrdCksData &Cks, XrdCksPCB *pcbP)
            {(void)pcbP; return Ver(Xfn, Cks);}




int
ChecksumManager::Init(const char * config_fn, const char *default_checksum)
{
    if (default_checksum)
    {
        m_default_digest = default_checksum;
    }
    return 1;
}


int
ChecksumManager::Get(const char *pfn, XrdCksData &cks)
{
    const char *requested_checksum = cks.Name ? cks.Name : m_default_digest.c_str();
    if (!strlen(requested_checksum))
    {
        requested_checksum = "adler32";
    }

    char buf[512];
    // Prepend the checksum name with the XRDCKS-
    std::string checksum_name = "XRDCKS-" + std::string(cks.Name);
    std::transform(checksum_name.begin(), checksum_name.end(), checksum_name.begin(), ::toupper);
    int retval = XrdSysXAttrActive->Get(checksum_name.c_str(), buf, 511, pfn);
    std::stringstream ss2;
    ss2 << "Got checksum (" << requested_checksum << ":" << buf << ") for " << pfn;
    m_log.Emsg("Get", ss2.str().c_str());
    cks.Set(buf, strlen(buf));
    return retval;
}


int
ChecksumManager::Config(const char *token, char *line)
{
    m_log.Emsg("Config", "ChecksumManager config variable passed", token, line);
    return 1;
}

