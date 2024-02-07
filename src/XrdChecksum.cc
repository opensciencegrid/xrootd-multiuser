


#include <sstream>
#include <algorithm>
#include <fstream>

#include "XrdVersion.hh"

#include "XrdChecksum.hh"
#include "MultiuserFileSystem.hh"

#include "XrdOss/XrdOss.hh"
#include "XrdSfs/XrdSfsInterface.hh"
#include "XrdSec/XrdSecEntity.hh"
#include "XrdSys/XrdSysError.hh"
#include "XrdSys/XrdSysXAttr.hh"
#include "XrdCks/XrdCks.hh"


extern XrdSysXAttr *XrdSysXAttrActive;
extern MultiuserFileSystem* g_multisuer_oss;

#define ATTR_PREFIX "XrdCks.Human."

ChecksumManager::ChecksumManager(XrdSysError *erP, int iosz,
                                  XrdVersionInfo &vInfo, bool autoload):
    XrdCksManager::XrdCksManager(erP, iosz, vInfo, autoload),
    m_log(*erP)
{

}


int
ChecksumManager::Set(const char *lfn, const ChecksumState &state)
{
    int retval = 0;
    if (state.Get(ChecksumManager::CKSUM).size())
        retval = this->Set(lfn, "CKSUM", state.Get(ChecksumManager::CKSUM).c_str());
    
    if (state.Get(ChecksumManager::ADLER32).size())
        retval = this->Set(lfn, "ADLER32", state.Get(ChecksumManager::ADLER32).c_str());
    
    if (state.Get(ChecksumManager::CRC32).size())
        retval = this->Set(lfn, "CRC32", state.Get(ChecksumManager::CRC32).c_str());
    
    if (state.Get(ChecksumManager::MD5).size())
        retval = this->Set(lfn, "MD5", state.Get(ChecksumManager::MD5).c_str());
    
    if (state.Get(ChecksumManager::CVMFS).size())
        retval = this->Set(lfn, "CVMFS", state.Get(ChecksumManager::CVMFS).c_str());

    return retval;
}


int        ChecksumManager::Calc( const char *lfn, XrdCksData &Cks, int doSet)
{
    std::string pfn = this->LFN2PFN(lfn);
    // Figure out what checksum they want
    int digests = 0;
    int return_digest = 0;
    if (doSet)
    {
        // doSet indicates that the new checksum value must replace any existing xattrs.
        // Calculate the enabled checksums (not necessarily all known to the plugin).
        digests = g_multisuer_oss.m_digests;
    }
    if (!strncasecmp(Cks.Name, "md5", Cks.NameSize))
    {
        return_digest = ChecksumManager::MD5;
    }
    else if (!strncasecmp(Cks.Name, "cksum", Cks.NameSize))
    {
        return_digest = ChecksumManager::CKSUM;
    }
    else if (!strncasecmp(Cks.Name, "crc32", Cks.NameSize))
    {
        return_digest = ChecksumManager::CRC32;
    }
    else if (!strncasecmp(Cks.Name, "adler32", Cks.NameSize))
    {
        return_digest = ChecksumManager::ADLER32;
    }
    else
    {
        return -ENOTSUP;
    }
    digests |= return_digest;

    ChecksumState state(digests);
    // Open the file to read
    std::ifstream is (pfn, std::ios::binary | std::ios::in);
    if (is.fail()) {
        std::stringstream ss;
        ss << "Failed to open file: " << pfn << "  error: " << strerror(errno);
        m_log.Emsg("Calc", ss.str().c_str());
        return -errno;
    } 

    const static int buffer_size = 256*1024;
    std::vector<char> read_buffer;
    read_buffer.resize(buffer_size);

    // Read through the file, checksumming as we go
    while(!is.eof()) {
        is.read(&read_buffer[0], buffer_size);
        int bytes_read = is.gcount();
        state.Update((unsigned char*)(&read_buffer[0]), bytes_read);
    }
    is.close();

    state.Finalize();
    this->Set(lfn, state);

    std::string checksum_value;

    switch (return_digest)
    {
    case ChecksumManager::CKSUM:
        checksum_value = state.Get(ChecksumManager::CKSUM);
        break;
    case ChecksumManager::ADLER32:;
        checksum_value = state.Get(ChecksumManager::ADLER32);
        break;
    case ChecksumManager::CRC32:
        checksum_value = state.Get(ChecksumManager::CRC32);
        break;
    case ChecksumManager::MD5:
        checksum_value = state.Get(ChecksumManager::MD5);
        break;
    default:
        return -ENOTSUP;
    };
    if (!checksum_value.size()) return -EIO;
    Cks.Set(checksum_value.c_str(), checksum_value.size());

    return 0;
}

int        ChecksumManager::Calc( const char *Xfn, XrdCksData &Cks, XrdCksPCB *pcbP, int doSet)
            {(void)pcbP; return Calc(Xfn, Cks, doSet);}

int        ChecksumManager::Del(  const char *lfn, XrdCksData &Cks)
{
    std::string pfn = this->LFN2PFN(lfn);
    std::string checksum_name(Cks.Name);
    std::transform(checksum_name.begin(), checksum_name.end(),
                   checksum_name.begin(), ::toupper);

    // Prepend XRDCKS-
    checksum_name = ATTR_PREFIX + checksum_name;

    XrdSysXAttrActive->Del(checksum_name.c_str(), pfn.c_str());
    return XrdCksManager::Del(lfn, Cks);
}

char* ChecksumManager::List(const char *lfn, char *Buff, int Blen, char Sep) 
{
    return XrdCksManager::List(lfn, Buff, Blen, Sep);
}

int        ChecksumManager::Set(  const char *lfn, XrdCksData &Cks, int myTime)
{
    // Extract the checksum value from the XrdCksData
    char buf[512];
    Cks.Get(buf, 512);
    return this->Set(lfn, Cks.Name, buf);

}

int ChecksumManager::Set(const char *lfn, const char *cksname, const char *chksvalue) {
    // Uppercase the name
    std::string checksum_name(cksname);
    std::transform(checksum_name.begin(), checksum_name.end(),
                   checksum_name.begin(), ::toupper);
    

    // Prepend XRDCKS-
    checksum_name = ATTR_PREFIX + checksum_name;

    std::string pfn = this->LFN2PFN(lfn);

    // Set the checksum
    XrdSysXAttrActive->Set(checksum_name.c_str(), 
                                                chksvalue, 
                                                strlen(chksvalue), 
                                                pfn.c_str());

    checksum_name = cksname;
    std::transform(checksum_name.begin(), checksum_name.end(),
                   checksum_name.begin(), ::tolower);
    XrdCksData cks;
    strcpy(cks.Name, checksum_name.c_str());
    cks.Set(chksvalue, strlen(chksvalue));
    return XrdCksManager::Set(pfn.c_str(), cks);
}

int        ChecksumManager::Ver(  const char *lfn, XrdCksData &Cks)
{
    return XrdCksManager::Ver(lfn, Cks);
}

int        ChecksumManager::Ver(  const char *Xfn, XrdCksData &Cks, XrdCksPCB *pcbP)
            {(void)pcbP; return Ver(Xfn, Cks);}




int
ChecksumManager::Init(const char * config_fn, const char *default_checksum)
{
    if (default_checksum)
    {
        m_default_digest = default_checksum;
    }

    return XrdCksManager::Init(config_fn, default_checksum);
}


int
ChecksumManager::Get(const char *lfn, XrdCksData &cks)
{
    std::string pfn = this->LFN2PFN(lfn);
    return XrdCksManager::Get(pfn.c_str(), cks);
}


std::string ChecksumManager::LFN2PFN(const char* lfn) {
    std::string pfn;
    char pfnbuff[MAXPATHLEN];
    int rc = 0;
    const char* pfn_cstr = g_multisuer_oss->Lfn2Pfn(lfn, pfnbuff, MAXPATHLEN, rc);

    if (pfn_cstr == 0)
    {
        std::stringstream ss;
        ss << "Failed to translate lfn to pfn for path: " << lfn << " errno: " << rc;
        m_log.Emsg("Get", ss.str().c_str());
        return pfn;
    }
       
    pfn = pfn_cstr;
    return pfn;
}

