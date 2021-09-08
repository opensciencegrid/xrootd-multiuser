


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




ChecksumManager::ChecksumManager(XrdCks *prevPI, XrdSysError *errP, XrdOucEnv *envP)
    : XrdCksWrapper(*prevPI, errP),
    m_log(*errP),
    m_envP(envP)
{
    m_cksPI = prevPI;
    m_supported_checksums.push_back("CKSUM");
    m_supported_checksums.push_back("ADLER32");
    m_supported_checksums.push_back("CRC32");
    m_supported_checksums.push_back("MD5");
    m_supported_checksums.push_back("CVMFS");
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
        digests = ChecksumManager::ALL;
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
    read_buffer.reserve(buffer_size);

    // Read through the file, checksumming as we go
    while(!is.eof()) {
        is.read(&read_buffer[0], buffer_size);
        int bytes_read = is.gcount();
        state.Update((unsigned char*)(&read_buffer[0]), bytes_read);
    }
    is.close();

    state.Finalize();
    this->Set(pfn.c_str(), state);

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
    checksum_name = "XRDCKS-" + checksum_name;

    int tmp_retval = XrdSysXAttrActive->Del(checksum_name.c_str(), pfn.c_str());
    return tmp_retval;

}

char      *ChecksumManager::List(const char *lfn, char *Buff, int Blen, char Sep)
{
    std::string pfn = this->LFN2PFN(lfn);
    std::stringstream ss;
    // If lfn is 0, then just list supported checksums
    if (lfn == 0) {
        for (const auto &method : m_supported_checksums) // access by reference to avoid copying
        {  
            ss << method << Sep;
        }
    } else {
        // Get all attribute names
        XrdSysXAttr::AList *alist;
        XrdSysXAttrActive->List(&alist, pfn.c_str());

        // Filter by those that start with the XRDCKS
        XrdSysXAttr::AList *iter = alist;
        std::string prefix = "XRDCKS-";

        while (iter) {
            if (prefix.compare(alist->Name) == 0) {
                // Skip the first prefix.size() characters of the name
                ss << alist->Name[prefix.size()] << Sep;
            }
            iter = iter->Next;
        }
        XrdSysXAttrActive->Free(alist);
    }

    // Copy the string to the char* Buff
    std::string result = ss.str();
    size_t mem_to_copy = (static_cast<unsigned>(Blen) < result.size()) ? Blen : result.size();
    memcpy(Buff, result.c_str(), mem_to_copy);
    return Buff;
}

const char      *ChecksumManager::Name(int seqNum) 
{
    switch (seqNum)
    {
    case 0:
        return "md5";
    case 1:
        return "adler32";
    case 2:
        return "cksum";
    case 3:
        return "crc32";
    default:
        return NULL;
    }
}

int        ChecksumManager::Size( const char  *Name)
{
    if (!strcasecmp(Name, "md5")) {return 16;}
    else if (!strcasecmp(Name, "adler32")) {return 5;}
    else if (!strcasecmp(Name, "cksum")) {return 5;}
    else if (!strcasecmp(Name, "crc32")) {return 5;}
    return -1;
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
    checksum_name = "XRDCKS-" + checksum_name;

    std::string pfn = this->LFN2PFN(lfn);

    // Set the checksum
    int tmp_retval = XrdSysXAttrActive->Set(checksum_name.c_str(), 
                                                chksvalue, 
                                                strlen(chksvalue), 
                                                pfn.c_str());
    return tmp_retval;
}

int        ChecksumManager::Ver(  const char *lfn, XrdCksData &Cks)
{
    std::string pfn = this->LFN2PFN(lfn);
    XrdCksData cks_on_disk;
    int rc = Get(pfn.c_str(), cks_on_disk);
    if (rc)
    {
        rc = Calc(pfn.c_str(), cks_on_disk, 1);
        if (rc)
        {
            return rc;
        }
    }

    return !memcmp(cks_on_disk.Value, Cks.Value, Cks.Length) ? 0 : 1;
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
    return 1;
}


int
ChecksumManager::Get(const char *lfn, XrdCksData &cks)
{
    const char *requested_checksum = cks.Name ? cks.Name : m_default_digest.c_str();
    if (!strlen(requested_checksum))
    {
        requested_checksum = "adler32";
    }

    // Convert the lfn to pfn
    std::string pfn = this->LFN2PFN(lfn);

    char buf[512];
    // Prepend the checksum name with the XRDCKS-
    std::string checksum_name = "XRDCKS-" + std::string(cks.Name);
    std::transform(checksum_name.begin(), checksum_name.end(), checksum_name.begin(), ::toupper);
    int retval = XrdSysXAttrActive->Get(checksum_name.c_str(), buf, 511, pfn.c_str());
    if (retval > 0) {
        buf[retval] = '\0';
    }
    //if (retval <= 0) {
        std::stringstream ss2;
        ss2 << "Got checksum (" << requested_checksum << ":" << buf << ") for " << pfn << ": retval = " << retval;
        m_log.Emsg("Get", ss2.str().c_str());
    //}
    int set_retval = cks.Set(buf, strlen(buf));
    ss2.clear();
    ss2 << "Set retval: " << set_retval;
    m_log.Emsg("Get", ss2.str().c_str());

    return cks.Length;
    
}


int
ChecksumManager::Config(const char *token, char *line)
{
    m_log.Emsg("Config", "ChecksumManager config variable passed", token, line);
    return 1;
}

std::string ChecksumManager::LFN2PFN(const char* lfn) {
    std::string pfn;
    char pfnbuff[MAXPATHLEN];
    int rc = 0;
    if (g_multisuer_oss->Lfn2Pfn(lfn, pfnbuff, MAXPATHLEN, rc) == 0)
    {
        std::stringstream ss;
        ss << "Failed to translate lfn to pfn for path: " << lfn << " errno: " << rc;
        m_log.Emsg("Get", ss.str().c_str());
        return pfn;
    }
    pfn = pfnbuff;
    return pfn;
}

