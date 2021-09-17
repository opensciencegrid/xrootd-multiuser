
/*
 * A checksum manager integrating with the Xrootd HDFS plugin.
 */
#ifndef __XRDCHECKSUM_HH__
#define __XRDCHECKSUM_HH__

#include <openssl/evp.h>

#include <cstdio>
#include <vector>
#include <string>

#include "XrdOuc/XrdOucEnv.hh"
#include "XrdSec/XrdSecEntity.hh"
#include "XrdCks/XrdCksManager.hh"


class XrdSysError;
class XrdOucEnv;



class ChecksumState
{
public:
    explicit ChecksumState(unsigned digests);

    ~ChecksumState();

    void Update(const unsigned char *buff, size_t blen);

    void Finalize();

    std::string Get(unsigned digest) const;

private:
    ChecksumState(ChecksumState const &);
    ChecksumState & operator=(ChecksumState const &);

    const unsigned m_digests;
    uint32_t m_crc32;
    uint32_t m_cksum;
    uint32_t m_adler32;

    unsigned m_md5_length;
    size_t m_cur_chunk_bytes;
    off_t m_offset;

    EVP_MD_CTX *m_md5;
    EVP_MD_CTX *m_file_sha1;
    EVP_MD_CTX *m_chunk_sha1;

    unsigned char m_md5_value[EVP_MAX_MD_SIZE];
    std::string m_sha1_final; // Hex-encoded.
    std::string m_graft;

    struct CvmfsChunk
    {
        std::string m_sha1;
        off_t m_offset;
    };
    std::vector<CvmfsChunk> m_chunks;

};

class ChecksumManager : public XrdCksManager
{
public:
    ChecksumManager(XrdSysError *erP, int iosz,
                                  XrdVersionInfo &vInfo, bool autoload=false);

    int        Calc( const char *Xfn, XrdCksData &Cks, int doSet=1);


    int        Calc( const char *Xfn, XrdCksData &Cks, XrdCksPCB *pcbP, int doSet=1);


    int        Del(  const char *Xfn, XrdCksData &Cks);


    int        Get(  const char *Xfn, XrdCksData &Cks);

    
//    int        Config(const char *Token, char *Line);

    
    int        Init(const char *ConfigFN, const char *DfltCalc=0);


    char      *List(const char *Xfn, char *Buff, int Blen, char Sep=' ');
  

//    const char      *Name(int seqNum=0);

//    XrdCksCalc *Object(const char *name);

//    int        Size( const char  *Name=0);

    int        Set(  const char *Xfn, XrdCksData &Cks, int myTime=0);


    int        Ver(  const char *Xfn, XrdCksData &Cks);
 

    int        Ver(  const char *Xfn, XrdCksData &Cks, XrdCksPCB *pcbP);



    int Set(const char *pfn, const ChecksumState &state);
    int Set(const char *pfn, const char *cksname, const char *chksvalue);


    virtual ~ChecksumManager() {}

    enum ChecksumTypes {
        MD5     = 0x01,
        CKSUM   = 0x02,
        ADLER32 = 0x04,
        CVMFS   = 0x08,
        CRC32   = 0x10,
        ALL     = 0xff
    };

private:
    typedef std::pair<std::string, std::string> ChecksumValue;
    typedef std::vector<ChecksumValue> ChecksumValues;

    XrdSysError &m_log;

    int SetMultiple(const char *pfn, const ChecksumValues &values);

    std::string m_default_digest;

    XrdCks *m_cksPI;

    std::vector<std::string> m_supported_checksums;
    std::string LFN2PFN(const char* lfn);
};



#endif