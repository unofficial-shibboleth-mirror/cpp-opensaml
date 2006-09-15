
/*
 *  Copyright 2001-2006 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * SAMLConfig.cpp
 * 
 * Library configuration 
 */

#include "internal.h"
#include "exceptions.h"
#include "SAMLConfig.h"
#include "binding/SAMLArtifact.h"
#include "saml1/core/Assertions.h"
#include "saml1/core/Protocols.h"
#include "saml2/core/Protocols.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"
#include "security/TrustEngine.h"
#include "util/SAMLConstants.h"

#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/util/NDC.h>

#include <log4cpp/Category.hh>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/enc/XSECCryptoProvider.hpp>
#include <xsec/utils/XSECPlatformUtils.hpp>
#include <openssl/err.h>

using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

// Expose entry points when used as an extension library

extern "C" int SAML_API xmltooling_extension_init(void*)
{
    if (SAMLConfig::getConfig().init(false))
        return 0;
    return -1;
}

extern "C" void SAML_API xmltooling_extension_term()
{
    SAMLConfig::getConfig().term(false);
}

DECL_EXCEPTION_FACTORY(ArtifactException,opensaml);
DECL_EXCEPTION_FACTORY(MetadataFilterException,opensaml::saml2md);

namespace opensaml {
   SAMLInternalConfig g_config;
}

SAMLConfig& SAMLConfig::getConfig()
{
    return g_config;
}

SAMLInternalConfig& SAMLInternalConfig::getInternalConfig()
{
    return g_config;
}

bool SAMLInternalConfig::init(bool initXMLTooling)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("init");
#endif
    Category& log=Category::getInstance(SAML_LOGCAT".SAMLConfig");
    log.debug("library initialization started");

    if (initXMLTooling) {
        XMLToolingConfig::getConfig().init();
        log.debug("XMLTooling library initialized");
    }

    REGISTER_EXCEPTION_FACTORY(ArtifactException,opensaml);
    REGISTER_EXCEPTION_FACTORY(MetadataFilterException,opensaml::saml2md);

    registerSAMLArtifacts();
    saml1::registerAssertionClasses();
    saml1p::registerProtocolClasses();
    saml2::registerAssertionClasses();
    saml2p::registerProtocolClasses();
    saml2md::registerMetadataClasses();
    saml2md::registerMetadataProviders();
    saml2md::registerMetadataFilters();
    registerTrustEngines();

    log.info("library initialization complete");
    return true;
}

void SAMLInternalConfig::term(bool termXMLTooling)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("term");
#endif
    Category& log=Category::getInstance(SAML_LOGCAT".SAMLConfig");

    saml1::AssertionSchemaValidators.destroyValidators();
    saml1p::ProtocolSchemaValidators.destroyValidators();
    saml2::AssertionSchemaValidators.destroyValidators();
    saml2md::MetadataSchemaValidators.destroyValidators();
    
    SAMLArtifactManager.deregisterFactories();
    MetadataFilterManager.deregisterFactories();
    MetadataProviderManager.deregisterFactories();
    TrustEngineManager.deregisterFactories();

    if (termXMLTooling) {
        XMLToolingConfig::getConfig().term();
        log.debug("XMLTooling library shut down");
    }
    log.info("library shutdown complete");
}

void SAMLInternalConfig::generateRandomBytes(void* buf, unsigned int len)
{
    try {
        if (XSECPlatformUtils::g_cryptoProvider->getRandom(reinterpret_cast<unsigned char*>(buf),len)<len)
            throw XMLSecurityException("Unable to generate random data; was PRNG seeded?");
    }
    catch (XSECCryptoException& e) {
        throw XMLSecurityException("Unable to generate random data: $1",params(1,e.getMsg()));
    }
}

void SAMLInternalConfig::generateRandomBytes(std::string& buf, unsigned int len)
{
    buf.erase();
    auto_ptr<unsigned char> hold(new unsigned char[len]);
    generateRandomBytes(hold.get(),len);
    for (unsigned int i=0; i<len; i++)
        buf+=(hold.get())[i];
}

XMLCh* SAMLInternalConfig::generateIdentifier()
{
    unsigned char key[17];
    generateRandomBytes(key,16);
    
    char hexform[34];
    sprintf(hexform,"_%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            key[0],key[1],key[2],key[3],key[4],key[5],key[6],key[7],
            key[8],key[9],key[10],key[11],key[12],key[13],key[14],key[15]);
    hexform[33]=0;
    return XMLString::transcode(hexform);
}

string SAMLInternalConfig::hashSHA1(const char* s, bool toHex)
{
    static char DIGITS[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    auto_ptr<XSECCryptoHash> hasher(XSECPlatformUtils::g_cryptoProvider->hashSHA1());
    if (hasher.get()) {
        auto_ptr<char> dup(strdup(s));
        unsigned char buf[21];
        hasher->hash(reinterpret_cast<unsigned char*>(dup.get()),strlen(dup.get()));
        if (hasher->finish(buf,20)==20) {
            string ret;
            if (toHex) {
                for (unsigned int i=0; i<20; i++) {
                    ret+=(DIGITS[((unsigned char)(0xF0 & buf[i])) >> 4 ]);
                    ret+=(DIGITS[0x0F & buf[i]]);
                }
            }
            else {
                for (unsigned int i=0; i<20; i++) {
                    ret+=buf[i];
                }
            }
            return ret;
        }
    }
    throw XMLSecurityException("Unable to generate SHA-1 hash.");
}

void opensaml::log_openssl()
{
    const char* file;
    const char* data;
    int flags,line;

    unsigned long code=ERR_get_error_line_data(&file,&line,&data,&flags);
    while (code) {
        Category& log=Category::getInstance("OpenSSL");
        log.errorStream() << "error code: " << code << " in " << file << ", line " << line << CategoryStream::ENDLINE;
        if (data && (flags & ERR_TXT_STRING))
            log.errorStream() << "error data: " << data << CategoryStream::ENDLINE;
        code=ERR_get_error_line_data(&file,&line,&data,&flags);
    }
}
