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

#define SAML_DECLARE_VALIDATORS

#include "internal.h"
#include "exceptions.h"
#include "SAMLConfig.h"
#include "saml1/core/Assertions.h"
#include "saml1/core/Protocols.h"
#include "util/SAMLConstants.h"

#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/util/NDC.h>

#include <log4cpp/Category.hh>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/utils/XSECPlatformUtils.hpp>

using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

//DECL_EXCEPTION_FACTORY(XMLParserException,xmltooling);

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

bool SAMLInternalConfig::init()
{
#ifdef _DEBUG
    xmltooling::NDC ndc("init");
#endif
    Category& log=Category::getInstance(SAML_LOGCAT".SAMLConfig");
    log.debug("library initialization started");

    XMLToolingConfig::getConfig().init();
    log.debug("XMLTooling library initialized");

    saml1::registerAssertionClasses();
    saml1::registerProtocolClasses();

    log.info("library initialization complete");
    return true;
}

void SAMLInternalConfig::term()
{
#ifdef _DEBUG
    xmltooling::NDC ndc("term");
#endif
    XMLToolingConfig::getConfig().term();
    Category::getInstance(SAML_LOGCAT".SAMLConfig").info("library shutdown complete");
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
