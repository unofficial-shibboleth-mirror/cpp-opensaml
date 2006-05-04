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
#include "util/XMLConstants.h"

#include <log4cpp/Category.hh>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>

using namespace opensaml::saml1;
using namespace opensaml;
using namespace xmltooling;
using namespace log4cpp;

#define REGISTER_ELEMENT(namespaceURI,cname) \
    q=QName(namespaceURI,cname::LOCAL_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder()); \
    Validator::registerValidator(q,new cname##SchemaValidator())
    
#define REGISTER_TYPE(namespaceURI,cname) \
    q=QName(namespaceURI,cname::TYPE_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder()); \
    Validator::registerValidator(q,new cname##SchemaValidator())


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

    QName q;
    REGISTER_ELEMENT(XMLConstants::SAML1_NS,AssertionIDReference);
    REGISTER_ELEMENT(XMLConstants::SAML1_NS,Audience);
    REGISTER_ELEMENT(XMLConstants::SAML1_NS,ConfirmationMethod);

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
