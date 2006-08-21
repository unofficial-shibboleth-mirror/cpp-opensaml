/*
 *  Copyright 2001-2005 Internet2
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
 * ExplicitKeyTrustEngine.cpp
 * 
 * TrustEngine based on explicit knowledge of peer key information.
 */

#include "internal.h"
#include "exceptions.h"
#include "security/MetadataKeyInfoIterator.h"
#include "security/X509TrustEngine.h"
#include "signature/SignatureProfileValidator.h"

#include <log4cpp/Category.hh>
#include <xmltooling/security/X509TrustEngine.h>
#include <xmltooling/util/NDC.h>

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    class SAML_DLLLOCAL ExplicitKeyTrustEngine : public X509TrustEngine
    {
    public:
        ExplicitKeyTrustEngine(const DOMElement* e) : X509TrustEngine(e), m_engine(NULL) {
            auto_ptr<xmltooling::TrustEngine> engine(
                xmltooling::XMLToolingConfig::getConfig().TrustEngineManager.newPlugin(EXPLICIT_KEY_TRUSTENGINE, e)
                );
            if (m_engine=dynamic_cast<xmltooling::X509TrustEngine*>(engine.get()))
                engine.release();
            else
                throw xmltooling::UnknownExtensionException("Embedded trust engine does not support required interface.");
        }
        
        virtual ~ExplicitKeyTrustEngine() {
            delete m_engine;
        }

        virtual bool validate(
            Signature& sig,
            RoleDescriptor& role,
            const KeyResolver* keyResolver=NULL
            );
        virtual bool validate(
            XSECCryptoX509* certEE,
            const vector<XSECCryptoX509*>& certChain,
            RoleDescriptor& role,
            bool checkName=true,
            const KeyResolver* keyResolver=NULL
            );

    private:
        xmltooling::X509TrustEngine* m_engine;
    };

    TrustEngine* SAML_DLLLOCAL ExplicitKeyTrustEngineFactory(const DOMElement* const & e)
    {
        return new ExplicitKeyTrustEngine(e);
    }
};

bool ExplicitKeyTrustEngine::validate(
    Signature& sig,
    RoleDescriptor& role,
    const KeyResolver* keyResolver
    )
{
#ifdef _DEBUG
    xmltooling::NDC ndc("validate");
#endif
    Category& log=Category::getInstance(SAML_LOGCAT".TrustEngine");
    
    log.debug("attempting to validate signature profile");
    SignatureProfileValidator sigValidator;
    try {
        sigValidator.validate(&sig);
        log.debug("signature profile validated");
    }
    catch (xmltooling::ValidationException& e) {
        if (log.isDebugEnabled()) {
            log.debug("signature profile failed to validate: %s", e.what());
        }
        return false;
    }

    MetadataKeyInfoIterator keys(role);
    return static_cast<xmltooling::TrustEngine*>(m_engine)->validate(sig,keys,keyResolver);
}

bool ExplicitKeyTrustEngine::validate(
    XSECCryptoX509* certEE,
    const vector<XSECCryptoX509*>& certChain,
    RoleDescriptor& role,
    bool checkName,
    const KeyResolver* keyResolver
    )
{
    MetadataKeyInfoIterator keys(role);
    return m_engine->validate(certEE,certChain,keys,checkName,keyResolver);
}
