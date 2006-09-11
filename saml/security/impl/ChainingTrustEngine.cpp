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
 * ChainingTrustEngine.cpp
 * 
 * TrustEngine that uses multiple engines in sequence.
 */

#include "internal.h"
#include "exceptions.h"
#include "security/ChainingTrustEngine.h"

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;
using namespace std;

namespace opensaml {
    TrustEngine* SAML_DLLLOCAL ChainingTrustEngineFactory(const DOMElement* const & e)
    {
        return new ChainingTrustEngine(e);
    }
};

static const XMLCh GenericTrustEngine[] =           UNICODE_LITERAL_11(T,r,u,s,t,E,n,g,i,n,e);
static const XMLCh type[] =                         UNICODE_LITERAL_4(t,y,p,e);

ChainingTrustEngine::ChainingTrustEngine(const DOMElement* e) {
    try {
        e = e ? xmltooling::XMLHelper::getFirstChildElement(e, GenericTrustEngine) : NULL;
        while (e) {
            xmltooling::auto_ptr_char temp(e->getAttributeNS(NULL,type));
            if (temp.get()) {
                auto_ptr<TrustEngine> engine(
                    SAMLConfig::getConfig().TrustEngineManager.newPlugin(temp.get(), e)
                    );
                X509TrustEngine* x509 = dynamic_cast<X509TrustEngine*>(engine.get());
                if (x509) {
                    m_engines.push_back(x509);
                    engine.release();
                }
                else {
                    throw xmltooling::UnknownExtensionException("Embedded trust engine does not support required interface.");
                }
            }
            e = xmltooling::XMLHelper::getNextSiblingElement(e, GenericTrustEngine);
        }
    }
    catch (xmltooling::XMLToolingException&) {
        for_each(m_engines.begin(), m_engines.end(), xmltooling::cleanup<X509TrustEngine>());
        throw;
    }
}

ChainingTrustEngine::~ChainingTrustEngine() {
    for_each(m_engines.begin(), m_engines.end(), xmltooling::cleanup<X509TrustEngine>());
}

bool ChainingTrustEngine::validate(
    Signature& sig,
    const RoleDescriptor& role,
    const KeyResolver* keyResolver
    )
{
    for (vector<X509TrustEngine*>::iterator i=m_engines.begin(); i!=m_engines.end(); ++i) {
        if (static_cast<TrustEngine*>(*i)->validate(sig,role,keyResolver))
            return true;
    }
    return false;
}

bool ChainingTrustEngine::validate(
    XSECCryptoX509* certEE,
    const vector<XSECCryptoX509*>& certChain,
    const RoleDescriptor& role,
    bool checkName,
    const KeyResolver* keyResolver
    )
{
    for (vector<X509TrustEngine*>::iterator i=m_engines.begin(); i!=m_engines.end(); ++i) {
        if ((*i)->validate(certEE,certChain,role,checkName,keyResolver))
            return true;
    }
    return false;
}
