/*
 *  Copyright 2001-2007 Internet2
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
 * ClientCertAuthRule.cpp
 * 
 * TLS client authentication SecurityPolicyRule
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/SecurityPolicyRule.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataCredentialCriteria.h"
#include "saml2/metadata/MetadataProvider.h"

#include <xmltooling/logging.h>
#include <xmltooling/security/X509TrustEngine.h>
#include <xmltooling/util/ReplayCache.h>

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    class SAML_DLLLOCAL ClientCertAuthRule : public SecurityPolicyRule
    {
    public:
        ClientCertAuthRule(const DOMElement* e) {}
        virtual ~ClientCertAuthRule() {}
        
        const char* getType() const {
            return CLIENTCERTAUTH_POLICY_RULE;
        }
        void evaluate(const XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const;
    };

    SecurityPolicyRule* SAML_DLLLOCAL ClientCertAuthRuleFactory(const DOMElement* const & e)
    {
        return new ClientCertAuthRule(e);
    }
};

void ClientCertAuthRule::evaluate(const XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const
{
    Category& log=Category::getInstance(SAML_LOGCAT".SecurityPolicyRule.ClientCertAuth");
    
    if (!request)
        return;
    
    if (!policy.getIssuerMetadata()) {
        log.debug("ignoring message, no issuer metadata supplied");
        return;
    }

    const X509TrustEngine* x509trust;
    if (!(x509trust=dynamic_cast<const X509TrustEngine*>(policy.getTrustEngine()))) {
        log.debug("ignoring message, no X509TrustEngine supplied");
        return;
    }
    
    const std::vector<XSECCryptoX509*>& chain = request->getClientCertificates();
    if (chain.empty())
        return;
    
    // Set up criteria object, including peer name to enforce cert name checking.
    MetadataCredentialCriteria cc(*(policy.getIssuerMetadata()));
    auto_ptr_char pn(policy.getIssuer()->getName());
    cc.setPeerName(pn.get());
    cc.setUsage(Credential::TLS_CREDENTIAL);

    if (!x509trust->validate(chain.front(), chain, *(policy.getMetadataProvider()), &cc)) {
        log.error("unable to verify certificate chain with supplied trust engine");
        return;
    }
    
    log.debug("client certificate verified against message issuer");
    policy.setAuthenticated(true);
}
