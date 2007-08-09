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
 * XMLSigningRule.cpp
 * 
 * XML Signature checking SecurityPolicyRule
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/SecurityPolicyRule.h"
#include "saml2/core/Assertions.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataCredentialCriteria.h"
#include "saml2/metadata/MetadataProvider.h"
#include "signature/SignatureProfileValidator.h"

#include <xmltooling/logging.h>
#include <xmltooling/security/SignatureTrustEngine.h>

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

using xmlsignature::SignatureException;

namespace opensaml {
    class SAML_DLLLOCAL XMLSigningRule : public SecurityPolicyRule
    {
    public:
        XMLSigningRule(const DOMElement* e);
        virtual ~XMLSigningRule() {}
        
        const char* getType() const {
            return XMLSIGNING_POLICY_RULE;
        }
        void evaluate(const XMLObject& message, const GenericRequest* request, const XMLCh* protocol, SecurityPolicy& policy) const;

    private:
        bool m_errorsFatal;
    };

    SecurityPolicyRule* SAML_DLLLOCAL XMLSigningRuleFactory(const DOMElement* const & e)
    {
        return new XMLSigningRule(e);
    }
    
    static const XMLCh errorsFatal[] = UNICODE_LITERAL_11(e,r,r,o,r,s,F,a,t,a,l);
};

XMLSigningRule::XMLSigningRule(const DOMElement* e) : m_errorsFatal(false)
{
    if (e) {
        const XMLCh* flag = e->getAttributeNS(NULL, errorsFatal);
        m_errorsFatal = (flag && (*flag==chLatin_t || *flag==chDigit_1)); 
    }
}

void XMLSigningRule::evaluate(
    const XMLObject& message, const GenericRequest* request, const XMLCh* protocol, SecurityPolicy& policy
    ) const
{
    Category& log=Category::getInstance(SAML_LOGCAT".SecurityPolicyRule.XMLSigning");
    
    if (!policy.getIssuerMetadata()) {
        log.debug("ignoring message, no issuer metadata supplied");
        return;
    }

    const SignatureTrustEngine* sigtrust;
    if (!(sigtrust=dynamic_cast<const SignatureTrustEngine*>(policy.getTrustEngine()))) {
        log.debug("ignoring message, no SignatureTrustEngine supplied");
        return;
    }
    
    const SignableObject* signable = dynamic_cast<const SignableObject*>(&message);
    if (!signable || !signable->getSignature())
        return;
    
    log.debug("validating signature profile");
    try {
        SignatureProfileValidator sigval;
        sigval.validateSignature(*(signable->getSignature()));
    }
    catch (ValidationException& ve) {
        log.error("signature profile failed to validate: %s", ve.what());
        if (m_errorsFatal)
            throw;
        return;
    }
    
    // Set up criteria object.
    MetadataCredentialCriteria cc(*(policy.getIssuerMetadata()));

    if (!sigtrust->validate(*(signable->getSignature()), *(policy.getMetadataProvider()), &cc)) {
        log.error("unable to verify message signature with supplied trust engine");
        if (m_errorsFatal)
            throw SignatureException("Message was signed, but signature could not be verified.");
        return;
    }

    log.debug("signature verified against message issuer");
    policy.setSecure(true);
}
