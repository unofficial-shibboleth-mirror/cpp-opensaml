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
#include "saml2/metadata/MetadataProvider.h"
#include "signature/SignatureProfileValidator.h"

#include <log4cpp/Category.hh>

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

using xmlsignature::SignatureException;

namespace opensaml {
    class SAML_DLLLOCAL XMLSigningRule : public SecurityPolicyRule
    {
    public:
        XMLSigningRule(const DOMElement* e);
        virtual ~XMLSigningRule() {}
        
        void evaluate(const xmltooling::XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const;

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

void XMLSigningRule::evaluate(const XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const
{
    Category& log=Category::getInstance(SAML_LOGCAT".SecurityPolicyRule.XMLSigning");
    log.debug("evaluating message signing policy");
    
    if (!policy.getIssuerMetadata()) {
        log.debug("ignoring message, no issuer metadata supplied");
        return;
    }
    else if (!policy.getTrustEngine()) {
        log.debug("ignoring message, no TrustEngine supplied");
        return;
    }
    
    const SignableObject* signable = dynamic_cast<const SignableObject*>(&message);
    if (!signable || !signable->getSignature()) {
        log.debug("ignoring unsigned or unrecognized message");
        return;
    }
    
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
    
    if (!policy.getTrustEngine()->validate(
            *(signable->getSignature()), *(policy.getIssuerMetadata()), policy.getMetadataProvider()->getKeyResolver()
            )) {
        log.error("unable to verify message signature with supplied trust engine");
        if (m_errorsFatal)
            throw SignatureException("Message was signed, but signature could not be verified.");
        return;
    }

    log.debug("signature verified against message issuer");
    policy.setSecure(true);
}
