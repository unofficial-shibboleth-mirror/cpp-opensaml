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
 * SAML2MessageRule.cpp
 * 
 * SAML 2.0 message extraction rule
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/SecurityPolicyRule.h"
#include "saml2/core/Protocols.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"
#include "util/SAMLConstants.h"

#include <xmltooling/logging.h>

using namespace opensaml::saml2md;
using namespace opensaml::saml2p;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    class SAML_DLLLOCAL SAML2MessageRule : public SecurityPolicyRule
    {
    public:
        SAML2MessageRule(const DOMElement* e) {}
        virtual ~SAML2MessageRule() {}
        
        void evaluate(const xmltooling::XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const;
    };

    SecurityPolicyRule* SAML_DLLLOCAL SAML2MessageRuleFactory(const DOMElement* const & e)
    {
        return new SAML2MessageRule(e);
    }
};

void SAML2MessageRule::evaluate(const XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const
{
    Category& log=Category::getInstance(SAML_LOGCAT".SecurityPolicyRule.SAML2Message");
    
    const QName& q = message.getElementQName(); 
    policy.setMessageQName(&q);
    
    if (!XMLString::equals(q.getNamespaceURI(), samlconstants::SAML20P_NS)&&
        !XMLString::equals(q.getNamespaceURI(), samlconstants::SAML20_NS)) {
        return;
    }

    try {
        const saml2::RootObject& samlRoot = dynamic_cast<const saml2::RootObject&>(message);
        policy.setMessageID(samlRoot.getID());
        policy.setIssueInstant(samlRoot.getIssueInstantEpoch());

        log.debug("extracting issuer from message");
        const Issuer* issuer = samlRoot.getIssuer();
        if (issuer) {
            policy.setIssuer(issuer);
        }
        else if (XMLString::equals(q.getLocalPart(), Response::LOCAL_NAME)) {
            // No issuer in the message, so we have to try the Response approach. 
            const vector<saml2::Assertion*>& assertions = dynamic_cast<const Response&>(samlRoot).getAssertions();
            if (!assertions.empty()) {
                issuer = assertions.front()->getIssuer();
                if (issuer)
                    policy.setIssuer(issuer);
            }
        }

        if (!issuer) {
            log.warn("issuer identity not extracted");
            return;
        }

        if (log.isDebugEnabled()) {
            auto_ptr_char iname(issuer->getName());
            log.debug("message from (%s)", iname.get());
        }

        if (policy.getIssuerMetadata()) {
            log.debug("metadata for issuer already set, leaving in place");
            return;
        }

        if (policy.getMetadataProvider() && policy.getRole()) {
            if (issuer->getFormat() && !XMLString::equals(issuer->getFormat(), NameIDType::ENTITY)) {
                log.warn("non-system entity issuer, skipping metadata lookup");
                return;
            }
            
            log.debug("searching metadata for message issuer...");
            const EntityDescriptor* entity = policy.getMetadataProvider()->getEntityDescriptor(issuer->getName());
            if (!entity) {
                auto_ptr_char temp(issuer->getName());
                log.warn("no metadata found, can't establish identity of issuer (%s)", temp.get());
                return;
            }
    
            log.debug("matched message issuer against metadata, searching for applicable role...");
            const RoleDescriptor* roledesc=entity->getRoleDescriptor(*policy.getRole(), samlconstants::SAML20P_NS);
            if (!roledesc) {
                log.warn("unable to find compatible role (%s) in metadata", policy.getRole()->toString().c_str());
                return;
            }
            policy.setIssuerMetadata(roledesc);
        }
    }
    catch (bad_cast&) {
        // Just trap it.
        log.warn("caught a bad_cast while examining message");
    }
}
