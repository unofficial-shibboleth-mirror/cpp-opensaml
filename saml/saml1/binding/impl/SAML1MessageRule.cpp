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
 * SAML1MessageRule.cpp
 * 
 * SAML 1.x message extraction rule
 */

#include "internal.h"
#include "exceptions.h"
#include "RootObject.h"
#include "binding/SecurityPolicyRule.h"
#include "saml1/core/Assertions.h"
#include "saml1/core/Protocols.h"
#include "saml2/core/Assertions.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"
#include "util/SAMLConstants.h"

#include <log4cpp/Category.hh>

using namespace opensaml::saml2md;
using namespace opensaml::saml1p;
using namespace opensaml;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {

    class SAML_DLLLOCAL SAML1MessageRule : public SecurityPolicyRule
    {
    public:
        SAML1MessageRule(const DOMElement* e) {}
        virtual ~SAML1MessageRule() {}
        
        void evaluate(const xmltooling::XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const;
    };

    SecurityPolicyRule* SAML_DLLLOCAL SAML1MessageRuleFactory(const DOMElement* const & e)
    {
        return new SAML1MessageRule(e);
    }
};

void SAML1MessageRule::evaluate(const XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const
{
    Category& log=Category::getInstance(SAML_LOGCAT".SecurityPolicyRule.SAML1Message");
    
    const QName& q = message.getElementQName(); 
    policy.setMessageQName(&q);

    if (!XMLString::equals(q.getNamespaceURI(), samlconstants::SAML1P_NS) &&
        !XMLString::equals(q.getNamespaceURI(), samlconstants::SAML1_NS)) {
        log.debug("not a SAML 1.x protocol message or assertion");
        return;
    }

    
    try {
        const RootObject& samlRoot = dynamic_cast<const RootObject&>(message);
        policy.setMessageID(samlRoot.getID());
        policy.setIssueInstant(samlRoot.getIssueInstantEpoch());

        log.debug("extracting issuer from message");

        const XMLCh* protocol = NULL;
        const saml1::Assertion* a = NULL;

        // Handle assertions directly.
        if (XMLString::equals(q.getLocalPart(), saml1::Assertion::LOCAL_NAME))
            a = dynamic_cast<const saml1::Assertion*>(&samlRoot);
            
        // Only samlp:Response is known to carry issuer (via payload) in standard SAML 1.x.
        if (!a && XMLString::equals(q.getLocalPart(), Response::LOCAL_NAME)) {
            // Should be a samlp:Response.
            const vector<saml1::Assertion*>& assertions = dynamic_cast<const saml1p::Response&>(samlRoot).getAssertions();
            if (!assertions.empty())
                a = assertions.front();
        }

        if (a && a->getIssuer()) {
            if (!policy.getIssuer() || policy.getIssuer()->getFormat() ||
                    !XMLString::equals(policy.getIssuer()->getName(), a->getIssuer())) {
                // We either have a conflict, or a first-time set of Issuer.
                auto_ptr<saml2::Issuer> issuer(saml2::IssuerBuilder::buildIssuer());
                issuer->setName(a->getIssuer());
                policy.setIssuer(issuer.get());
                issuer.release();   // owned by policy now
            }
            pair<bool,int> minor = a->getMinorVersion();
            protocol = (minor.first && minor.second==0) ?
                samlconstants::SAML10_PROTOCOL_ENUM : samlconstants::SAML11_PROTOCOL_ENUM;
        }
        
        if (!protocol) {
            log.warn("issuer identity not extracted");
            return;
        }

        if (log.isDebugEnabled()) {
            auto_ptr_char iname(policy.getIssuer()->getName());
            log.debug("message from (%s)", iname.get());
        }
        
        if (policy.getIssuerMetadata()) {
            log.debug("metadata for issuer already set, leaving in place");
            return;
        }
        
        if (policy.getMetadataProvider() && policy.getRole()) {
            log.debug("searching metadata for message issuer...");
            const EntityDescriptor* entity = policy.getMetadataProvider()->getEntityDescriptor(policy.getIssuer()->getName());
            if (!entity) {
                auto_ptr_char temp(policy.getIssuer()->getName());
                log.warn("no metadata found, can't establish identity of issuer (%s)", temp.get());
                return;
            }
    
            log.debug("matched message issuer against metadata, searching for applicable role...");
            const RoleDescriptor* roledesc=entity->getRoleDescriptor(*policy.getRole(), protocol);
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
