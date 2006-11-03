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
 * MessageSigningRule.cpp
 * 
 * XML Signature checking SecurityPolicyRule
 */

#include "internal.h"
#include "exceptions.h"
#include "RootObject.h"
#include "binding/MessageSigningRule.h"
#include "saml1/core/Assertions.h"
#include "saml1/core/Protocols.h"
#include "saml2/core/Protocols.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"
#include "security/TrustEngine.h"

#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReplayCache.h>
#include <log4cpp/Category.hh>

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    SecurityPolicyRule* SAML_DLLLOCAL MessageSigningRuleFactory(const DOMElement* const & e)
    {
        return new MessageSigningRule(e);
    }
};

pair<saml2::Issuer*,const saml2md::RoleDescriptor*> MessageSigningRule::evaluate(
    const GenericRequest& request,
    const XMLObject& message,
    const MetadataProvider* metadataProvider,
    const QName* role,
    const opensaml::TrustEngine* trustEngine
    ) const
{
    Category& log=Category::getInstance(SAML_LOGCAT".SecurityPolicyRule.MessageSigning");
    log.debug("evaluating message signing policy");
    
    pair<saml2::Issuer*,const RoleDescriptor*> ret = pair<saml2::Issuer*,const RoleDescriptor*>(NULL,NULL);  
    
    if (!metadataProvider || !role || !trustEngine) {
        log.debug("ignoring message, no metadata or trust information supplied");
        return ret;
    }
    
    try {
        const RootObject& root = dynamic_cast<const RootObject&>(message);
        if (!root.getSignature()) {
            log.debug("ignoring unsigned message");
            return ret;
        }
        
        log.debug("extracting issuer from message");
        pair<saml2::Issuer*,const XMLCh*> issuerInfo = getIssuerAndProtocol(message);
        
        auto_ptr<saml2::Issuer> issuer(issuerInfo.first);
        if (!issuerInfo.first || !issuerInfo.second ||
                (issuer->getFormat() && !XMLString::equals(issuer->getFormat(), saml2::NameIDType::ENTITY))) {
            log.warn("issuer identity not estabished, or was not an entityID");
            return ret;
        }
        
        log.debug("searching metadata for message issuer...");
        const EntityDescriptor* entity = metadataProvider->getEntityDescriptor(issuer->getName());
        if (!entity) {
            auto_ptr_char temp(issuer->getName());
            log.warn("no metadata found, can't establish identity of issuer (%s)", temp.get());
            return ret;
        }

        log.debug("matched assertion issuer against metadata, searching for applicable role...");
        const RoleDescriptor* roledesc=entity->getRoleDescriptor(*role, issuerInfo.second);
        if (!roledesc) {
            log.warn("unable to find compatible role (%s) in metadata", role->toString().c_str());
            return ret;
        }

        if (!trustEngine->validate(*(root.getSignature()), *roledesc, metadataProvider->getKeyResolver())) {
            log.error("unable to verify signature on message with supplied trust engine");
            return ret;
        }

        if (log.isDebugEnabled()) {
            auto_ptr_char iname(entity->getEntityID());
            log.debug("message from (%s), signature verified", iname.get());
        }
        
        ret.first = issuer.release();
        ret.second = roledesc;
    }
    catch (bad_cast&) {
        // Just trap it.
        log.warn("caught a bad_cast while extracting issuer");
    }
    return ret;
}

pair<saml2::Issuer*,const XMLCh*> MessageSigningRule::getIssuerAndProtocol(const XMLObject& message) const
{
    // We just let any bad casts throw here.
    
    saml2::Issuer* issuer;

    // Shortcuts some of the casting.
    const XMLCh* ns = message.getElementQName().getNamespaceURI();
    if (ns) {
        if (XMLString::equals(ns, samlconstants::SAML20P_NS) || XMLString::equals(ns, samlconstants::SAML20_NS)) {
            // 2.0 namespace should be castable to a specialized 2.0 root.
            const saml2::RootObject& root = dynamic_cast<const saml2::RootObject&>(message);
            issuer = root.getIssuer();
            if (issuer && issuer->getName()) {
                return make_pair(issuer->cloneIssuer(), samlconstants::SAML20P_NS);
            }
            
            // No issuer in the message, so we have to try the Response approach. 
            const vector<saml2::Assertion*>& assertions = dynamic_cast<const saml2p::Response&>(message).getAssertions();
            if (!assertions.empty()) {
                issuer = assertions.front()->getIssuer();
                if (issuer && issuer->getName())
                    return make_pair(issuer->cloneIssuer(), samlconstants::SAML20P_NS);
            }
        }
        else if (XMLString::equals(ns, samlconstants::SAML1P_NS)) {
            // Should be a samlp:Response, at least in OpenSAML.
            const vector<saml1::Assertion*>& assertions = dynamic_cast<const saml1p::Response&>(message).getAssertions();
            if (!assertions.empty()) {
                const saml1::Assertion* a = assertions.front();
                if (a->getIssuer()) {
                    issuer = saml2::IssuerBuilder::buildIssuer();
                    issuer->setName(a->getIssuer());
                    pair<bool,int> minor = a->getMinorVersion();
                    return make_pair(
                        issuer,
                        (minor.first && minor.second==0) ? samlconstants::SAML10_PROTOCOL_ENUM : samlconstants::SAML11_PROTOCOL_ENUM
                        );
                }
            }
        }
        else if (XMLString::equals(ns, samlconstants::SAML1_NS)) {
            // Should be a saml:Assertion.
            const saml1::Assertion& a = dynamic_cast<const saml1::Assertion&>(message);
            if (a.getIssuer()) {
                issuer = saml2::IssuerBuilder::buildIssuer();
                issuer->setName(a.getIssuer());
                pair<bool,int> minor = a.getMinorVersion();
                return make_pair(
                    issuer,
                    (minor.first && minor.second==0) ? samlconstants::SAML10_PROTOCOL_ENUM : samlconstants::SAML11_PROTOCOL_ENUM
                    );
            }
        }
    }
    return pair<saml2::Issuer*,const XMLCh*>(NULL,NULL);
}
