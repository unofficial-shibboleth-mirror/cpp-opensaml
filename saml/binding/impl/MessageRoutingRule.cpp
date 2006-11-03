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
 * MessageRoutingRule.cpp
 * 
 * XML Signature checking SecurityPolicyRule
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/HTTPRequest.h"
#include "binding/MessageRoutingRule.h"
#include "saml1/core/Protocols.h"
#include "saml2/core/Protocols.h"

#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReplayCache.h>
#include <log4cpp/Category.hh>

using namespace opensaml;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    SecurityPolicyRule* SAML_DLLLOCAL MessageRoutingRuleFactory(const DOMElement* const & e)
    {
        return new MessageRoutingRule(e);
    }
};

static const XMLCh mandatory[] = UNICODE_LITERAL_9(m,a,n,d,a,t,o,r,y);

MessageRoutingRule::MessageRoutingRule(const DOMElement* e) : m_mandatory(true)
{
    if (e) {
        const XMLCh* attr = e->getAttributeNS(NULL, mandatory);
        if (attr && (*attr==chLatin_f || *attr==chDigit_0))
            m_mandatory = false;
    }
}

pair<saml2::Issuer*,const saml2md::RoleDescriptor*> MessageRoutingRule::evaluate(
    const GenericRequest& request,
    const XMLObject& message,
    const saml2md::MetadataProvider* metadataProvider,
    const QName* role,
    const opensaml::TrustEngine* trustEngine
    ) const
{
    Category& log=Category::getInstance(SAML_LOGCAT".SecurityPolicyRule.MessageRouting");
    log.debug("evaluating message routing policy");
    
    try {
        const char* to = dynamic_cast<const HTTPRequest&>(request).getRequestURL();
        if (!to || !*to) {
            if (m_mandatory)
                throw BindingException("Unable to determine delivery location.");
            log.debug("unable to determine delivery location, ignoring message");
            return pair<saml2::Issuer*,const saml2md::RoleDescriptor*>(NULL,NULL);
        }
        auto_ptr_char dest(getDestination(message));
        if (dest.get() && *dest.get()) {
            if (!XMLString::equals(to, dest.get())) {
                log.error("Message intended for (%s), but delivered to (%s)", dest.get(), to);
                throw BindingException("Message delivered to incorrect address.");
            }
        }
        else if (m_mandatory)
            throw BindingException("Message did not contain intended address.");
    }
    catch (bad_cast&) {
        throw BindingException("Message was not of a recognized type.");
    }
    return pair<saml2::Issuer*,const saml2md::RoleDescriptor*>(NULL,NULL);
}

const XMLCh* MessageRoutingRule::getDestination(const XMLObject& message) const
{
    // We just let any bad casts throw here.

    // Shortcuts some of the casting.
    const XMLCh* ns = message.getElementQName().getNamespaceURI();
    if (ns) {
        if (XMLString::equals(ns, samlconstants::SAML20P_NS)) {
            const saml2p::StatusResponseType* response = dynamic_cast<const saml2p::StatusResponseType*>(&message);
            if (response)
                return response->getDestination();
            return dynamic_cast<const saml2p::RequestAbstractType&>(message).getDestination();
        }
        else if (XMLString::equals(ns, samlconstants::SAML1P_NS)) {
            // Should be a samlp:Response, at least in OpenSAML.
            return dynamic_cast<const saml1p::Response&>(message).getRecipient();
        }
    }
    return NULL;
}
