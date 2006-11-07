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
 * SimpleSigningRule.cpp
 * 
 * Blob-oriented signature checking SecurityPolicyRule
 */

#include "internal.h"
#include "exceptions.h"
#include "RootObject.h"
#include "binding/HTTPRequest.h"
#include "binding/SimpleSigningRule.h"
#include "saml2/core/Protocols.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"
#include "security/TrustEngine.h"

#include <log4cpp/Category.hh>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReplayCache.h>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/enc/XSECCryptoProvider.hpp>
#include <xsec/framework/XSECException.hpp>

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    SecurityPolicyRule* SAML_DLLLOCAL SimpleSigningRuleFactory(const DOMElement* const & e)
    {
        return new SimpleSigningRule(e);
    }

    // Appends a raw parameter=value pair to the string.
    static bool appendParameter(string& s, const char* data, const char* name)
    {
        const char* start = strstr(data,name);
        if (!start)
            return false;
        if (!s.empty())
            s += '&';
        const char* end = strchr(start,'&');
        if (end)
            s.append(start, end-start);
        else
            s.append(start);
        return true;
    }
};


pair<saml2::Issuer*,const saml2md::RoleDescriptor*> SimpleSigningRule::evaluate(
    const GenericRequest& request,
    const XMLObject& message,
    const MetadataProvider* metadataProvider,
    const QName* role,
    const opensaml::TrustEngine* trustEngine
    ) const
{
    Category& log=Category::getInstance(SAML_LOGCAT".SecurityPolicyRule.SimpleSigning");
    log.debug("evaluating simple signing policy");
    
    pair<saml2::Issuer*,const RoleDescriptor*> ret = pair<saml2::Issuer*,const RoleDescriptor*>(NULL,NULL);  
    
    if (!metadataProvider || !role || !trustEngine) {
        log.debug("ignoring message, no metadata supplied");
        return ret;
    }
    
    const char* signature = request.getParameter("Signature");
    if (!signature) {
        log.debug("ignoring unsigned message");
        return ret;
    }
    
    const char* sigAlgorithm = request.getParameter("SigAlg");
    if (!sigAlgorithm) {
        log.error("SigAlg parameter not found, no way to verify the signature");
        return ret;
    }

    try {
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

        // We have to construct a string containing the signature input by accessing the
        // request directly. We can't use the decoded parameters because we need the raw
        // data and URL-encoding isn't canonical.
        string input;
        const HTTPRequest& httpRequest = dynamic_cast<const HTTPRequest&>(request);
        const char* raw =
            (!strcmp(httpRequest.getMethod(), "GET")) ? httpRequest.getQueryString() : httpRequest.getRequestBody();
        if (!appendParameter(input, raw, "SAMLRequest="))
            appendParameter(input, raw, "SAMLResponse=");
        appendParameter(input, raw, "RelayState=");
        appendParameter(input, raw, "SigAlg=");

        auto_ptr_XMLCh alg(sigAlgorithm);
        if (!trustEngine->validate(alg.get(), signature, NULL, input.c_str(), input.length(), *roledesc, metadataProvider->getKeyResolver())) {
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

pair<saml2::Issuer*,const XMLCh*> SimpleSigningRule::getIssuerAndProtocol(const XMLObject& message) const
{
    // We just let any bad casts throw here.

    // Shortcuts some of the casting.
    const XMLCh* ns = message.getElementQName().getNamespaceURI();
    if (ns) {
        if (XMLString::equals(ns, samlconstants::SAML20P_NS) || XMLString::equals(ns, samlconstants::SAML20_NS)) {
            // 2.0 namespace should be castable to a specialized 2.0 root.
            const saml2::RootObject& root = dynamic_cast<const saml2::RootObject&>(message);
            saml2::Issuer* issuer = root.getIssuer();
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
    }
    return pair<saml2::Issuer*,const XMLCh*>(NULL,NULL);
}
