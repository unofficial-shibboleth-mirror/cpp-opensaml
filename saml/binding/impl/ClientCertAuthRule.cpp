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
 * ClientCertAuthRule.cpp
 * 
 * XML Signature checking SecurityPolicyRule
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/ClientCertAuthRule.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"
#include "security/X509TrustEngine.h"

#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReplayCache.h>
#include <log4cpp/Category.hh>

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    SecurityPolicyRule* SAML_DLLLOCAL ClientCertAuthRuleFactory(const DOMElement* const & e)
    {
        return new ClientCertAuthRule(e);
    }
};

pair<saml2::Issuer*,const RoleDescriptor*> ClientCertAuthRule::evaluate(
    const GenericRequest& request,
    const XMLObject& message,
    const MetadataProvider* metadataProvider,
    const QName* role,
    const opensaml::TrustEngine* trustEngine
    ) const
{
    Category& log=Category::getInstance(SAML_LOGCAT".SecurityPolicyRule.ClientCertAuth");
    log.debug("evaluating client certificate authentication policy");
    
    pair<saml2::Issuer*,const RoleDescriptor*> ret = pair<saml2::Issuer*,const RoleDescriptor*>(NULL,NULL);  
    
    const opensaml::X509TrustEngine* x509trust;
    if (!metadataProvider || !role || !(x509trust=dynamic_cast<const opensaml::X509TrustEngine*>(trustEngine))) {
        log.debug("ignoring message, no metadata or X509TrustEngine supplied");
        return ret;
    }
    
    const std::vector<XSECCryptoX509*>& chain = request.getClientCertificates();
    if (chain.empty()) {
        log.debug("ignoring message, no client certificates in request");
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

        log.debug("matched message issuer against metadata, searching for applicable role...");
        const RoleDescriptor* roledesc=entity->getRoleDescriptor(*role, issuerInfo.second);
        if (!roledesc) {
            log.warn("unable to find compatible role (%s) in metadata", role->toString().c_str());
            return ret;
        }

        if (!x509trust->validate(chain.front(), chain, *roledesc, true, metadataProvider->getKeyResolver())) {
            log.error("unable to verify certificate chain with supplied trust engine");
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

pair<saml2::Issuer*,const XMLCh*> ClientCertAuthRule::getIssuerAndProtocol(const XMLObject& message) const
{
    // We just let any bad casts throw here.

    // Shortcuts some of the casting.
    const XMLCh* ns = message.getElementQName().getNamespaceURI();
    if (ns) {
        if (XMLString::equals(ns, samlconstants::SAML20P_NS)) {
            // 2.0 namespace should be castable to a specialized 2.0 root.
            const saml2::RootObject& root = dynamic_cast<const saml2::RootObject&>(message);
            saml2::Issuer* issuer = root.getIssuer();
            if (issuer && issuer->getName())
                return make_pair(issuer->cloneIssuer(), samlconstants::SAML20P_NS);
        }
    }
    return pair<saml2::Issuer*,const XMLCh*>(NULL,NULL);
}
