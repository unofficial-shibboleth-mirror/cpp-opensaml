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

#include <xmltooling/security/X509TrustEngine.h>
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

bool ClientCertAuthRule::evaluate(const XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const
{
    Category& log=Category::getInstance(SAML_LOGCAT".SecurityPolicyRule.ClientCertAuth");
    log.debug("evaluating client certificate authentication policy");
    
    if (!request) {
        log.debug("ignoring message, no protocol request available");
        return false;
    }
    else if (!policy.getIssuerMetadata()) {
        log.debug("ignoring message, no issuer metadata supplied");
        return false;
    }

    const X509TrustEngine* x509trust;
    if (!(x509trust=dynamic_cast<const X509TrustEngine*>(policy.getTrustEngine()))) {
        log.debug("ignoring message, no X509TrustEngine supplied");
        return false;
    }
    
    const std::vector<XSECCryptoX509*>& chain = request->getClientCertificates();
    if (chain.empty()) {
        log.debug("ignoring message, no client certificates in request");
        return false;
    }
    
    if (!x509trust->validate(chain.front(), chain, *(policy.getIssuerMetadata()), true,
            policy.getMetadataProvider()->getKeyResolver())) {
        log.error("unable to verify certificate chain with supplied trust engine");
        return false;
    }
    
    log.debug("client certificate verified against message issuer");
    return true;
}
