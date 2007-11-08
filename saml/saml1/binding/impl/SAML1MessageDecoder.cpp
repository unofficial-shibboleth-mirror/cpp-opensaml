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
 * SAML1MessageDecoder.cpp
 * 
 * Base class for SAML 1.x MessageDecoders.
 */

#include "internal.h"
#include "exceptions.h"
#include "saml1/binding/SAML1MessageDecoder.h"
#include "saml1/core/Assertions.h"
#include "saml1/core/Protocols.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"

#include <xmltooling/logging.h>

using namespace opensaml::saml2md;
using namespace opensaml::saml1p;
using namespace opensaml::saml1;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

void SAML1MessageDecoder::extractMessageDetails(
    const XMLObject& message, const GenericRequest& req, const XMLCh* protocol, SecurityPolicy& policy
    ) const
{
    // Only handle SAML 1.x protocol messages.
    const QName& q = message.getElementQName();
    if (!XMLString::equals(q.getNamespaceURI(), samlconstants::SAML1P_NS))
        return;

    Category& log = Category::getInstance(SAML_LOGCAT".MessageDecoder.SAML1");

    const Request* request=NULL;
    const Response* response=NULL;
    if (XMLString::equals(q.getLocalPart(), Request::LOCAL_NAME))
        request = dynamic_cast<const Request*>(&message);
    if (!request && XMLString::equals(q.getLocalPart(), Response::LOCAL_NAME))
        response = dynamic_cast<const Response*>(&message);

    if (!request && !response) {
        log.warn("decoder cannot extract details from non-SAML 1.x protocol message");
        return;
    }

    const RootObject* root = request ? static_cast<const RootObject*>(request) : static_cast<const RootObject*>(response);

    // Extract message details.
    policy.setMessageID(root->getID());
    policy.setIssueInstant(root->getIssueInstantEpoch());

    if (request) {
        log.warn("issuer identity not extracted, only responses with assertions carry issuer information in standard SAML 1.x");
        return;
    }

    log.debug("extracting issuer from SAML 1.x Response");
    const vector<saml1::Assertion*>& assertions = response->getAssertions();
    if (assertions.empty()) {
        log.warn("issuer identity not extracted from response (no assertions were present)");
        return;
    }

    const XMLCh* issuer = assertions.front()->getIssuer();
    policy.setIssuer(issuer);
    if (log.isDebugEnabled()) {
        auto_ptr_char iname(issuer);
        log.debug("response from (%s)", iname.get());
    }

    if (policy.getIssuerMetadata()) {
        log.debug("metadata for issuer already set, leaving in place");
        return;
    }

    if (policy.getMetadataProvider() && policy.getRole()) {
        log.debug("searching metadata for response issuer...");

        MetadataProvider::Criteria mc(issuer, policy.getRole(), protocol);
        pair<const EntityDescriptor*,const RoleDescriptor*> entity = policy.getMetadataProvider()->getEntityDescriptor(mc);

        if (!entity.first) {
            auto_ptr_char iname(issuer);
            log.warn("no metadata found, can't establish identity of issuer (%s)", iname.get());
            return;
        }
        else if (!entity.second) {
            log.warn("unable to find compatible role (%s) in metadata", policy.getRole()->toString().c_str());
            return;
        }
        policy.setIssuerMetadata(entity.second);
    }
}
