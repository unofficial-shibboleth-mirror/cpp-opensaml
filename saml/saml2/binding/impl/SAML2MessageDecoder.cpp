/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * SAML2MessageDecoder.cpp
 *
 * Base class for SAML 2.0 MessageDecoders.
 */

#include "internal.h"
#include "binding/SecurityPolicy.h"
#include "saml2/binding/SAML2MessageDecoder.h"
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

SAML2MessageDecoder::SAML2MessageDecoder()
{
}

SAML2MessageDecoder::~SAML2MessageDecoder()
{
}

const XMLCh* SAML2MessageDecoder::getProtocolFamily() const
{
    return samlconstants::SAML20P_NS;
}

void SAML2MessageDecoder::extractMessageDetails(
    const XMLObject& message, const GenericRequest& request, const XMLCh* protocol, SecurityPolicy& policy
    ) const
{
    // Only handle SAML 2.0 messages.
    const xmltooling::QName& q = message.getElementQName();
    if (!XMLString::equals(q.getNamespaceURI(), samlconstants::SAML20P_NS))
        return;

    Category& log = Category::getInstance(SAML_LOGCAT".MessageDecoder.SAML2");

    try {
        const saml2::RootObject& samlRoot = dynamic_cast<const saml2::RootObject&>(message);
        policy.setMessageID(samlRoot.getID());
        policy.setIssueInstant(samlRoot.getIssueInstantEpoch());

        log.debug("extracting issuer from SAML 2.0 protocol message");
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
            MetadataProvider::Criteria& mc = policy.getMetadataProviderCriteria();
            mc.entityID_unicode = issuer->getName();
            mc.role = policy.getRole();
            mc.protocol = protocol;
            pair<const EntityDescriptor*,const RoleDescriptor*> entity = policy.getMetadataProvider()->getEntityDescriptor(mc);
            if (!entity.first) {
                auto_ptr_char temp(issuer->getName());
                log.warn("no metadata found, can't establish identity of issuer (%s)", temp.get());
                return;
            }
            else if (!entity.second) {
                log.warn("unable to find compatible role (%s) in metadata", policy.getRole()->toString().c_str());
                return;
            }
            policy.setIssuerMetadata(entity.second);
        }
    }
    catch (bad_cast&) {
        // Just trap it.
        log.warn("caught a bad_cast while extracting message details");
    }
}
