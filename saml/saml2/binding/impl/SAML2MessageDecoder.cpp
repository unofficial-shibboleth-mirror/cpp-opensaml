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
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/io/HTTPRequest.h>
#include <xmltooling/io/HTTPResponse.h>
#include <xmltooling/util/URLEncoder.h>

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

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

void SAML2MessageDecoder::extractCorrelationID(
    const HTTPRequest& request, HTTPResponse* response, const string& relayState, SecurityPolicy& policy
    ) const
{
    Category& log = Category::getInstance(SAML_LOGCAT ".MessageDecoder.SAML2");

    if (!relayState.empty()) {

        if (response) {
            // CLean existing cookies.
            int maxCookies = 20, purgedCookies = 0;

            // Walk the list of cookies backwards by name.
            const map<string,string>& cookies = request.getCookies();
            for (map<string,string>::const_reverse_iterator i = cookies.rbegin(); i != cookies.rend(); ++i) {
                if (boost::starts_with(i->first, "_opensaml_req_")) {
                    if (maxCookies > 0) {
                        // Keep it, but count it against the limit.
                        --maxCookies;
                    }
                    else {
                        // We're over the limit, so everything here and older gets cleaned up.
                        response->setCookie(i->first.c_str(), nullptr, 0, HTTPResponse::SAMESITE_NONE);
                        ++purgedCookies;
                    }
                }
            }

            if (purgedCookies > 0)
                log.debug(string("purged ") + boost::lexical_cast<string>(purgedCookies) + " stale request correlation cookie(s) from client");
        }

        string cookie_name = string("_opensaml_req_").append(
            XMLToolingConfig::getConfig().getURLEncoder()->encode(relayState.c_str()));
        const char* cookie = request.getCookie(cookie_name.c_str());
        if (cookie && *cookie) {
            log.debug("recovered request/response correlation value (%s)", cookie);
            char* dup = strdup(cookie);
            XMLToolingConfig::getConfig().getURLEncoder()->decode(dup);
            auto_ptr_XMLCh corrID(dup);
            free(dup);
            policy.setCorrelationID(corrID.get());
            if (response) {
                response->setCookie(cookie_name.c_str(), nullptr, 0, HTTPResponse::SAMESITE_NONE);
            }
        }
        else {
            log.debug("no request/response correlation cookie found");
        }
    }
    else {
        log.debug("no RelayState, unable to search for request/response correlation cookie");
    }
}

void SAML2MessageDecoder::extractMessageDetails(
    const XMLObject& message, const GenericRequest& request, const XMLCh* protocol, SecurityPolicy& policy
    ) const
{
    // Only handle SAML 2.0 messages.
    const xmltooling::QName& q = message.getElementQName();
    if (!XMLString::equals(q.getNamespaceURI(), samlconstants::SAML20P_NS))
        return;

    Category& log = Category::getInstance(SAML_LOGCAT ".MessageDecoder.SAML2");

    try {
        const saml2::RootObject& samlRoot = dynamic_cast<const saml2::RootObject&>(message);
        policy.setMessageID(samlRoot.getID());
        policy.setIssueInstant(samlRoot.getIssueInstantEpoch());

        const saml2p::StatusResponseType* statusResponse = dynamic_cast<const saml2p::StatusResponseType*>(&message);
        if (statusResponse) {
            policy.setInResponseTo(statusResponse->getInResponseTo());
        }

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
