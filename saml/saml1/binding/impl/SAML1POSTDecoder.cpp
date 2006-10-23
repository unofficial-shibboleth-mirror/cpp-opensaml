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
 * SAML1POSTDecoder.cpp
 * 
 * SAML 1.x POST binding/profile message decoder
 */

#include "internal.h"
#include "exceptions.h"
#include "saml1/core/Assertions.h"
#include "saml1/binding/SAML1POSTDecoder.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"
#include "security/X509TrustEngine.h"

#include <log4cpp/Category.hh>
#include <xercesc/util/Base64.hpp>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReplayCache.h>
#include <xmltooling/validation/ValidatorSuite.h>

using namespace opensaml::saml2md;
using namespace opensaml::saml1p;
using namespace opensaml::saml1;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    namespace saml1p {              
        MessageDecoder* SAML_DLLLOCAL SAML1POSTDecoderFactory(const DOMElement* const & e)
        {
            return new SAML1POSTDecoder(e);
        }
    };
};

SAML1POSTDecoder::SAML1POSTDecoder(const DOMElement* e) {}

SAML1POSTDecoder::~SAML1POSTDecoder() {}

Response* SAML1POSTDecoder::decode(
    string& relayState,
    const RoleDescriptor*& issuer,
    bool& issuerTrusted,
    const HTTPRequest& httpRequest,
    const MetadataProvider* metadataProvider,
    const QName* role,
    const opensaml::TrustEngine* trustEngine
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("decode");
#endif
    Category& log = Category::getInstance(SAML_LOGCAT".MessageDecoder.SAML1POST");

    log.debug("validating input");
    if (strcmp(httpRequest.getMethod(),"POST"))
        return NULL;
    const char* samlResponse = httpRequest.getParameter("SAMLResponse");
    const char* TARGET = httpRequest.getParameter("TARGET");
    if (!samlResponse || !TARGET)
        return NULL;
    relayState = TARGET;

    // Decode the base64 into SAML.
    unsigned int x;
    XMLByte* decoded=Base64::decode(reinterpret_cast<const XMLByte*>(samlResponse),&x);
    if (!decoded)
        throw BindingException("Unable to decode base64 in POST profile response.");
    log.debug("decoded SAML response:\n%s", decoded);
    istringstream is(reinterpret_cast<char*>(decoded));
    XMLString::release(&decoded);
    
    // Parse and bind the document into an XMLObject.
    DOMDocument* doc = (m_validate ? XMLToolingConfig::getConfig().getValidatingParser()
        : XMLToolingConfig::getConfig().getParser()).parse(is); 
    XercesJanitor<DOMDocument> janitor(doc);
    auto_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
    janitor.release();

    Response* response = dynamic_cast<Response*>(xmlObject.get());
    if (!response)
        throw BindingException("Decoded message was not a SAML 1.x Response.");

    const EntityDescriptor* provider=NULL;
    try {
        if (!m_validate)
            SchemaValidators.validate(xmlObject.get());
        
        // Check recipient URL.
        auto_ptr_char recipient(response->getRecipient());
        const char* recipient2 = httpRequest.getRequestURL();
        if (!recipient.get() || !*(recipient.get())) {
            log.error("response missing Recipient attribute");
            throw BindingException("SAML response did not contain Recipient attribute identifying intended destination.");
        }
        else if (!recipient2 || !*recipient2 || strcmp(recipient.get(),recipient2)) {
            log.error("POST targeted at (%s), but delivered to (%s)", recipient.get(), recipient2 ? recipient2 : "none");
            throw BindingException("SAML message delivered with POST to incorrect server URL.");
        }
        
        // Check freshness.
        time_t now = time(NULL);
        if (response->getIssueInstant()->getEpoch() < now-(2*XMLToolingConfig::getConfig().clock_skew_secs))
            throw BindingException("Detected expired POST profile response.");
        
        // Check replay.
        ReplayCache* replayCache = XMLToolingConfig::getConfig().getReplayCache();
        if (replayCache) {
            auto_ptr_char id(response->getResponseID());
            if (!replayCache->check("SAML1POST", id.get(), response->getIssueInstant()->getEpoch() + (2*XMLToolingConfig::getConfig().clock_skew_secs))) {
                log.error("replay detected of response ID (%s)", id.get());
                throw BindingException("Rejecting replayed response ID ($1).", params(1,id.get()));
            }
        }
        else
            log.warn("replay cache was not provided, this is a serious security risk!");
        
        /* For SAML 1, the issuer can only be established from any assertions in the message.
         * Generally, errors aren't delivered like this, so there should be one.
         * The Issuer attribute is matched against metadata, and then trust checking can be
         * applied.
         */
        issuer = NULL;
        issuerTrusted = false;
        log.debug("attempting to establish issuer and integrity of message...");
        const vector<Assertion*>& assertions=const_cast<const Response*>(response)->getAssertions();
        if (!assertions.empty()) {
            log.debug("searching metadata for assertion issuer...");
            provider=metadataProvider ? metadataProvider->getEntityDescriptor(assertions.front()->getIssuer()) : NULL;
            if (provider) {
                log.debug("matched assertion issuer against metadata, searching for applicable role...");
                pair<bool,int> minor = response->getMinorVersion();
                issuer=provider->getRoleDescriptor(
                    *role,
                    (minor.first && minor.second==0) ? samlconstants::SAML10_PROTOCOL_ENUM : samlconstants::SAML11_PROTOCOL_ENUM
                    );
                if (issuer) {
                    if (trustEngine && response->getSignature()) {
                        issuerTrusted = trustEngine->validate(
                            *(response->getSignature()), *issuer, metadataProvider->getKeyResolver()
                            );
                        if (!issuerTrusted) {
                            log.error("unable to verify signature on message with supplied trust engine");
                            throw BindingException("Message signature failed verification.");
                        }
                    }
                    else {
                        log.warn("unable to verify integrity of the message, leaving untrusted");
                    }
                }
                else {
                    log.warn(
                        "unable to find compatible SAML 1.%d role (%s) in metadata",
                        (minor.first && minor.second==0) ? 0 : 1,
                        role->toString().c_str()
                        );
                }
                if (log.isDebugEnabled()) {
                    auto_ptr_char iname(assertions.front()->getIssuer());
                    log.debug("message from (%s), integrity %sverified", iname.get(), issuerTrusted ? "" : "NOT ");
                }
            }
            else {
                auto_ptr_char temp(assertions.front()->getIssuer());
                log.warn("no metadata found, can't establish identity of issuer (%s)", temp.get());
            }
        }
        else {
            log.warn("no assertions found, can't establish identity of issuer");
        }
    }
    catch (XMLToolingException& ex) {
        // Check for an Issuer.
        if (!provider) {
            const vector<Assertion*>& assertions=const_cast<const Response*>(response)->getAssertions();
            if (!assertions.empty() || !metadataProvider ||
                    !(provider=metadataProvider->getEntityDescriptor(assertions.front()->getIssuer(), false))) {
                // Just record it.
                auto_ptr_char iname(assertions.front()->getIssuer());
                if (iname.get())
                    ex.addProperty("entityID", iname.get());
                throw;
            }
        }
        if (!issuer) {
            pair<bool,int> minor = response->getMinorVersion();
            issuer=provider->getRoleDescriptor(
                *role,
                (minor.first && minor.second==0) ? samlconstants::SAML10_PROTOCOL_ENUM : samlconstants::SAML11_PROTOCOL_ENUM
                );
        }
        if (issuer) annotateException(&ex,issuer); // throws it
        annotateException(&ex,provider);  // throws it
    }

    xmlObject.release();
    return response;
}
