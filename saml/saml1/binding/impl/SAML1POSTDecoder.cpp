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
 * SAML 1.x POST binding/profile message encoder
 */

#include "internal.h"
#include "exceptions.h"
#include "saml/binding/ReplayCache.h"
#include "saml1/binding/SAML1POSTDecoder.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"
#include "security/X509TrustEngine.h"

#include <log4cpp/Category.hh>
#include <xercesc/util/Base64.hpp>
#include <xmltooling/util/NDC.h>

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
    const X509TrustEngine* trustEngine
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

    try {
        if (!m_validate)
            SchemaValidators.validate(xmlObject.get());
        
        // Check recipient URL.
        auto_ptr_char recipient(response->getRecipient());
        const char* recipient2 = httpRequest.getRequestURL();
        if (!recipient2 || !*recipient2 || strcmp(recipient.get(),recipient2)) {
            log.error("POST targeted at (%s), but delivered to (%s)", recipient.get(), recipient2 ? recipient2 : "none");
            throw BindingException("SAML message delivered with POST to incorrect server URL.");
        }
        
        time_t now = time(NULL);
        if (response->getIssueInstant()->getEpoch() < now-(2*XMLToolingConfig::getConfig().clock_skew_secs))
            throw BindingException("Detected expired POST profile response.");
            
        ReplayCache* replayCache = SAMLConfig::getConfig().getReplayCache();
        if (replayCache) {
            auto_ptr_char id(response->getResponseID());
            if (!replayCache->check("SAML1POST", id.get(), response->getIssueInstant()->getEpoch() + (2*XMLToolingConfig::getConfig().clock_skew_secs)))
                throw BindingException("Rejecting replayed response ID ($1).", params(1,id.get()));
        }
        else
            log.warn("replay cache was not provided, this is a serious security risk!");
        
        issuer = NULL;
        issuerTrusted = false;
        log.debug("attempting to establish issuer and integrity of message...");
        const vector<Assertion*>& assertions=const_cast<const Response*>(response)->getAssertions();
        if (!assertions.empty()) {
            const EntityDescriptor* provider=
                metadataProvider ? metadataProvider->getEntityDescriptor(assertions.front()->getIssuer()) : NULL;
            if (provider) {
                pair<bool,int> minor = response->getMinorVersion();
                issuer=provider->getRoleDescriptor(
                    *role,
                    (minor.first && minor.second==0) ? SAMLConstants::SAML10_PROTOCOL_ENUM : SAMLConstants::SAML11_PROTOCOL_ENUM
                    );
                if (issuer && trustEngine && response->getSignature()) {
                    issuerTrusted = static_cast<const TrustEngine*>(trustEngine)->validate(
                        *(response->getSignature()), *issuer, metadataProvider->getKeyResolver()
                        );
                    if (!issuerTrusted)
                        log.error("signature on message could not be verified by supplied trust engine");
                }
                if (log.isDebugEnabled()) {
                    auto_ptr_char iname(assertions.front()->getIssuer());
                    log.debug("message from (%s), integrity %sverified", iname.get(), issuerTrusted ? "" : "NOT ");
                }
            }
            else
                log.warn("no metadata provider supplied, can't establish identity of issuer");
        }
        else
            log.warn("no assertions found, can't establish identity of issuer");
    }
    catch (XMLToolingException& ex) {
        // Check for an Issuer.
        const vector<Assertion*>& assertions=const_cast<const Response*>(response)->getAssertions();
        if (!assertions.empty()) {
            if (!metadataProvider) {
                // Just record it.
                auto_ptr_char issuer(assertions.front()->getIssuer());
                if (issuer.get())
                    ex.addProperty("entityID", issuer.get());
                throw;  
            }
            // Try and locate metadata for error handling.
            const EntityDescriptor* provider=metadataProvider->getEntityDescriptor(assertions.front()->getIssuer(),false);
            if (provider) {
                pair<bool,int> minor = response->getMinorVersion();
                const IDPSSODescriptor* role=provider->getIDPSSODescriptor(
                    (minor.first && minor.second==0) ? SAMLConstants::SAML10_PROTOCOL_ENUM : SAMLConstants::SAML11_PROTOCOL_ENUM
                    );
                if (role) annotateException(&ex,role); // throws it
                annotateException(&ex,provider);  // throws it
            }
        }
    }

    xmlObject.release();
    return response;
}
