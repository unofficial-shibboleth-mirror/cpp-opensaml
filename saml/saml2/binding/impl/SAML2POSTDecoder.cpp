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
 * SAML2POSTDecoder.cpp
 * 
 * SAML 2.0 HTTP POST binding message encoder
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/MessageDecoder.h"
#include "saml2/core/Protocols.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"

#include <log4cpp/Category.hh>
#include <xercesc/util/Base64.hpp>
#include <xmltooling/io/HTTPRequest.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/validation/ValidatorSuite.h>

using namespace opensaml::saml2md;
using namespace opensaml::saml2p;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    namespace saml2p {              
        class SAML_DLLLOCAL SAML2POSTDecoder : public MessageDecoder
        {
        public:
            SAML2POSTDecoder(const DOMElement* e) {}
            virtual ~SAML2POSTDecoder() {}
            
            xmltooling::XMLObject* decode(
                std::string& relayState,
                const GenericRequest& genericRequest,
                SecurityPolicy& policy
                ) const;
        };                

        MessageDecoder* SAML_DLLLOCAL SAML2POSTDecoderFactory(const DOMElement* const & e)
        {
            return new SAML2POSTDecoder(e);
        }
    };
};

XMLObject* SAML2POSTDecoder::decode(
    std::string& relayState,
    const GenericRequest& genericRequest,
    SecurityPolicy& policy
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("decode");
#endif
    Category& log = Category::getInstance(SAML_LOGCAT".MessageDecoder.SAML2POST");

    log.debug("validating input");
    const HTTPRequest* httpRequest=dynamic_cast<const HTTPRequest*>(&genericRequest);
    if (!httpRequest) {
        log.error("unable to cast request to HTTPRequest type");
        return NULL;
    }
    if (strcmp(httpRequest->getMethod(),"POST"))
        return NULL;
    const char* msg = httpRequest->getParameter("SAMLResponse");
    if (!msg)
        msg = httpRequest->getParameter("SAMLRequest");
    if (!msg)
        return NULL;
    const char* state = httpRequest->getParameter("RelayState");
    if (state)
        relayState = state;
    else
        relayState.erase();

    // Decode the base64 into SAML.
    unsigned int x;
    XMLByte* decoded=Base64::decode(reinterpret_cast<const XMLByte*>(msg),&x);
    if (!decoded)
        throw BindingException("Unable to decode base64 in POST binding message.");
    log.debug("decoded SAML message:\n%s", decoded);
    istringstream is(reinterpret_cast<char*>(decoded));
    XMLString::release(&decoded);
    
    // Parse and bind the document into an XMLObject.
    DOMDocument* doc = (policy.getValidating() ? XMLToolingConfig::getConfig().getValidatingParser()
        : XMLToolingConfig::getConfig().getParser()).parse(is); 
    XercesJanitor<DOMDocument> janitor(doc);
    auto_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
    janitor.release();

    saml2::RootObject* root = NULL;
    StatusResponseType* response = NULL;
    RequestAbstractType* request = dynamic_cast<RequestAbstractType*>(xmlObject.get());
    if (!request) {
        response = dynamic_cast<StatusResponseType*>(xmlObject.get());
        if (!response)
            throw BindingException("XML content for SAML 2.0 HTTP-POST Decoder must be a SAML 2.0 protocol message.");
        root = static_cast<saml2::RootObject*>(response);
    }
    else {
        root = static_cast<saml2::RootObject*>(request);
    }
    
    if (!policy.getValidating())
        SchemaValidators.validate(xmlObject.get());

    // Run through the policy.
    policy.evaluate(*root, &genericRequest);
    
    // Check destination URL.
    auto_ptr_char dest(request ? request->getDestination() : response->getDestination());
    const char* dest2 = httpRequest->getRequestURL();
    if ((root->getSignature() || httpRequest->getParameter("Signature")) && (!dest.get() || !*(dest.get()))) {
        log.error("signed SAML message missing Destination attribute");
        throw BindingException("Signed SAML message missing Destination attribute identifying intended destination.");
    }
    else if (dest.get() && (!dest2 || !*dest2 || strcmp(dest.get(),dest2))) {
        log.error("POST targeted at (%s), but delivered to (%s)", dest.get(), dest2 ? dest2 : "none");
        throw BindingException("SAML message delivered with POST to incorrect server URL.");
    }
    
    return xmlObject.release();
}
