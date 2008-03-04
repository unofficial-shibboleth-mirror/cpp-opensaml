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
 * SAML1POSTDecoder.cpp
 * 
 * SAML 1.x POST binding/profile message decoder
 */

#include "internal.h"
#include "exceptions.h"
#include "saml1/binding/SAML1MessageDecoder.h"
#include "saml1/core/Assertions.h"
#include "saml1/core/Protocols.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"

#include <xercesc/framework/MemBufInputSource.hpp>
#include <xercesc/framework/Wrapper4InputSource.hpp>
#include <xercesc/util/Base64.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/io/HTTPRequest.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/validation/ValidatorSuite.h>

using namespace opensaml::saml2md;
using namespace opensaml::saml1p;
using namespace opensaml::saml1;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml1p {              
        class SAML_DLLLOCAL SAML1POSTDecoder : public SAML1MessageDecoder
        {
        public:
            SAML1POSTDecoder() {}
            virtual ~SAML1POSTDecoder() {}
            
            xmltooling::XMLObject* decode(
                std::string& relayState,
                const GenericRequest& genericRequest,
                SecurityPolicy& policy
                ) const;
        };                

        MessageDecoder* SAML_DLLLOCAL SAML1POSTDecoderFactory(const pair<const DOMElement*,const XMLCh*>& p)
        {
            return new SAML1POSTDecoder();
        }
    };
};

XMLObject* SAML1POSTDecoder::decode(
    string& relayState,
    const GenericRequest& genericRequest,
    SecurityPolicy& policy
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("decode");
#endif
    Category& log = Category::getInstance(SAML_LOGCAT".MessageDecoder.SAML1POST");

    log.debug("validating input");
    const HTTPRequest* httpRequest=dynamic_cast<const HTTPRequest*>(&genericRequest);
    if (!httpRequest)
        throw BindingException("Unable to cast request object to HTTPRequest type.");
    if (strcmp(httpRequest->getMethod(),"POST"))
        throw BindingException("Invalid HTTP method ($1).", params(1, httpRequest->getMethod()));
    const char* samlResponse = httpRequest->getParameter("SAMLResponse");
    const char* TARGET = httpRequest->getParameter("TARGET");
    if (!samlResponse || !TARGET)
        throw BindingException("Request missing SAMLResponse or TARGET form parameters.");
    relayState = TARGET;

    // Decode the base64 into XML.
    unsigned int x;
    XMLByte* decoded=Base64::decode(reinterpret_cast<const XMLByte*>(samlResponse),&x);
    if (!decoded)
        throw BindingException("Unable to decode base64 in POST profile response.");
    log.debugStream() << "decoded SAML response:\n" << decoded << logging::eol;

    // Parse and bind the document into an XMLObject.
    MemBufInputSource src(decoded, x, "SAMLResponse", true);
    Wrapper4InputSource dsrc(&src, false);
    DOMDocument* doc = (policy.getValidating() ? XMLToolingConfig::getConfig().getValidatingParser()
        : XMLToolingConfig::getConfig().getParser()).parse(dsrc); 
    XercesJanitor<DOMDocument> janitor(doc);
    auto_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
    janitor.release();

    Response* response = dynamic_cast<Response*>(xmlObject.get());
    if (!response)
        throw BindingException("Decoded message was not a SAML 1.x Response.");

    if (!policy.getValidating())
        SchemaValidators.validate(response);
    
    pair<bool,int> minor = response->getMinorVersion();
    extractMessageDetails(
        *response,
        genericRequest,
        (minor.first && minor.second==0) ? samlconstants::SAML10_PROTOCOL_ENUM : samlconstants::SAML11_PROTOCOL_ENUM,
        policy
        );

    // Run through the policy.
    policy.evaluate(*response,&genericRequest);
    
    // Check recipient URL.
    auto_ptr_char recipient(response->getRecipient());
    const char* recipient2 = httpRequest->getRequestURL();
    const char* delim = strchr(recipient2, '?');
    if (!recipient.get() || !*(recipient.get())) {
        log.error("response missing Recipient attribute");
        throw BindingException("SAML response did not contain Recipient attribute identifying intended destination.");
    }
    else if ((delim && strncmp(recipient.get(), recipient2, delim - recipient2)) || (!delim && strcmp(recipient.get(),recipient2))) {
        log.error("POST targeted at (%s), but delivered to (%s)", recipient.get(), recipient2);
        throw BindingException("SAML message delivered with POST to incorrect server URL.");
    }
    
    return xmlObject.release();
}
