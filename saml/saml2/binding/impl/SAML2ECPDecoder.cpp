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
 * SAML2ECPDecoder.cpp
 * 
 * SAML 2.0 ECP profile message decoder
 */

#include "internal.h"
#include "exceptions.h"
#include "saml2/binding/SAML2MessageDecoder.h"
#include "saml2/core/Protocols.h"

#include <xmltooling/logging.h>
#include <xmltooling/soap/SOAP.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/validation/ValidatorSuite.h>

using namespace opensaml::saml2p;
using namespace opensaml;
using namespace soap11;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml2p {              
        class SAML_DLLLOCAL SAML2ECPDecoder : public SAML2MessageDecoder
        {
        public:
            SAML2ECPDecoder() {}
            virtual ~SAML2ECPDecoder() {}

            xmltooling::XMLObject* decode(
                std::string& relayState,
                const GenericRequest& genericRequest,
                SecurityPolicy& policy
                ) const;
        };                

        MessageDecoder* SAML_DLLLOCAL SAML2ECPDecoderFactory(const pair<const DOMElement*,const XMLCh*>& p)
        {
            return new SAML2ECPDecoder();
        }
    };
};

XMLObject* SAML2ECPDecoder::decode(
    string& relayState,
    const GenericRequest& genericRequest,
    SecurityPolicy& policy
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("decode");
#endif
    Category& log = Category::getInstance(SAML_LOGCAT".MessageDecoder.SAML2ECP");

    log.debug("validating input");
    string s = genericRequest.getContentType();
    if (s.find("application/vnd.paos+xml") == string::npos) {
        log.warn("ignoring incorrect content type (%s)", s.c_str() ? s.c_str() : "none");
        throw BindingException("Invalid content type for PAOS message.");
    }

    const char* data = genericRequest.getRequestBody();
    if (!data)
        throw BindingException("PAOS message had an empty request body.");
    istringstream is(data);
    
    // Parse and bind the document into an XMLObject.
    DOMDocument* doc = (policy.getValidating() ? XMLToolingConfig::getConfig().getValidatingParser()
        : XMLToolingConfig::getConfig().getParser()).parse(is); 
    XercesJanitor<DOMDocument> janitor(doc);
    auto_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
    janitor.release();

    Envelope* env = dynamic_cast<Envelope*>(xmlObject.get());
    if (!env)
        throw BindingException("Decoded message was not a SOAP 1.1 Envelope.");

    if (!policy.getValidating())
        SchemaValidators.validate(env);
    
    Body* body = env->getBody();
    if (body && body->hasChildren()) {
        Response* response = dynamic_cast<Response*>(body->getUnknownXMLObjects().front());
        if (response) {
            // Run through the policy at two layers.
            extractMessageDetails(*env, genericRequest, samlconstants::SAML20P_NS, policy);
            policy.evaluate(*env, &genericRequest);
            policy.reset(true);
            extractMessageDetails(*response, genericRequest, samlconstants::SAML20P_NS, policy);
            policy.evaluate(*response, &genericRequest);
            
            // Check for RelayState header.
            if (env->getHeader()) {
                const vector<XMLObject*>& blocks = const_cast<const Header*>(env->getHeader())->getUnknownXMLObjects();
                for (vector<XMLObject*>::const_iterator h = blocks.begin(); h != blocks.end(); ++h) {
                    static const XMLCh RelayState[] = UNICODE_LITERAL_10(R,e,l,a,y,S,t,a,t,e);
                    if (XMLString::equals((*h)->getElementQName().getLocalPart(), RelayState) &&
                            XMLString::equals((*h)->getElementQName().getNamespaceURI(), samlconstants::SAML20ECP_NS)) {
                        const ElementProxy* ep = dynamic_cast<const ElementProxy*>(*h);
                        if (ep) {
                            auto_ptr_char rs(ep->getTextContent());
                            if (rs.get()) {
                                relayState = rs.get();
                                break;
                            }
                        }
                    }
                }
            }
            
            xmlObject.release();
            body->detach(); // frees Envelope
            response->detach();   // frees Body
            return response;
        }
    }
    
    throw BindingException("SOAP Envelope did not contain a SAML Response.");
}
