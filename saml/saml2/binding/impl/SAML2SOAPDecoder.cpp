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
 * SAML2SOAPDecoder.cpp
 * 
 * SAML 2.0 SOAP binding message decoder
 */

#include "internal.h"
#include "exceptions.h"
#include "saml2/binding/SAML2SOAPDecoder.h"

#include <log4cpp/Category.hh>
#include <xmltooling/soap/SOAP.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/validation/ValidatorSuite.h>

using namespace opensaml::saml2p;
using namespace opensaml;
using namespace soap11;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    namespace saml2p {              
        MessageDecoder* SAML_DLLLOCAL SAML2SOAPDecoderFactory(const DOMElement* const & e)
        {
            return new SAML2SOAPDecoder(e);
        }
    };
};

SAML2SOAPDecoder::SAML2SOAPDecoder(const DOMElement* e) {}

XMLObject* SAML2SOAPDecoder::decode(
    string& relayState,
    const GenericRequest& genericRequest,
    SecurityPolicy& policy
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("decode");
#endif
    Category& log = Category::getInstance(SAML_LOGCAT".MessageDecoder.SAML2SOAP");

    log.debug("validating input");
    string s = genericRequest.getContentType();
    if (s != "text/xml") {
        log.warn("ignoring incorrect Content Type (%s)", s.c_str() ? s.c_str() : "none");
        return NULL;
    }

    const char* data = genericRequest.getRequestBody();
    if (!data) {
        log.warn("empty request body");
        return NULL;
    }
    istringstream is(data);
    
    // Parse and bind the document into an XMLObject.
    DOMDocument* doc = (m_validate ? XMLToolingConfig::getConfig().getValidatingParser()
        : XMLToolingConfig::getConfig().getParser()).parse(is); 
    XercesJanitor<DOMDocument> janitor(doc);
    auto_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
    janitor.release();

    Envelope* env = dynamic_cast<Envelope*>(xmlObject.get());
    if (!env)
        throw BindingException("Decoded message was not a SOAP 1.1 Envelope.");

    if (!m_validate)
        SchemaValidators.validate(env);
    
    Body* body = env->getBody();
    if (body && body->hasChildren()) {
        RequestAbstractType* request = dynamic_cast<RequestAbstractType*>(body->getXMLObjects().front());
        if (request) {
            // Run through the policy at two layers.
            policy.evaluate(genericRequest, *env);
            policy.evaluate(genericRequest, *request);
            xmlObject.release();
            body->detach(); // frees Envelope
            request->detach();   // frees Body
            return request;
        }
    }
    
    throw BindingException("SOAP Envelope did not contain a SAML Request.");
}
