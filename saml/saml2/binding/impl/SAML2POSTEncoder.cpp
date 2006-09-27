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
 * SAML2POSTEncoder.cpp
 * 
 * SAML 2.0 HTTP-POST binding message encoder
 */

#include "internal.h"
#include "exceptions.h"
#include "saml2/binding/SAML2POSTEncoder.h"
#include "saml2/core/Protocols.h"

#include <log4cpp/Category.hh>
#include <xercesc/util/Base64.hpp>
#include <xmltooling/util/NDC.h>

using namespace opensaml::saml2p;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    namespace saml2p {              
        MessageEncoder* SAML_DLLLOCAL SAML2POSTEncoderFactory(const DOMElement* const & e)
        {
            return new SAML2POSTEncoder(e);
        }
    };
};

SAML2POSTEncoder::SAML2POSTEncoder(const DOMElement* e) {}

SAML2POSTEncoder::~SAML2POSTEncoder() {}

void SAML2POSTEncoder::encode(
    map<string,string>& outputFields,
    XMLObject* xmlObject,
    const char* recipientID,
    const char* relayState,
    const CredentialResolver* credResolver,
    const XMLCh* sigAlgorithm
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("encode");
#endif
    Category& log = Category::getInstance(SAML_LOGCAT".MessageEncoder.SAML2POST");
    log.debug("validating input");
    
    outputFields.clear();
    if (xmlObject->getParent())
        throw BindingException("Cannot encode XML content with parent.");
    
    StatusResponseType* response = NULL;
    RequestAbstractType* request = dynamic_cast<RequestAbstractType*>(xmlObject);
    if (!request)
        response = dynamic_cast<StatusResponseType*>(xmlObject);
    if (!response)
        throw BindingException("XML content for SAML 2.0 HTTP-POST Encoder must be a SAML 2.0 protocol message.");
    
    DOMElement* rootElement = NULL;
    if (credResolver) {
        // Signature based on native XML signing.
        if (request ? request->getSignature() : response->getSignature()) {
            log.debug("message already signed, skipping signature operation");
        }
        else {
            log.debug("signing and marshalling the message");

            // Build a Signature.
            Signature* sig = buildSignature(credResolver, sigAlgorithm);
            
            // Append Signature.
            request ? request->setSignature(sig) : response->setSignature(sig);    
        
            // Sign response while marshalling.
            vector<Signature*> sigs(1,sig);
            rootElement = xmlObject->marshall((DOMDocument*)NULL,&sigs);
        }
    }
    else {
        log.debug("marshalling the message");
        rootElement = xmlObject->marshall();
    }
    
    string xmlbuf;
    XMLHelper::serialize(rootElement, xmlbuf);
    unsigned int len=0;
    XMLByte* out=Base64::encode(reinterpret_cast<const XMLByte*>(xmlbuf.data()),xmlbuf.size(),&len);
    if (out) {
        xmlbuf.erase();
        xmlbuf.append(reinterpret_cast<char*>(out),len);
        XMLString::release(&out);
    }
    else {
        throw BindingException("Base64 encoding of XML failed.");
    }
    
    // Pass back output fields.
    outputFields[request ? "SAMLRequest" : "SAMLResponse"] = xmlbuf;
    if (relayState)
        outputFields["RelayState"] = relayState;

    // Cleanup by destroying XML.
    delete xmlObject;

    log.debug("message encoded");
}
