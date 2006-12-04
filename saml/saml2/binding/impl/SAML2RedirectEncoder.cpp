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
 * SAML2RedirectEncoder.cpp
 * 
 * SAML 2.0 HTTP-POST binding message encoder
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/HTTPResponse.h"
#include "binding/URLEncoder.h"
#include "saml2/binding/SAML2Redirect.h"
#include "saml2/binding/SAML2RedirectEncoder.h"
#include "saml2/core/Protocols.h"

#include <fstream>
#include <sstream>
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
        MessageEncoder* SAML_DLLLOCAL SAML2RedirectEncoderFactory(const DOMElement* const & e)
        {
            return new SAML2RedirectEncoder(e);
        }
    };
};

long SAML2RedirectEncoder::encode(
    GenericResponse& genericResponse,
    XMLObject* xmlObject,
    const char* destination,
    const char* recipientID,
    const char* relayState,
    const CredentialResolver* credResolver,
    const XMLCh* sigAlgorithm
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("encode");
#endif
    Category& log = Category::getInstance(SAML_LOGCAT".MessageEncoder.SAML2Redirect");

    log.debug("validating input");
    HTTPResponse* httpResponse=dynamic_cast<HTTPResponse*>(&genericResponse);
    if (!httpResponse)
        throw BindingException("Unable to cast response interface to HTTPResponse type.");
    if (xmlObject->getParent())
        throw BindingException("Cannot encode XML content with parent.");
    
    StatusResponseType* response = NULL;
    RequestAbstractType* request = dynamic_cast<RequestAbstractType*>(xmlObject);
    if (!request) {
        response = dynamic_cast<StatusResponseType*>(xmlObject);
        if (!response)
            throw BindingException("XML content for SAML 2.0 HTTP-POST Encoder must be a SAML 2.0 protocol message.");
    }
    
    // Check for XML signature.
    if (request ? request->getSignature() : response->getSignature()) {
        log.debug("message already signed, removing native signature due to size considerations");
        request ? request->setSignature(NULL) : response->setSignature(NULL);
    }
    
    log.debug("marshalling, deflating, base64-encoding the message");
    DOMElement* rootElement = xmlObject->marshall();
    string xmlbuf;
    XMLHelper::serialize(rootElement, xmlbuf);
    
    unsigned int len;
    char* deflated = deflate(const_cast<char*>(xmlbuf.c_str()), xmlbuf.length(), &len);
    if (!deflated)
        throw BindingException("Failed to deflate message.");
    
    XMLByte* encoded=Base64::encode(reinterpret_cast<XMLByte*>(deflated),len,&len);
    delete[] deflated;
    if (!encoded)
        throw BindingException("Base64 encoding of XML failed.");
    
    // Create beginnings of redirect query string.
    URLEncoder* escaper = SAMLConfig::getConfig().getURLEncoder();
    xmlbuf.erase();
    xmlbuf.append(reinterpret_cast<char*>(encoded),len);
    xmlbuf = (request ? "SAMLRequest=" : "SAMLResponse=") + escaper->encode(xmlbuf.c_str()); 
    if (relayState)
        xmlbuf = xmlbuf + "&RelayState=" + escaper->encode(relayState);
  
    if (credResolver) {
        // Sign the query string after adding the algorithm.
        if (!sigAlgorithm)
            sigAlgorithm = DSIGConstants::s_unicodeStrURIRSA_SHA1;
        auto_ptr_char alg(sigAlgorithm);
        xmlbuf = xmlbuf + "&SigAlg=" + escaper->encode(alg.get());

        char sigbuf[1024];
        memset(sigbuf,0,sizeof(sigbuf));
        auto_ptr<XSECCryptoKey> key(credResolver->getKey());
        Signature::createRawSignature(key.get(), sigAlgorithm, xmlbuf.c_str(), xmlbuf.length(), sigbuf, sizeof(sigbuf)-1);
        xmlbuf = xmlbuf + "&Signature=" + escaper->encode(sigbuf);
    }
    
    // Generate redirect.
    log.debug("message encoded, sending redirect to client");
    xmlbuf.insert(0,1,(strchr(destination,'?') ? '&' : '?'));
    xmlbuf.insert(0,destination);
    long ret = httpResponse->sendRedirect(xmlbuf.c_str());

    // Cleanup by destroying XML.
    delete xmlObject;
    
    return ret;
}
