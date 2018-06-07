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
 * SAML2RedirectEncoder.cpp
 * 
 * SAML 2.0 HTTP-POST binding message encoder.
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/MessageEncoder.h"
#include "saml2/core/Protocols.h"

#include <fstream>
#include <sstream>
#include <xercesc/util/Base64.hpp>
#include <xsec/dsig/DSIGConstants.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/io/HTTPResponse.h>
#include <xmltooling/security/Credential.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/URLEncoder.h>
#include <xmltooling/util/XMLHelper.h>

using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml2p {              
        class SAML_DLLLOCAL SAML2RedirectEncoder : public MessageEncoder
        {
        public:
            SAML2RedirectEncoder() {}
            virtual ~SAML2RedirectEncoder() {}

            bool isCompact() const {
                return true;
            }

            const XMLCh* getProtocolFamily() const {
                return samlconstants::SAML20P_NS;
            }

            long encode(
                GenericResponse& genericResponse,
                XMLObject* xmlObject,
                const char* destination,
                const EntityDescriptor* recipient=nullptr,
                const char* relayState=nullptr,
                const ArtifactGenerator* artifactGenerator=nullptr,
                const Credential* credential=nullptr,
                const XMLCh* signatureAlg=nullptr,
                const XMLCh* digestAlg=nullptr
                ) const;
        };

        MessageEncoder* SAML_DLLLOCAL SAML2RedirectEncoderFactory(const DOMElement* const &, bool)
        {
            return new SAML2RedirectEncoder();
        }
    };
};

long SAML2RedirectEncoder::encode(
    GenericResponse& genericResponse,
    XMLObject* xmlObject,
    const char* destination,
    const EntityDescriptor* recipient,
    const char* relayState,
    const ArtifactGenerator* artifactGenerator,
    const Credential* credential,
    const XMLCh* signatureAlg,
    const XMLCh* digestAlg
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("encode");
#endif
    Category& log = Category::getInstance(SAML_LOGCAT ".MessageEncoder.SAML2Redirect");

    log.debug("validating input");
    HTTPResponse* httpResponse=dynamic_cast<HTTPResponse*>(&genericResponse);
    if (!httpResponse)
        throw BindingException("Unable to cast response interface to HTTPResponse type.");
    if (xmlObject->getParent())
        throw BindingException("Cannot encode XML content with parent.");
    
    StatusResponseType* response = nullptr;
    RequestAbstractType* request = dynamic_cast<RequestAbstractType*>(xmlObject);
    if (!request) {
        response = dynamic_cast<StatusResponseType*>(xmlObject);
        if (!response)
            throw BindingException("XML content for SAML 2.0 HTTP-Redirect Encoder must be a SAML 2.0 protocol message.");
    }
    
    // Check for XML signature.
    if (request ? request->getSignature() : response->getSignature()) {
        log.debug("message already signed, removing native signature due to size considerations");
        request ? request->setSignature(nullptr) : response->setSignature(nullptr);
    }
    
    log.debug("marshalling, deflating, base64-encoding the message");
    DOMElement* rootElement = xmlObject->marshall();
    string xmlbuf;
    XMLHelper::serialize(rootElement, xmlbuf);
    log.debug("marshalled message:\n%s", xmlbuf.c_str());
    
    unsigned int len;
    char* deflated = XMLHelper::deflate(const_cast<char*>(xmlbuf.c_str()), xmlbuf.length(), &len);
    if (!deflated)
        throw BindingException("Failed to deflate message.");
    
    XMLSize_t xlen;
    XMLByte* encoded=Base64::encode(reinterpret_cast<XMLByte*>(deflated), len, &xlen);
    delete[] deflated;
    if (!encoded)
        throw BindingException("Base64 encoding of XML failed.");
    
    // Create beginnings of redirect query string.
    xmlbuf.erase();
    for (const XMLByte* xb = encoded; *xb; ++xb) {
        if (!isspace(*xb))
            xmlbuf += *xb;
    }
    XMLString::release((char**)&encoded);
    
    const URLEncoder* escaper = XMLToolingConfig::getConfig().getURLEncoder();
    xmlbuf = (request ? "SAMLRequest=" : "SAMLResponse=") + escaper->encode(xmlbuf.c_str()); 
    if (relayState && *relayState)
        xmlbuf = xmlbuf + "&RelayState=" + escaper->encode(relayState);
  
    if (credential) {
        log.debug("signing the message");
        
        // Sign the query string after adding the algorithm.
        if (!signatureAlg) {
#ifdef XSEC_OPENSSL_HAVE_SHA2
            signatureAlg = DSIGConstants::s_unicodeStrURIRSA_SHA256;
#else
            signatureAlg = DSIGConstants::s_unicodeStrURIRSA_SHA1;
#endif
        }
        auto_ptr_char alg(signatureAlg);
        xmlbuf = xmlbuf + "&SigAlg=" + escaper->encode(alg.get());

        char sigbuf[1024];
        memset(sigbuf,0,sizeof(sigbuf));
        Signature::createRawSignature(credential->getPrivateKey(), signatureAlg, xmlbuf.c_str(), xmlbuf.length(), sigbuf, sizeof(sigbuf)-1);
        xmlbuf = xmlbuf + "&Signature=" + escaper->encode(sigbuf);
    }
    
    // Generate redirect.
    log.debug("message encoded, sending redirect to client");
    xmlbuf.insert((string::size_type)0,(string::size_type)1,(strchr(destination,'?') ? '&' : '?'));
    xmlbuf.insert(0,destination);
    long ret = httpResponse->sendRedirect(xmlbuf.c_str());

    // Cleanup by destroying XML.
    delete xmlObject;
    
    return ret;
}
