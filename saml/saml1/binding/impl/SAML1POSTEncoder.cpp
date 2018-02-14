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
 * SAML1POSTEncoder.cpp
 * 
 * SAML 1.x POST binding/profile message encoder.
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/MessageEncoder.h"
#include "signature/ContentReference.h"
#include "saml1/core/Protocols.h"

#include <fstream>
#include <sstream>
#include <xercesc/util/Base64.hpp>
#include <xsec/framework/XSECDefs.hpp>
#include <xmltooling/io/HTTPResponse.h>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/PathResolver.h>
#include <xmltooling/util/TemplateEngine.h>

using namespace opensaml::saml1p;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml1p {              
        class SAML_DLLLOCAL SAML1POSTEncoder : public MessageEncoder
        {
        public:
            SAML1POSTEncoder(const DOMElement* e);
            virtual ~SAML1POSTEncoder() {}

            const XMLCh* getProtocolFamily() const {
                return samlconstants::SAML11_PROTOCOL_ENUM;
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

        protected:
            /** Pathname of HTML template for transmission of message via POST. */
            string m_template;
        };

        MessageEncoder* SAML_DLLLOCAL SAML1POSTEncoderFactory(const DOMElement* const & e)
        {
            return new SAML1POSTEncoder(e);
        }
    };
};

SAML1POSTEncoder::SAML1POSTEncoder(const DOMElement* e)
{
    // Fishy alert: we ignore the namespace and look for a matching DOM Attr node by name only.
    // Can't use DOM 1 calls, so we have to walk the attribute list by hand.

    static const XMLCh _template[] = UNICODE_LITERAL_8(t, e, m, p, l, a, t, e);

    const DOMNamedNodeMap* attributes = e->getAttributes();
    XMLSize_t size = attributes ? attributes->getLength() : 0;
    for (XMLSize_t i = 0; i < size; ++i) {
        const DOMNode* attr = attributes->item(i);
        if (XMLString::equals(attr->getLocalName(), _template)) {
            auto_ptr_char val(attr->getNodeValue());
            if (val.get())
                m_template = val.get();
        }
    }

    if (m_template.empty())
        m_template = "bindingTemplate.html";
    XMLToolingConfig::getConfig().getPathResolver()->resolve(m_template, PathResolver::XMLTOOLING_CFG_FILE);
}

long SAML1POSTEncoder::encode(
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
    Category& log = Category::getInstance(SAML_LOGCAT ".MessageEncoder.SAML1POST");
    log.debug("validating input");

    TemplateEngine* engine = XMLToolingConfig::getConfig().getTemplateEngine();
    if (!engine || !destination)
        throw BindingException("Encoding response using POST requires a TemplateEngine instance and a destination.");
    HTTPResponse::sanitizeURL(destination);
    if (xmlObject->getParent())
        throw BindingException("Cannot encode XML content with parent.");
    Response* response = dynamic_cast<Response*>(xmlObject);
    if (!response)
        throw BindingException("XML content for SAML 1.x POST Encoder must be a SAML 1.x <Response>.");
    if (!relayState)
        throw BindingException("SAML 1.x POST Encoder requires relay state (TARGET) value.");
    
    DOMElement* rootElement = nullptr;
    if (credential) {
        // Signature based on native XML signing.
        if (response->getSignature()) {
            log.debug("response already signed, skipping signature operation");
        }
        else {
            log.debug("signing and marshalling the response");

            // Build a Signature.
            Signature* sig = SignatureBuilder::buildSignature();
            response->setSignature(sig);
            if (signatureAlg)
                sig->setSignatureAlgorithm(signatureAlg);
            if (digestAlg) {
                opensaml::ContentReference* cr = dynamic_cast<opensaml::ContentReference*>(sig->getContentReference());
                if (cr)
                    cr->setDigestAlgorithm(digestAlg);
            }
    
            // Sign response while marshalling.
            vector<Signature*> sigs(1,sig);
            rootElement = response->marshall((DOMDocument*)nullptr,&sigs,credential);
        }
    }
    else {
        log.debug("marshalling the response");
        rootElement = response->marshall();
    }

    // Push message into template.
    TemplateEngine::TemplateParameters pmap;
    string& xmlbuf = pmap.m_map["SAMLResponse"];
    XMLHelper::serialize(rootElement, xmlbuf);
    log.debug("marshalled response:\n%s", xmlbuf.c_str());
    
    // Replace with base-64 encoded version.
    XMLSize_t len=0;
    XMLByte* out=Base64::encode(reinterpret_cast<const XMLByte*>(xmlbuf.data()),xmlbuf.size(),&len);
    if (out) {
        xmlbuf.erase();
        xmlbuf.append(reinterpret_cast<char*>(out),len);
        XMLString::release((char**)&out);
    }
    else {
        throw BindingException("Base64 encoding of XML failed.");
    }

    // Fill in the rest of the data and send to the client.
    log.debug("message encoded, sending HTML form template to client");
    ifstream infile(m_template.c_str());
    if (!infile)
        throw BindingException("Failed to open HTML template for POST response ($1).", params(1,m_template.c_str()));
    pmap.m_map["action"] = destination;
    pmap.m_map["TARGET"] = relayState;
    stringstream s;
    engine->run(infile, s, pmap);
    genericResponse.setContentType("text/html");
    HTTPResponse* httpResponse = dynamic_cast<HTTPResponse*>(&genericResponse);
    if (httpResponse) {
        httpResponse->setResponseHeader("Expires", "01-Jan-1997 12:00:00 GMT");
        httpResponse->setResponseHeader("Cache-Control", "no-cache, no-store, must-revalidate, private");
        httpResponse->setResponseHeader("Pragma", "no-cache");
    }
    long ret = genericResponse.sendResponse(s);

    // Cleanup by destroying XML.
    delete xmlObject;
    return ret;
}
