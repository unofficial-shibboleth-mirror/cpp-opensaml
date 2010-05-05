/*
 *  Copyright 2001-2010 Internet2
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
 * SAML 2.0 HTTP-POST binding message encoder.
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/MessageEncoder.h"
#include "signature/ContentReference.h"
#include "saml2/core/Protocols.h"

#include <fstream>
#include <sstream>
#include <xercesc/util/Base64.hpp>
#include <xsec/dsig/DSIGConstants.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/io/HTTPResponse.h>
#include <xmltooling/security/Credential.h>
#include <xmltooling/signature/KeyInfo.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/PathResolver.h>
#include <xmltooling/util/TemplateEngine.h>

using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml2p {              
        class SAML_DLLLOCAL SAML2POSTEncoder : public MessageEncoder
        {
        public:
            SAML2POSTEncoder(const DOMElement* e, const XMLCh* ns, bool simple=false);
            virtual ~SAML2POSTEncoder() {}
            
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

        private:        
            string m_template;
            bool m_simple;
        };

        MessageEncoder* SAML_DLLLOCAL SAML2POSTEncoderFactory(const pair<const DOMElement*,const XMLCh*>& p)
        {
            return new SAML2POSTEncoder(p.first, p.second, false);
        }

        MessageEncoder* SAML_DLLLOCAL SAML2POSTSimpleSignEncoderFactory(const pair<const DOMElement*,const XMLCh*>& p)
        {
            return new SAML2POSTEncoder(p.first, p.second, true);
        }
    };
};

static const XMLCh _template[] = UNICODE_LITERAL_8(t,e,m,p,l,a,t,e);

SAML2POSTEncoder::SAML2POSTEncoder(const DOMElement* e, const XMLCh* ns, bool simple) : m_simple(simple)
{
    if (e) {
        auto_ptr_char t(e->getAttributeNS(ns, _template));
        if (t.get() && *t.get())
            m_template = t.get();
    }
    if (m_template.empty())
        throw XMLToolingException("SAML2POSTEncoder requires template XML attribute.");
    XMLToolingConfig::getConfig().getPathResolver()->resolve(m_template, PathResolver::XMLTOOLING_CFG_FILE);
}

long SAML2POSTEncoder::encode(
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
    Category& log = Category::getInstance(SAML_LOGCAT".MessageEncoder.SAML2POST");
    log.debug("validating input");

    TemplateEngine* engine = XMLToolingConfig::getConfig().getTemplateEngine();
    if (!engine || !destination)
        throw BindingException("Encoding message using POST requires a TemplateEngine instance and a destination.");
    HTTPResponse::sanitizeURL(destination);
    if (xmlObject->getParent())
        throw BindingException("Cannot encode XML content with parent.");
    
    StatusResponseType* response = nullptr;
    RequestAbstractType* request = dynamic_cast<RequestAbstractType*>(xmlObject);
    if (!request) {
        response = dynamic_cast<StatusResponseType*>(xmlObject);
        if (!response)
            throw BindingException("XML content for SAML 2.0 HTTP-POST Encoder must be a SAML 2.0 protocol message.");
    }
    
    DOMElement* rootElement = nullptr;
    if (credential && !m_simple) {
        // Signature based on native XML signing.
        if (request ? request->getSignature() : response->getSignature()) {
            log.debug("message already signed, skipping signature operation");
        }
        else {
            log.debug("signing and marshalling the message");

            // Build a Signature.
            Signature* sig = SignatureBuilder::buildSignature();
            request ? request->setSignature(sig) : response->setSignature(sig);    
            if (signatureAlg)
                sig->setSignatureAlgorithm(signatureAlg);
            if (digestAlg) {
                opensaml::ContentReference* cr = dynamic_cast<opensaml::ContentReference*>(sig->getContentReference());
                if (cr)
                    cr->setDigestAlgorithm(digestAlg);
            }
            
            // Sign response while marshalling.
            vector<Signature*> sigs(1,sig);
            rootElement = xmlObject->marshall((DOMDocument*)nullptr,&sigs,credential);
        }
    }
    else {
        log.debug("marshalling the message");
        rootElement = xmlObject->marshall((DOMDocument*)nullptr);
    }
    
    // Serialize the message.
    TemplateEngine::TemplateParameters pmap;
    string& msg = pmap.m_map[(request ? "SAMLRequest" : "SAMLResponse")];
    XMLHelper::serialize(rootElement, msg);
    log.debug("marshalled message:\n%s", msg.c_str());
    
    // SimpleSign.
    if (credential && m_simple) {
        log.debug("applying simple signature to message data");
        string input = (request ? "SAMLRequest=" : "SAMLResponse=") + msg;
        if (relayState && *relayState)
            input = input + "&RelayState=" + relayState;
        if (!signatureAlg)
            signatureAlg = DSIGConstants::s_unicodeStrURIRSA_SHA1;
        auto_ptr_char alg(signatureAlg);
        pmap.m_map["SigAlg"] = alg.get();
        input = input + "&SigAlg=" + alg.get();

        char sigbuf[1024];
        memset(sigbuf,0,sizeof(sigbuf));
        Signature::createRawSignature(credential->getPrivateKey(), signatureAlg, input.c_str(), input.length(), sigbuf, sizeof(sigbuf)-1);
        pmap.m_map["Signature"] = sigbuf;

        auto_ptr<KeyInfo> keyInfo(credential->getKeyInfo());
        if (keyInfo.get()) {
            string& kstring = pmap.m_map["KeyInfo"];
            XMLHelper::serialize(keyInfo->marshall((DOMDocument*)nullptr), kstring);
            xsecsize_t len=0;
            XMLByte* out=Base64::encode(reinterpret_cast<const XMLByte*>(kstring.data()),kstring.size(),&len);
            if (!out)
                throw BindingException("Base64 encoding of XML failed.");
            kstring.erase();
            kstring.append(reinterpret_cast<char*>(out),len);
#ifdef OPENSAML_XERCESC_HAS_XMLBYTE_RELEASE
            XMLString::release(&out);
#else
            XMLString::release((char**)&out);
#endif
        }
    }
    
    // Base64 the message.
    xsecsize_t len=0;
    XMLByte* out=Base64::encode(reinterpret_cast<const XMLByte*>(msg.data()),msg.size(),&len);
    if (!out)
        throw BindingException("Base64 encoding of XML failed.");
    msg.erase();
    msg.append(reinterpret_cast<char*>(out),len);
#ifdef OPENSAML_XERCESC_HAS_XMLBYTE_RELEASE
    XMLString::release(&out);
#else
    XMLString::release((char**)&out);
#endif
    
    // Push the rest of it into template and send result to client.
    log.debug("message encoded, sending HTML form template to client");
    ifstream infile(m_template.c_str());
    if (!infile)
        throw BindingException("Failed to open HTML template for POST message ($1).", params(1,m_template.c_str()));
    pmap.m_map["action"] = destination;
    if (relayState && *relayState)
        pmap.m_map["RelayState"] = relayState;
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
