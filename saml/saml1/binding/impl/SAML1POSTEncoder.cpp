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
 * SAML1POSTEncoder.cpp
 * 
 * SAML 1.x POST binding/profile message encoder
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/MessageEncoder.h"
#include "signature/ContentReference.h"
#include "saml1/core/Protocols.h"

#include <fstream>
#include <sstream>
#include <log4cpp/Category.hh>
#include <xercesc/util/Base64.hpp>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/TemplateEngine.h>

using namespace opensaml::saml1p;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    namespace saml1p {              
        class SAML_DLLLOCAL SAML1POSTEncoder : public MessageEncoder
        {
        public:
            SAML1POSTEncoder(const DOMElement* e);
            virtual ~SAML1POSTEncoder() {}
            
            long encode(
                GenericResponse& genericResponse,
                XMLObject* xmlObject,
                const char* destination,
                const EntityDescriptor* recipient=NULL,
                const char* relayState=NULL,
                const ArtifactGenerator* artifactGenerator=NULL,
                const Credential* credential=NULL,
                const XMLCh* signatureAlg=NULL,
                const XMLCh* digestAlg=NULL
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

static const XMLCh _template[] = UNICODE_LITERAL_8(t,e,m,p,l,a,t,e);

SAML1POSTEncoder::SAML1POSTEncoder(const DOMElement* e)
{
    if (e) {
        auto_ptr_char t(e->getAttribute(_template));
        if (t.get() && *t.get())
            m_template = t.get();
    }
    if (m_template.empty())
        throw XMLToolingException("SAML1POSTEncoder requires template XML attribute.");
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
    Category& log = Category::getInstance(SAML_LOGCAT".MessageEncoder.SAML1POST");

    log.debug("validating input");
    if (xmlObject->getParent())
        throw BindingException("Cannot encode XML content with parent.");
    Response* response = dynamic_cast<Response*>(xmlObject);
    if (!response)
        throw BindingException("XML content for SAML 1.x POST Encoder must be a SAML 1.x <Response>.");
    if (!relayState)
        throw BindingException("SAML 1.x POST Encoder requires relay state (TARGET) value.");
    
    DOMElement* rootElement = NULL;
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
            rootElement = response->marshall((DOMDocument*)NULL,&sigs,credential);
        }
    }
    else {
        log.debug("marshalling the response");
        rootElement = response->marshall();
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

    // Push message into template and send result to client.
    log.debug("message encoded, sending HTML form template to client");
    TemplateEngine* engine = XMLToolingConfig::getConfig().getTemplateEngine();
    if (!engine)
        throw BindingException("Encoding response using POST requires a TemplateEngine instance.");
    ifstream infile(m_template.c_str());
    if (!infile)
        throw BindingException("Failed to open HTML template for POST response ($1).", params(1,m_template.c_str()));
    TemplateEngine::TemplateParameters params;
    params.m_map["action"] = destination;
    params.m_map["SAMLResponse"] = xmlbuf;
    params.m_map["TARGET"] = relayState;
    stringstream s;
    engine->run(infile, s, params);
    genericResponse.setContentType("text/html");
    long ret = genericResponse.sendResponse(s);

    // Cleanup by destroying XML.
    delete xmlObject;
    return ret;
}
