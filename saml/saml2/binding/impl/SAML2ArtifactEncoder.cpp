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
 * SAML2ArtifactEncoder.cpp
 * 
 * SAML 2.0 HTTP-Artifact binding message encoder
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/ArtifactMap.h"
#include "binding/MessageEncoder.h"
#include "saml2/binding/SAML2Artifact.h"
#include "saml2/core/Protocols.h"
#include "saml2/metadata/Metadata.h"

#include <fstream>
#include <sstream>
#include <log4cpp/Category.hh>
#include <xmltooling/io/HTTPResponse.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/TemplateEngine.h>
#include <xmltooling/util/URLEncoder.h>

using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    namespace saml2p {              
        class SAML_DLLLOCAL SAML2ArtifactEncoder : public MessageEncoder
        {
        public:
            SAML2ArtifactEncoder(const DOMElement* e);
            virtual ~SAML2ArtifactEncoder() {}
            
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
        
        private:
            bool m_post;
            string m_template;
        };

        MessageEncoder* SAML_DLLLOCAL SAML2ArtifactEncoderFactory(const DOMElement* const & e)
        {
            return new SAML2ArtifactEncoder(e);
        }
    };

    static const XMLCh _template[] =    UNICODE_LITERAL_8(t,e,m,p,l,a,t,e);
    static const XMLCh postArtifact[] = UNICODE_LITERAL_12(p,o,s,t,A,r,t,i,f,a,c,t);
};

SAML2ArtifactEncoder::SAML2ArtifactEncoder(const DOMElement* e) : m_post(false)
{
    if (e) {
        const XMLCh* flag = e->getAttributeNS(NULL, postArtifact);
        m_post = (flag && (*flag==chLatin_t || *flag==chDigit_1));
        if (m_post) {
            auto_ptr_char t(e->getAttributeNS(NULL, _template));
            if (t.get())
                m_template = t.get();
        }
    }
}

long SAML2ArtifactEncoder::encode(
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
    Category& log = Category::getInstance(SAML_LOGCAT".MessageEncoder.SAML2Artifact");

    log.debug("validating input");
    HTTPResponse* httpResponse=dynamic_cast<HTTPResponse*>(&genericResponse);
    if (!httpResponse)
        throw BindingException("Unable to cast response interface to HTTPResponse type.");
    if (relayState && strlen(relayState)>80)
        throw BindingException("RelayState cannot exceed 80 bytes in length.");
    
    if (xmlObject->getParent())
        throw BindingException("Cannot encode XML content with parent.");

    StatusResponseType* response = NULL;
    RequestAbstractType* request = dynamic_cast<RequestAbstractType*>(xmlObject);
    if (!request)
        response = dynamic_cast<StatusResponseType*>(xmlObject);
    if (!response)
        throw BindingException("XML content for SAML 2.0 HTTP-Artifact Encoder must be a SAML 2.0 protocol message.");
    
    ArtifactMap* mapper = SAMLConfig::getConfig().getArtifactMap();
    if (!mapper)
        throw BindingException("SAML 2.0 HTTP-Artifact Encoder requires ArtifactMap be set in configuration.");

    // Obtain a fresh artifact.
    if (!artifactGenerator)
        throw BindingException("SAML 2.0 HTTP-Artifact Encoder requires an ArtifactGenerator instance.");
    auto_ptr_char recipientID(recipient ? recipient->getEntityID() : NULL);
    log.debug("obtaining new artifact for relying party (%s)", recipientID.get() ? recipientID.get() : "unknown");
    auto_ptr<SAMLArtifact> artifact(artifactGenerator->generateSAML2Artifact(recipient));

    if (credential) {
        // Signature based on native XML signing.
        if (request ? request->getSignature() : response->getSignature()) {
            log.debug("message already signed, skipping signature operation");
        }
        else {
            log.debug("signing the message");

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
            xmlObject->marshall((DOMDocument*)NULL,&sigs,credential);
        }
    }
    
    // Store the message. Last step in storage will be to delete the XML.
    log.debug("storing artifact and content in map");
    mapper->storeContent(xmlObject, artifact.get(), recipientID.get());

    if (m_template.empty()) {
        // Generate redirect.
        string loc = destination;
        loc += (strchr(destination,'?') ? '&' : '?');
        const URLEncoder* escaper = XMLToolingConfig::getConfig().getURLEncoder();
        loc = loc + "SAMLart=" + escaper->encode(artifact->encode().c_str());
        if (relayState && *relayState)
            loc = loc + "&RelayState=" + escaper->encode(relayState);
        log.debug("message encoded, sending redirect to client");
        return httpResponse->sendRedirect(loc.c_str());
    }
    else {
        // Push message into template and send result to client. 
        log.debug("message encoded, sending HTML form template to client");
        TemplateEngine* engine = XMLToolingConfig::getConfig().getTemplateEngine();
        if (!engine)
            throw BindingException("Encoding artifact using POST requires a TemplateEngine instance.");
        ifstream infile(m_template.c_str());
        if (!infile)
            throw BindingException("Failed to open HTML template for POST response ($1).", params(1,m_template.c_str()));
        TemplateEngine::TemplateParameters params;
        params.m_map["action"] = destination;
        params.m_map["SAMLart"] = artifact->encode();
        if (relayState && *relayState)
            params.m_map["RelayState"] = relayState;
        stringstream s;
        engine->run(infile, s, params);
        httpResponse->setContentType("text/html");
        return httpResponse->sendResponse(s);
    }
}
