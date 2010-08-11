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
 * SAML2ArtifactEncoder.cpp
 * 
 * SAML 2.0 HTTP-Artifact binding message encoder.
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/ArtifactMap.h"
#include "binding/MessageEncoder.h"
#include "saml2/binding/SAML2Artifact.h"
#include "saml2/core/Protocols.h"
#include "saml2/metadata/Metadata.h"
#include "signature/ContentReference.h"

#include <fstream>
#include <sstream>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/io/HTTPResponse.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/PathResolver.h>
#include <xmltooling/util/TemplateEngine.h>
#include <xmltooling/util/URLEncoder.h>

using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml2p {              
        class SAML_DLLLOCAL SAML2ArtifactEncoder : public MessageEncoder
        {
        public:
            SAML2ArtifactEncoder(const DOMElement* e, const XMLCh* ns);
            virtual ~SAML2ArtifactEncoder() {}

            const XMLCh* getProtocolFamily() const {
                return samlconstants::SAML20P_NS;
            }

            const char* getShortName() const {
                return "Artifact";
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
        
        private:
            string m_template;
        };

        MessageEncoder* SAML_DLLLOCAL SAML2ArtifactEncoderFactory(const pair<const DOMElement*,const XMLCh*>& p)
        {
            return new SAML2ArtifactEncoder(p.first, p.second);
        }
    };

    static const XMLCh _template[] =    UNICODE_LITERAL_8(t,e,m,p,l,a,t,e);
    static const XMLCh postArtifact[] = UNICODE_LITERAL_12(p,o,s,t,A,r,t,i,f,a,c,t);
};

SAML2ArtifactEncoder::SAML2ArtifactEncoder(const DOMElement* e, const XMLCh* ns)
{
    if (XMLHelper::getAttrBool(e, false, postArtifact, ns)) {
        m_template = XMLHelper::getAttrString(e, "bindingTemplate.html", _template, ns);
        if (!m_template.empty())
            XMLToolingConfig::getConfig().getPathResolver()->resolve(m_template, PathResolver::XMLTOOLING_CFG_FILE);
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
    if (!destination)
        throw BindingException("Encoding response requires a destination.");
    HTTPResponse* httpResponse=dynamic_cast<HTTPResponse*>(&genericResponse);
    if (!httpResponse)
        throw BindingException("Unable to cast response interface to HTTPResponse type.");
    if (relayState && strlen(relayState)>80)
        throw BindingException("RelayState cannot exceed 80 bytes in length.");
    if (xmlObject->getParent())
        throw BindingException("Cannot encode XML content with parent.");

    StatusResponseType* response = nullptr;
    RequestAbstractType* request = dynamic_cast<RequestAbstractType*>(xmlObject);
    if (!request) {
        response = dynamic_cast<StatusResponseType*>(xmlObject);
        if (!response)
            throw BindingException("XML content for SAML 2.0 HTTP-Artifact Encoder must be a SAML 2.0 protocol message.");
    }
    
    ArtifactMap* mapper = SAMLConfig::getConfig().getArtifactMap();
    if (!mapper)
        throw BindingException("SAML 2.0 HTTP-Artifact Encoder requires ArtifactMap be set in configuration.");

    // Obtain a fresh artifact.
    if (!artifactGenerator)
        throw BindingException("SAML 2.0 HTTP-Artifact Encoder requires an ArtifactGenerator instance.");
    auto_ptr_char recipientID(recipient ? recipient->getEntityID() : nullptr);
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
            xmlObject->marshall((DOMDocument*)nullptr,&sigs,credential);
        }
    }

    if (log.isDebugEnabled())
        log.debugStream() << "marshalled message:" << logging::eol << *xmlObject << logging::eol;
    
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
        HTTPResponse::sanitizeURL(destination);
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
        httpResponse->setResponseHeader("Expires", "01-Jan-1997 12:00:00 GMT");
        httpResponse->setResponseHeader("Cache-Control", "no-cache, no-store, must-revalidate, private");
        httpResponse->setResponseHeader("Pragma", "no-cache");
        return httpResponse->sendResponse(s);
    }
}
