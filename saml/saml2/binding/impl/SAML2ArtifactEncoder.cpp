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
 * SAML2ArtifactEncoder.cpp
 * 
 * SAML 2.0 HTTP-Artifact binding message encoder
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/ArtifactMap.h"
#include "binding/HTTPResponse.h"
#include "binding/URLEncoder.h"
#include "saml2/binding/SAML2Artifact.h"
#include "saml2/binding/SAML2ArtifactEncoder.h"
#include "saml2/core/Protocols.h"

#include <fstream>
#include <sstream>
#include <log4cpp/Category.hh>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/TemplateEngine.h>

using namespace opensaml::saml2p;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    namespace saml2p {              
        MessageEncoder* SAML_DLLLOCAL SAML2ArtifactEncoderFactory(const DOMElement* const & e)
        {
            return new SAML2ArtifactEncoder(e);
        }
    };
};

static const XMLCh templat[] = UNICODE_LITERAL_8(t,e,m,p,l,a,t,e);

SAML2ArtifactEncoder::SAML2ArtifactEncoder(const DOMElement* e)
{
    if (e) {
        auto_ptr_char t(e->getAttributeNS(NULL, templat));
        if (t.get())
            m_template = t.get();
    }
}

long SAML2ArtifactEncoder::encode(
    GenericResponse& genericResponse,
    xmltooling::XMLObject* xmlObject,
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
    if (!m_artifactGenerator)
        throw BindingException("SAML 2.0 HTTP-Artifact Encoder requires an ArtifactGenerator instance.");
    log.debug("obtaining new artifact for relying party (%s)", recipientID ? recipientID : "unknown");
    auto_ptr<SAMLArtifact> artifact(m_artifactGenerator->generateSAML2Artifact(recipientID));

    if (credResolver) {
        // Signature based on native XML signing.
        if (request ? request->getSignature() : response->getSignature()) {
            log.debug("message already signed, skipping signature operation");
        }
        else {
            log.debug("signing the message");

            // Build a Signature.
            Signature* sig = buildSignature(credResolver, sigAlgorithm);
            
            // Append Signature.
            request ? request->setSignature(sig) : response->setSignature(sig);    
        
            // Sign response while marshalling.
            vector<Signature*> sigs(1,sig);
            xmlObject->marshall((DOMDocument*)NULL,&sigs);
        }
    }
    
    // Store the message. Last step in storage will be to delete the XML.
    log.debug("storing artifact and content in map");
    mapper->storeContent(xmlObject, artifact.get(), recipientID);

    if (m_template.empty()) {
        // Generate redirect.
        string loc = destination;
        loc += (strchr(destination,'?') ? '&' : '?');
        URLEncoder* escaper = SAMLConfig::getConfig().getURLEncoder();
        loc = loc + "SAMLart=" + escaper->encode(artifact->encode().c_str());
        if (relayState)
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
        if (relayState)
            params.m_map["RelayState"] = relayState;
        stringstream s;
        engine->run(infile, s, params);
        httpResponse->setContentType("text/html");
        return httpResponse->sendResponse(s);
    }
}
