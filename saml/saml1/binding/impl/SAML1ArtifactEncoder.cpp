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
 * SAML1ArtifactEncoder.cpp
 * 
 * SAML 1.x Artifact binding/profile message encoder
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/ArtifactMap.h"
#include "binding/MessageEncoder.h"
#include "binding/SAMLArtifact.h"
#include "saml1/core/Assertions.h"
#include "saml1/core/Protocols.h"
#include "saml2/metadata/Metadata.h"

#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/io/HTTPResponse.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/URLEncoder.h>

using namespace opensaml::saml1;
using namespace opensaml::saml1p;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml1p {              
        class SAML_DLLLOCAL SAML1ArtifactEncoder : public MessageEncoder
        {
        public:
            SAML1ArtifactEncoder() {}
            virtual ~SAML1ArtifactEncoder() {}
            
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
        };                

        MessageEncoder* SAML_DLLLOCAL SAML1ArtifactEncoderFactory(const pair<const DOMElement*,const XMLCh*>& p)
        {
            return new SAML1ArtifactEncoder();
        }
    };
};

long SAML1ArtifactEncoder::encode(
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
    Category& log = Category::getInstance(SAML_LOGCAT".MessageEncoder.SAML1Artifact");

    log.debug("validating input");
    HTTPResponse* httpResponse=dynamic_cast<HTTPResponse*>(&genericResponse);
    if (!httpResponse)
        throw BindingException("Unable to cast response interface to HTTPResponse type.");
    if (xmlObject->getParent())
        throw BindingException("Cannot encode XML content with parent.");
    Assertion* assertion = dynamic_cast<Assertion*>(xmlObject);
    if (!assertion)
        throw BindingException("XML content for SAML 1.x Artifact Encoder must be a SAML 1.x <Assertion>.");
    if (!relayState)
        throw BindingException("SAML 1.x Artifact Encoder requires relay state (TARGET) value.");
    
    // Signing is a protocol level issue, so no signing here...
    
    ArtifactMap* mapper = SAMLConfig::getConfig().getArtifactMap();
    if (!mapper)
        throw BindingException("SAML 1.x Artifact Encoder requires ArtifactMap be set in configuration.");

    // Obtain a fresh artifact.
    if (!artifactGenerator)
        throw BindingException("SAML 1.x Artifact Encoder requires an ArtifactGenerator instance.");
    auto_ptr_char recipientID(recipient ? recipient->getEntityID() : NULL);
    log.debug("obtaining new artifact for relying party (%s)", recipientID.get() ? recipientID.get() : "unknown");
    auto_ptr<SAMLArtifact> artifact(artifactGenerator->generateSAML1Artifact(recipient));
    
    // Store the assertion. Last step in storage will be to delete the XML.
    log.debug("storing artifact and content in map");
    mapper->storeContent(xmlObject, artifact.get(), recipientID.get());

    // Generate redirect.
    string loc = destination;
    loc += (strchr(destination,'?') ? '&' : '?');
    const URLEncoder* escaper = XMLToolingConfig::getConfig().getURLEncoder();
    loc = loc + "SAMLart=" + escaper->encode(artifact->encode().c_str()) + "&TARGET=" + escaper->encode(relayState);
    log.debug("message encoded, sending redirect to client");
    return httpResponse->sendRedirect(loc.c_str());
}
