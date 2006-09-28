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
 * SAML1ArtifactEncoder.cpp
 * 
 * SAML 1.x Artifact binding/profile message encoder
 */

#include "internal.h"
#include "exceptions.h"
#include "saml/binding/ArtifactMap.h"
#include "saml/binding/SAMLArtifact.h"
#include "saml1/binding/SAML1ArtifactEncoder.h"
#include "saml1/core/Assertions.h"

#include <log4cpp/Category.hh>
#include <xmltooling/util/NDC.h>

using namespace opensaml::saml1;
using namespace opensaml::saml1p;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    namespace saml1p {              
        MessageEncoder* SAML_DLLLOCAL SAML1ArtifactEncoderFactory(const DOMElement* const & e)
        {
            return new SAML1ArtifactEncoder(e);
        }
    };
};

SAML1ArtifactEncoder::SAML1ArtifactEncoder(const DOMElement* e) {}

SAML1ArtifactEncoder::~SAML1ArtifactEncoder() {}

void SAML1ArtifactEncoder::encode(
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
    Category& log = Category::getInstance(SAML_LOGCAT".MessageEncoder.SAML1Artifact");
    log.debug("validating input");
    
    outputFields.clear();
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
    if (!m_artifactGenerator)
        throw BindingException("SAML 1.x Artifact Encoder requires an ArtifactGenerator instance.");
    log.debug("obtaining new artifact for relying party (%s)", recipientID ? recipientID : "unknown");
    auto_ptr<SAMLArtifact> artifact(m_artifactGenerator->generateSAML1Artifact(recipientID));
    
    // Pass back output fields.
    outputFields["SAMLart"] = artifact->encode();
    outputFields["TARGET"] = relayState;

    // Store the assertion. Last step in storage will be to delete the XML.
    log.debug("storing artifact and content in map");
    mapper->storeContent(xmlObject, artifact.get(), recipientID);

    log.debug("message encoded");
}