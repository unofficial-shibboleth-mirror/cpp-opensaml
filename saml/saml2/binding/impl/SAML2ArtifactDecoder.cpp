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
 * SAML2ArtifactDecoder.cpp
 * 
 * SAML 2.0 Artifact binding message decoder
 */

#include "internal.h"
#include "exceptions.h"
#include "saml2/binding/SAML2Artifact.h"
#include "saml2/binding/SAML2MessageDecoder.h"
#include "saml2/core/Protocols.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"

#include <xmltooling/logging.h>
#include <xmltooling/io/HTTPRequest.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReplayCache.h>

using namespace opensaml::saml2md;
using namespace opensaml::saml2p;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml2p {              
        class SAML_DLLLOCAL SAML2ArtifactDecoder : public SAML2MessageDecoder
        {
        public:
            SAML2ArtifactDecoder() {}
            virtual ~SAML2ArtifactDecoder() {}
            
            xmltooling::XMLObject* decode(
                std::string& relayState,
                const GenericRequest& genericRequest,
                SecurityPolicy& policy
                ) const;
        };                

        MessageDecoder* SAML_DLLLOCAL SAML2ArtifactDecoderFactory(const pair<const DOMElement*,const XMLCh*>& p)
        {
            return new SAML2ArtifactDecoder();
        }
    };
};

XMLObject* SAML2ArtifactDecoder::decode(
    string& relayState,
    const GenericRequest& genericRequest,
    SecurityPolicy& policy
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("decode");
#endif
    Category& log = Category::getInstance(SAML_LOGCAT".MessageDecoder.SAML2Artifact");

    log.debug("validating input");
    const HTTPRequest* httpRequest=dynamic_cast<const HTTPRequest*>(&genericRequest);
    if (!httpRequest)
        throw BindingException("Unable to cast request object to HTTPRequest type.");
    const char* SAMLart = httpRequest->getParameter("SAMLart");
    if (!SAMLart)
        throw BindingException("Request missing SAMLart query string or form parameter.");
    const char* state = httpRequest->getParameter("RelayState");
    if (state)
        relayState = state;

    if (!m_artifactResolver || !policy.getMetadataProvider() || !policy.getRole())
        throw BindingException("Artifact binding requires ArtifactResolver and MetadataProvider implementations be supplied.");

    // Import the artifact.
    SAMLArtifact* artifact=NULL;
    try {
        log.debug("processing encoded artifact (%s)", SAMLart);
        
        // Check replay.
        ReplayCache* replayCache = XMLToolingConfig::getConfig().getReplayCache();
        if (replayCache) {
            if (!replayCache->check("SAML2Artifact", SAMLart, time(NULL) + (2*XMLToolingConfig::getConfig().clock_skew_secs))) {
                log.error("replay detected of artifact (%s)", SAMLart);
                throw BindingException("Rejecting replayed artifact ($1).", params(1,SAMLart));
            }
        }
        else
            log.warn("replay cache was not provided, this is a serious security risk!");

        artifact = SAMLArtifact::parse(SAMLart);
    }
    catch (ArtifactException&) {
        log.error("error parsing artifact (%s)", SAMLart);
        throw;
    }
    
    // Check the type.
    auto_ptr<SAML2Artifact> artifact2(dynamic_cast<SAML2Artifact*>(artifact));
    if (!artifact2.get()) {
        throw BindingException("Artifact binding requires SAML 2.0 artifact.");
        delete artifact;
    }
    
    log.debug("attempting to determine source of artifact...");
    MetadataProvider::Criteria mc(artifact, policy.getRole(), samlconstants::SAML20P_NS);
    pair<const EntityDescriptor*,const RoleDescriptor*> provider=policy.getMetadataProvider()->getEntityDescriptor(mc);
    if (!provider.first) {
        log.error(
            "metadata lookup failed, unable to determine issuer of artifact (0x%s)",
            SAMLArtifact::toHex(artifact->getBytes()).c_str()
            );
        throw BindingException("Metadata lookup failed, unable to determine artifact issuer.");
    }
    
    if (log.isDebugEnabled()) {
        auto_ptr_char issuer(provider.first->getEntityID());
        log.debug("lookup succeeded, artifact issued by (%s)", issuer.get());
    }

    if (!provider.second || !dynamic_cast<const SSODescriptorType*>(provider.second)) {
        log.error("unable to find compatible SAML 2.0 role (%s) in metadata", policy.getRole()->toString().c_str());
        throw BindingException("Unable to find compatible metadata role for artifact issuer.");
    }
    // Set issuer into policy.
    policy.setIssuer(provider.first->getEntityID());
    policy.setIssuerMetadata(provider.second);
    
    log.debug("calling ArtifactResolver...");
    auto_ptr<ArtifactResponse> response(
        m_artifactResolver->resolve(*(artifact2.get()), dynamic_cast<const SSODescriptorType&>(*provider.second), policy)
        );
    
    // The policy should be enforced against the ArtifactResponse by the resolve step.
    // Reset only the message state.
    policy.reset(true);

    // Now extract details from the payload and check that message.
    XMLObject* payload = response->getPayload();
    extractMessageDetails(*payload, genericRequest, samlconstants::SAML20P_NS, policy);
    policy.evaluate(*payload, &genericRequest);

    // Return the payload only.
    response.release();
    payload->detach(); 
    return payload;
}
