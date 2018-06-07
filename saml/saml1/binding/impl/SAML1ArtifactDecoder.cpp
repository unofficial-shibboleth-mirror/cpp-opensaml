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
 * SAML1ArtifactDecoder.cpp
 *
 * SAML 1.x Artifact binding/profile message decoder
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/SAMLArtifact.h"
#include "binding/SecurityPolicy.h"
#include "saml1/binding/SAML1MessageDecoder.h"
#include "saml1/core/Protocols.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"

#include <boost/ptr_container/ptr_vector.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/io/HTTPRequest.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReplayCache.h>

using namespace opensaml::saml2md;
using namespace opensaml::saml1p;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;
using boost::ptr_vector;

namespace opensaml {
    namespace saml1p {
        class SAML_DLLLOCAL SAML1ArtifactDecoder : public SAML1MessageDecoder
        {
        public:
            SAML1ArtifactDecoder() {}
            virtual ~SAML1ArtifactDecoder() {}

            xmltooling::XMLObject* decode(
                std::string& relayState,
                const GenericRequest& genericRequest,
                SecurityPolicy& policy
                ) const;
        };

        MessageDecoder* SAML_DLLLOCAL SAML1ArtifactDecoderFactory(const DOMElement* const&, bool)
        {
            return new SAML1ArtifactDecoder();
        }
    };
};

XMLObject* SAML1ArtifactDecoder::decode(
    string& relayState,
    const GenericRequest& genericRequest,
    SecurityPolicy& policy
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("decode");
#endif
    Category& log = Category::getInstance(SAML_LOGCAT ".MessageDecoder.SAML1Artifact");

    log.debug("validating input");
    const HTTPRequest* httpRequest=dynamic_cast<const HTTPRequest*>(&genericRequest);
    if (!httpRequest)
        throw BindingException("Unable to cast request object to HTTPRequest type.");
    vector<const char*> SAMLart;
    const char* TARGET = httpRequest->getParameter("TARGET");
    if (httpRequest->getParameters("SAMLart", SAMLart)==0 || !TARGET)
        throw BindingException("Request missing SAMLart or TARGET query string parameters.");
    relayState = TARGET;

    if (!m_artifactResolver || !policy.getMetadataProvider() || !policy.getRole())
        throw BindingException("Artifact profile requires ArtifactResolver and MetadataProvider implementations be supplied.");

    // Import the artifacts.
    vector<SAMLArtifact*> artifactptrs; // needed for compatibility with non-Boost API in ArtifactResolver
    ptr_vector<SAMLArtifact> artifacts;
    for (vector<const char*>::const_iterator raw=SAMLart.begin(); raw!=SAMLart.end(); ++raw) {
        try {
            log.debug("processing encoded artifact (%s)", *raw);

            // Check replay.
            ReplayCache* replayCache = XMLToolingConfig::getConfig().getReplayCache();
            if (replayCache) {
                if (!replayCache->check("SAML1Artifact", *raw, time(nullptr) + (2*XMLToolingConfig::getConfig().clock_skew_secs))) {
                    log.error("replay detected of artifact (%s)", *raw);
                    throw BindingException("Rejecting replayed artifact ($1).", params(1,*raw));
                }
            }
            else
                log.warn("replay cache was not provided, this is a serious security risk!");

            artifacts.push_back(SAMLArtifact::parse(*raw));
            artifactptrs.push_back(&(artifacts.back()));
        }
        catch (ArtifactException&) {
            log.error("error parsing artifact (%s)", *raw);
            throw;
        }
    }

    log.debug("attempting to determine source of artifact(s)...");
    MetadataProvider::Criteria& mc = policy.getMetadataProviderCriteria();
    mc.artifact = &(artifacts.front());
    mc.role = policy.getRole();
    mc.protocol = samlconstants::SAML11_PROTOCOL_ENUM;
    mc.protocol2 = samlconstants::SAML10_PROTOCOL_ENUM;
    pair<const EntityDescriptor*,const RoleDescriptor*> provider=policy.getMetadataProvider()->getEntityDescriptor(mc);
    if (!provider.first) {
        log.error(
            "metadata lookup failed, unable to determine issuer of artifact (0x%s)",
            SAMLArtifact::toHex(artifacts.front().getBytes()).c_str()
            );
        throw BindingException("Metadata lookup failed, unable to determine artifact issuer");
    }

    if (log.isDebugEnabled()) {
        auto_ptr_char issuer(provider.first->getEntityID());
        log.debug("artifact issued by (%s)", issuer.get());
    }

    if (!provider.second || !dynamic_cast<const IDPSSODescriptor*>(provider.second)) {
        log.error("unable to find compatible SAML 1.x role (%s) in metadata", policy.getRole()->toString().c_str());
        throw BindingException("Unable to find compatible metadata role for artifact issuer.");
    }
    // Set Issuer for the policy.
    policy.setIssuer(provider.first->getEntityID());
    policy.setIssuerMetadata(provider.second);

    log.debug("calling ArtifactResolver...");
    auto_ptr<Response> response(
        m_artifactResolver->resolve(artifactptrs, dynamic_cast<const IDPSSODescriptor&>(*provider.second), policy)
        );

    // The policy should be enforced against the Response by the resolve step.

    return response.release();
}
