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
 * SAML1ArtifactDecoder.cpp
 * 
 * SAML 1.x Artifact binding/profile message decoder
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/HTTPRequest.h"
#include "saml/binding/SAMLArtifact.h"
#include "saml1/binding/SAML1ArtifactDecoder.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"

#include <log4cpp/Category.hh>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReplayCache.h>

using namespace opensaml::saml2md;
using namespace opensaml::saml1p;
using namespace opensaml;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    namespace saml1p {              
        MessageDecoder* SAML_DLLLOCAL SAML1ArtifactDecoderFactory(const DOMElement* const & e)
        {
            return new SAML1ArtifactDecoder(e);
        }
    };
};

SAML1ArtifactDecoder::SAML1ArtifactDecoder(const DOMElement* e) {}

XMLObject* SAML1ArtifactDecoder::decode(
    string& relayState,
    const GenericRequest& genericRequest,
    SecurityPolicy& policy
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("decode");
#endif
    Category& log = Category::getInstance(SAML_LOGCAT".MessageDecoder.SAML1Artifact");

    log.debug("validating input");
    const HTTPRequest* httpRequest=dynamic_cast<const HTTPRequest*>(&genericRequest);
    if (!httpRequest) {
        log.error("unable to cast request to HTTPRequest type");
        return NULL;
    }
    if (strcmp(httpRequest->getMethod(),"GET"))
        return NULL;
    vector<const char*> SAMLart;
    const char* TARGET = httpRequest->getParameter("TARGET");
    if (httpRequest->getParameters("SAMLart", SAMLart)==0 || !TARGET)
        return NULL;
    relayState = TARGET;

    if (!m_artifactResolver || !policy.getMetadataProvider() || !policy.getRole())
        throw BindingException("Artifact profile requires ArtifactResolver and MetadataProvider implementations be supplied.");

    // Import the artifacts.
    vector<SAMLArtifact*> artifacts;
    for (vector<const char*>::const_iterator raw=SAMLart.begin(); raw!=SAMLart.end(); ++raw) {
        try {
            log.debug("processing encoded artifact (%s)", *raw);
            
            // Check replay.
            ReplayCache* replayCache = XMLToolingConfig::getConfig().getReplayCache();
            if (replayCache) {
                if (!replayCache->check("SAML1Artifact", *raw, time(NULL) + (2*XMLToolingConfig::getConfig().clock_skew_secs))) {
                    log.error("replay detected of artifact (%s)", *raw);
                    throw BindingException("Rejecting replayed artifact ($1).", params(1,*raw));
                }
            }
            else
                log.warn("replay cache was not provided, this is a serious security risk!");

            artifacts.push_back(SAMLArtifact::parse(*raw));
        }
        catch (ArtifactException&) {
            log.error("error parsing artifact (%s)", *raw);
            for_each(artifacts.begin(), artifacts.end(), xmltooling::cleanup<SAMLArtifact>());
            throw;
        }
        catch (XMLToolingException&) {
            for_each(artifacts.begin(), artifacts.end(), xmltooling::cleanup<SAMLArtifact>());
            throw;
        }
    }
    
    log.debug("attempting to determine source of artifact(s)...");
    const EntityDescriptor* provider=policy.getMetadataProvider()->getEntityDescriptor(artifacts.front());
    if (!provider) {
        log.error(
            "metadata lookup failed, unable to determine issuer of artifact (0x%s)",
            SAMLArtifact::toHex(artifacts.front()->getBytes()).c_str()
            );
        for_each(artifacts.begin(), artifacts.end(), xmltooling::cleanup<SAMLArtifact>());
        throw BindingException("Metadata lookup failed, unable to determine artifact issuer");
    }
    
    if (log.isDebugEnabled()) {
        auto_ptr_char issuer(provider->getEntityID());
        log.debug("lookup succeeded, artifact issued by (%s)", issuer.get());
    }

    // Mock up an Issuer object for the policy.
    auto_ptr<saml2::Issuer> issuer(saml2::IssuerBuilder::buildIssuer());
    issuer->setName(provider->getEntityID());
    policy.setIssuer(issuer.get());
    issuer.release();   // owned by policy now
    
    log.debug("attempting to find artifact issuing role...");
    const RoleDescriptor* roledesc=provider->getRoleDescriptor(*(policy.getRole()), samlconstants::SAML11_PROTOCOL_ENUM);
    if (!roledesc)
        roledesc=provider->getRoleDescriptor(*(policy.getRole()), samlconstants::SAML10_PROTOCOL_ENUM);
    if (!roledesc || !dynamic_cast<const IDPSSODescriptor*>(roledesc)) {
        log.error("unable to find compatible SAML role (%s) in metadata", policy.getRole()->toString().c_str());
        for_each(artifacts.begin(), artifacts.end(), xmltooling::cleanup<SAMLArtifact>());
        throw BindingException("Unable to find compatible metadata role for artifact issuer.");
    }
    policy.setIssuerMetadata(roledesc);
    
    try {
        auto_ptr<Response> response(
            m_artifactResolver->resolve(artifacts, dynamic_cast<const IDPSSODescriptor&>(*roledesc), policy)
            );
        
        policy.evaluate(*(response.get()), &genericRequest);
        
        for_each(artifacts.begin(), artifacts.end(), xmltooling::cleanup<SAMLArtifact>());
        return response.release();
    }
    catch (XMLToolingException&) {
        for_each(artifacts.begin(), artifacts.end(), xmltooling::cleanup<SAMLArtifact>());
        throw;
    }
}
