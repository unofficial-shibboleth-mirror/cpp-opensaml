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
 * SAML2ArtifactDecoder.cpp
 * 
 * SAML 2.0 Artifact binding message decoder
 */

#include "internal.h"
#include "exceptions.h"
#include "saml/binding/SAMLArtifact.h"
#include "saml2/core/Protocols.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"
#include "saml2/binding/SAML2Artifact.h"
#include "saml2/binding/SAML2ArtifactDecoder.h"
#include "security/X509TrustEngine.h"

#include <log4cpp/Category.hh>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReplayCache.h>

using namespace opensaml::saml2md;
using namespace opensaml::saml2p;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    namespace saml2p {              
        MessageDecoder* SAML_DLLLOCAL SAML2ArtifactDecoderFactory(const DOMElement* const & e)
        {
            return new SAML2ArtifactDecoder(e);
        }
    };
};

SAML2ArtifactDecoder::SAML2ArtifactDecoder(const DOMElement* e) {}

SAML2ArtifactDecoder::~SAML2ArtifactDecoder() {}

XMLObject* SAML2ArtifactDecoder::decode(
    string& relayState,
    const RoleDescriptor*& issuer,
    const XMLCh*& securityMech,
    const HTTPRequest& httpRequest,
    const MetadataProvider* metadataProvider,
    const QName* role,
    const opensaml::TrustEngine* trustEngine
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("decode");
#endif
    Category& log = Category::getInstance(SAML_LOGCAT".MessageDecoder.SAML2Artifact");

    log.debug("validating input");
    const char* SAMLart = httpRequest.getParameter("SAMLart");
    if (!SAMLart)
        return NULL;
    const char* state = httpRequest.getParameter("RelayState");
    if (state)
        relayState = state;

    if (!m_artifactResolver || !metadataProvider)
        throw BindingException("Artifact binding requires ArtifactResolver and MetadataProvider implementations be supplied.");

    // Import the artifact.
    SAMLArtifact* artifact=NULL;
    ReplayCache* replayCache = XMLToolingConfig::getConfig().getReplayCache();
    try {
        log.debug("processing encoded artifact (%s)", SAMLart);
        
        // Check replay.
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
    
    issuer = NULL;
    securityMech = NULL;
    log.debug("attempting to determine source of artifact...");
    const EntityDescriptor* provider=metadataProvider->getEntityDescriptor(artifact);
    if (!provider) {
        log.error(
            "metadata lookup failed, unable to determine issuer of artifact (0x%s)",
            SAMLArtifact::toHex(artifact->getBytes()).c_str()
            );
        throw BindingException("Metadata lookup failed, unable to determine artifact issuer.");
    }
    
    if (log.isDebugEnabled()) {
        auto_ptr_char issuer(provider->getEntityID());
        log.debug("lookup succeeded, artifact issued by (%s)", issuer.get());
    }
    
    log.debug("attempting to find artifact issuing role...");
    issuer=provider->getRoleDescriptor(*role, samlconstants::SAML20P_NS);
    if (!issuer || !dynamic_cast<const SSODescriptorType*>(issuer)) {
        log.error("unable to find compatible SAML role (%s) in metadata", role->toString().c_str());
        BindingException ex("Unable to find compatible metadata role for artifact issuer.");
        annotateException(&ex,provider); // throws it
    }
    
    try {
        auto_ptr<ArtifactResponse> response(
            m_artifactResolver->resolve(
                securityMech,
                *(artifact2.get()),
                dynamic_cast<const SSODescriptorType&>(*issuer),
                dynamic_cast<const X509TrustEngine*>(trustEngine)
                )
            );
        
        // Check Issuer of outer message.
        if (!issuerMatches(response->getIssuer(), provider->getEntityID())) {
            log.error("issuer of ArtifactResponse did not match source of artifact");
            throw BindingException("Issuer of ArtifactResponse did not match source of artifact.");
        }

        // Extract payload and check that Issuer.
        XMLObject* payload = response->getPayload();
        RequestAbstractType* req = NULL;
        StatusResponseType* res = dynamic_cast<StatusResponseType*>(payload);
        if (!res)
            req = dynamic_cast<RequestAbstractType*>(payload);
        if (!res && !req)
            throw BindingException("ArtifactResponse payload was not a recognized SAML 2.0 protocol message.");
            
        if (!issuerMatches(res ? res->getIssuer() : req->getIssuer(), provider->getEntityID())) {
            log.error("issuer of ArtifactResponse payload did not match source of artifact");
            throw BindingException("Issuer of ArtifactResponse payload did not match source of artifact.");
        }

        // Check payload freshness.
        time_t now = time(NULL);
        if ((res ? res->getIssueInstant() : req->getIssueInstant())->getEpoch() < now-(2*XMLToolingConfig::getConfig().clock_skew_secs))
            throw BindingException("Detected expired ArtifactResponse payload.");

        // Check replay.
        if (replayCache) {
            auto_ptr_char mid(res ? res->getID() : req->getID());
            if (!replayCache->check("SAML2ArtifactPayload", mid.get(), now + (2*XMLToolingConfig::getConfig().clock_skew_secs))) {
                log.error("replay detected of ArtifactResponse payload message ID (%s)", mid.get());
                throw BindingException("Rejecting replayed ArtifactResponse payload ($1).", params(1,mid.get()));
            }
        }
        
        // Check signatures.
        if (trustEngine) {
            if (response->getSignature()) {
                if (!trustEngine->validate(*(response->getSignature()), *issuer, metadataProvider->getKeyResolver())) {
                    log.error("unable to verify signature on ArtifactResponse message with supplied trust engine");
                    throw BindingException("Message signature failed verification.");
                }
                else if (!securityMech) {
                    securityMech = samlconstants::SAML20P_NS;
                }
            }
            Signature* sig = (res ? res->getSignature() : req->getSignature());
            if (sig) {
                if (!trustEngine->validate(*sig, *issuer, metadataProvider->getKeyResolver())) {
                    log.error("unable to verify signature on ArtifactResponse payload with supplied trust engine");
                    throw BindingException("Message signature failed verification.");
                }
                else if (!securityMech) {
                    securityMech = samlconstants::SAML20P_NS;
                }
            }
        }
        
        if (!securityMech) {
            log.warn("unable to authenticate ArtifactResponse message or payload, leaving untrusted");
        }
        
        // Return the payload only.
        response.release();
        payload->detach(); 
        return payload;
    }
    catch (XMLToolingException& ex) {
        annotateException(&ex,issuer,false);
        throw;
    }
}

bool SAML2ArtifactDecoder::issuerMatches(const Issuer* messageIssuer, const XMLCh* expectedIssuer) const
{
    if (messageIssuer && messageIssuer->getName()) {
        if (messageIssuer->getFormat() && !XMLString::equals(messageIssuer->getFormat(), NameIDType::ENTITY))
            return false;
        else if (!XMLString::equals(expectedIssuer, messageIssuer->getName()))
            return false;
    }
    return true;
}

