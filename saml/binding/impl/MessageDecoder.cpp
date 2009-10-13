/*
 *  Copyright 2001-2009 Internet2
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
 * MessageDecoder.cpp
 *
 * Interface to SAML protocol binding message decoders.
 */

#include "internal.h"
#include "binding/MessageDecoder.h"
#include "saml2/metadata/EndpointManager.h"
#include "saml2/metadata/Metadata.h"
#include "util/SAMLConstants.h"

#include <xmltooling/impl/AnyElement.h>

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml1p {
        SAML_DLLLOCAL PluginManager< MessageDecoder,string,pair<const DOMElement*,const XMLCh*> >::Factory SAML1ArtifactDecoderFactory;
        SAML_DLLLOCAL PluginManager< MessageDecoder,string,pair<const DOMElement*,const XMLCh*> >::Factory SAML1POSTDecoderFactory;
        SAML_DLLLOCAL PluginManager< MessageDecoder,string,pair<const DOMElement*,const XMLCh*> >::Factory SAML1SOAPDecoderFactory;
    };

    namespace saml2p {
        SAML_DLLLOCAL PluginManager< MessageDecoder,string,pair<const DOMElement*,const XMLCh*> >::Factory SAML2ArtifactDecoderFactory;
        SAML_DLLLOCAL PluginManager< MessageDecoder,string,pair<const DOMElement*,const XMLCh*> >::Factory SAML2POSTDecoderFactory;
        SAML_DLLLOCAL PluginManager< MessageDecoder,string,pair<const DOMElement*,const XMLCh*> >::Factory SAML2RedirectDecoderFactory;
        SAML_DLLLOCAL PluginManager< MessageDecoder,string,pair<const DOMElement*,const XMLCh*> >::Factory SAML2SOAPDecoderFactory;
        SAML_DLLLOCAL PluginManager< MessageDecoder,string,pair<const DOMElement*,const XMLCh*> >::Factory SAML2ECPDecoderFactory;
    };
};

void SAML_API opensaml::registerMessageDecoders()
{
    SAMLConfig& conf=SAMLConfig::getConfig();
    conf.MessageDecoderManager.registerFactory(samlconstants::SAML1_PROFILE_BROWSER_ARTIFACT, saml1p::SAML1ArtifactDecoderFactory);
    conf.MessageDecoderManager.registerFactory(samlconstants::SAML1_PROFILE_BROWSER_POST, saml1p::SAML1POSTDecoderFactory);
    conf.MessageDecoderManager.registerFactory(samlconstants::SAML1_BINDING_SOAP, saml1p::SAML1SOAPDecoderFactory);
    conf.MessageDecoderManager.registerFactory(samlconstants::SAML20_BINDING_HTTP_ARTIFACT, saml2p::SAML2ArtifactDecoderFactory);
    conf.MessageDecoderManager.registerFactory(samlconstants::SAML20_BINDING_HTTP_POST, saml2p::SAML2POSTDecoderFactory);
    conf.MessageDecoderManager.registerFactory(samlconstants::SAML20_BINDING_HTTP_POST_SIMPLESIGN, saml2p::SAML2POSTDecoderFactory);
    conf.MessageDecoderManager.registerFactory(samlconstants::SAML20_BINDING_HTTP_REDIRECT, saml2p::SAML2RedirectDecoderFactory);
    conf.MessageDecoderManager.registerFactory(samlconstants::SAML20_BINDING_SOAP, saml2p::SAML2SOAPDecoderFactory);
    conf.MessageDecoderManager.registerFactory(samlconstants::SAML20_BINDING_PAOS, saml2p::SAML2ECPDecoderFactory);

    static const XMLCh RelayState[] = UNICODE_LITERAL_10(R,e,l,a,y,S,t,a,t,e);
    XMLObjectBuilder::registerBuilder(xmltooling::QName(samlconstants::SAML20ECP_NS, RelayState), new AnyElementBuilder());
}

MessageDecoder::MessageDecoder() : m_artifactResolver(NULL)
{
}

MessageDecoder::~MessageDecoder()
{
}

bool MessageDecoder::isUserAgentPresent() const
{
    return true;
}

void MessageDecoder::setArtifactResolver(const ArtifactResolver* artifactResolver)
{
    m_artifactResolver = artifactResolver;
}

MessageDecoder::ArtifactResolver::ArtifactResolver()
{
}

MessageDecoder::ArtifactResolver::~ArtifactResolver()
{
}

bool MessageDecoder::ArtifactResolver::isSupported(const SSODescriptorType& ssoDescriptor) const
{
    EndpointManager<ArtifactResolutionService> mgr(ssoDescriptor.getArtifactResolutionServices());
    if (ssoDescriptor.hasSupport(samlconstants::SAML20P_NS)) {
        auto_ptr_XMLCh binding(samlconstants::SAML20_BINDING_SOAP);
        return (mgr.getByBinding(binding.get()) != NULL);
    }
    else if (ssoDescriptor.hasSupport(samlconstants::SAML11_PROTOCOL_ENUM) || ssoDescriptor.hasSupport(samlconstants::SAML10_PROTOCOL_ENUM)) {
        auto_ptr_XMLCh binding(samlconstants::SAML1_BINDING_SOAP);
        return (mgr.getByBinding(binding.get()) != NULL);
    }

    return false;
}
