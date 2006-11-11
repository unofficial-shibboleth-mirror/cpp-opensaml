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
 * MessageDecoder.cpp
 * 
 * Interface to SAML protocol binding message decoders. 
 */

#include "internal.h"
#include "binding/MessageDecoder.h"
#include "util/SAMLConstants.h"

using namespace opensaml;
using namespace xmltooling;

namespace opensaml {
    namespace saml1p {
        SAML_DLLLOCAL PluginManager<MessageDecoder,const DOMElement*>::Factory SAML1ArtifactDecoderFactory;
        SAML_DLLLOCAL PluginManager<MessageDecoder,const DOMElement*>::Factory SAML1POSTDecoderFactory;
        SAML_DLLLOCAL PluginManager<MessageDecoder,const DOMElement*>::Factory SAML1SOAPDecoderFactory;
    }; 

    namespace saml2p {
        SAML_DLLLOCAL PluginManager<MessageDecoder,const DOMElement*>::Factory SAML2ArtifactDecoderFactory;
        SAML_DLLLOCAL PluginManager<MessageDecoder,const DOMElement*>::Factory SAML2POSTDecoderFactory;
        SAML_DLLLOCAL PluginManager<MessageDecoder,const DOMElement*>::Factory SAML2RedirectDecoderFactory;
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
}
