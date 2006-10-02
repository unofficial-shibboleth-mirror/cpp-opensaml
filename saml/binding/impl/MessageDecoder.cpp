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

using namespace opensaml;
using namespace xmltooling;

namespace opensaml {
    namespace saml1p {
        SAML_DLLLOCAL PluginManager<MessageDecoder,const DOMElement*>::Factory SAML1ArtifactDecoderFactory;
        SAML_DLLLOCAL PluginManager<MessageDecoder,const DOMElement*>::Factory SAML1POSTDecoderFactory;
    }; 

    namespace saml2p {
        SAML_DLLLOCAL PluginManager<MessageDecoder,const DOMElement*>::Factory SAML2ArtifactDecoderFactory;
        SAML_DLLLOCAL PluginManager<MessageDecoder,const DOMElement*>::Factory SAML2POSTDecoderFactory;
    };
};

void SAML_API opensaml::registerMessageDecoders()
{
    SAMLConfig& conf=SAMLConfig::getConfig();
    //conf.MessageDecoderManager.registerFactory(SAML1_ARTIFACT_DECODER, saml1p::SAML1ArtifactDecoderFactory);
    conf.MessageDecoderManager.registerFactory(SAML1_POST_DECODER, saml1p::SAML1POSTDecoderFactory);
    //conf.MessageDecoderManager.registerFactory(SAML2_ARTIFACT_DECODER, saml2p::SAML2ArtifactDecoderFactory);
    //conf.MessageDecoderManager.registerFactory(SAML2_POST_DECODER, saml2p::SAML2POSTDecoderFactory);
}
