/*
 *  Copyright 2001-2010 Internet2
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
 * MessageEncoder.cpp
 * 
 * Interface to SAML protocol binding message encoders. 
 */

#include "internal.h"
#include "binding/MessageEncoder.h"
#include "util/SAMLConstants.h"

#include <xmltooling/signature/KeyInfo.h>
#include <xmltooling/signature/Signature.h>

using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml1p {
        SAML_DLLLOCAL PluginManager< MessageEncoder,string,pair<const DOMElement*,const XMLCh*> >::Factory SAML1ArtifactEncoderFactory;
        SAML_DLLLOCAL PluginManager< MessageEncoder,string,pair<const DOMElement*,const XMLCh*> >::Factory SAML1POSTEncoderFactory;
        SAML_DLLLOCAL PluginManager< MessageEncoder,string,pair<const DOMElement*,const XMLCh*> >::Factory SAML1SOAPEncoderFactory;
    }; 

    namespace saml2p {
        SAML_DLLLOCAL PluginManager< MessageEncoder,string,pair<const DOMElement*,const XMLCh*> >::Factory SAML2ArtifactEncoderFactory;
        SAML_DLLLOCAL PluginManager< MessageEncoder,string,pair<const DOMElement*,const XMLCh*> >::Factory SAML2POSTEncoderFactory;
        SAML_DLLLOCAL PluginManager< MessageEncoder,string,pair<const DOMElement*,const XMLCh*> >::Factory SAML2POSTSimpleSignEncoderFactory;
        SAML_DLLLOCAL PluginManager< MessageEncoder,string,pair<const DOMElement*,const XMLCh*> >::Factory SAML2RedirectEncoderFactory;
        SAML_DLLLOCAL PluginManager< MessageEncoder,string,pair<const DOMElement*,const XMLCh*> >::Factory SAML2SOAPEncoderFactory;
        SAML_DLLLOCAL PluginManager< MessageEncoder,string,pair<const DOMElement*,const XMLCh*> >::Factory SAML2ECPEncoderFactory;
    };
};

void SAML_API opensaml::registerMessageEncoders()
{
    SAMLConfig& conf=SAMLConfig::getConfig();
    conf.MessageEncoderManager.registerFactory(samlconstants::SAML1_PROFILE_BROWSER_ARTIFACT, saml1p::SAML1ArtifactEncoderFactory);
    conf.MessageEncoderManager.registerFactory(samlconstants::SAML1_PROFILE_BROWSER_POST, saml1p::SAML1POSTEncoderFactory);
    conf.MessageEncoderManager.registerFactory(samlconstants::SAML1_BINDING_SOAP, saml1p::SAML1SOAPEncoderFactory);
    conf.MessageEncoderManager.registerFactory(samlconstants::SAML20_BINDING_HTTP_ARTIFACT, saml2p::SAML2ArtifactEncoderFactory);
    conf.MessageEncoderManager.registerFactory(samlconstants::SAML20_BINDING_HTTP_POST, saml2p::SAML2POSTEncoderFactory);
    conf.MessageEncoderManager.registerFactory(samlconstants::SAML20_BINDING_HTTP_POST_SIMPLESIGN, saml2p::SAML2POSTSimpleSignEncoderFactory);
    conf.MessageEncoderManager.registerFactory(samlconstants::SAML20_BINDING_HTTP_REDIRECT, saml2p::SAML2RedirectEncoderFactory);
    conf.MessageEncoderManager.registerFactory(samlconstants::SAML20_BINDING_SOAP, saml2p::SAML2SOAPEncoderFactory);
    conf.MessageEncoderManager.registerFactory(samlconstants::SAML20_BINDING_PAOS, saml2p::SAML2ECPEncoderFactory);
}

MessageEncoder::MessageEncoder()
{
}

MessageEncoder::~MessageEncoder()
{
}

const XMLCh* MessageEncoder::getProtocolFamily() const
{
    return nullptr;
}

const char* MessageEncoder::getShortName() const
{
    return nullptr;
}

bool MessageEncoder::isCompact() const
{
    return false;
}

bool MessageEncoder::isUserAgentPresent() const
{
    return true;
}

MessageEncoder::ArtifactGenerator::ArtifactGenerator()
{
}

MessageEncoder::ArtifactGenerator::~ArtifactGenerator()
{
}
