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
 * @file saml/saml2/binding/SAML2POSTDecoder.h
 * 
 * SAML 2.0 HTTP POST binding message decoder
 */

#include <saml/binding/MessageDecoder.h>

namespace opensaml {
    namespace saml2p {

        /**
         * SAML 2.0 HTTP POST binding message decoder
         */
        class SAML_API SAML2POSTDecoder : public MessageDecoder
        {
        public:
            SAML2POSTDecoder(const DOMElement* e);
            virtual ~SAML2POSTDecoder();
            
            xmltooling::XMLObject* decode(
                std::string& relayState,
                const saml2md::RoleDescriptor*& issuer,
                bool& issuerTrusted,
                const HTTPRequest& httpRequest,
                const saml2md::MetadataProvider* metadataProvider=NULL,
                const xmltooling::QName* role=NULL,
                const X509TrustEngine* trustEngine=NULL
                ) const;
        };                

    };
};