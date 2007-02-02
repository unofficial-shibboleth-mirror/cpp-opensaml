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
 * @file saml/saml1/binding/SAML1SOAPDecoder.h
 * 
 * SAML 1.x SOAP binding message decoder
 */

#include <saml/binding/MessageDecoder.h>
#include <saml/saml1/core/Protocols.h>


namespace opensaml {
    namespace saml1p {

        /**
         * SAML 1.x SOAP binding message decoder
         */
        class SAML_API SAML1SOAPDecoder : public MessageDecoder
        {
        public:
            SAML1SOAPDecoder(const DOMElement* e);
            virtual ~SAML1SOAPDecoder() {}
            
            xmltooling::XMLObject* decode(
                std::string& relayState,
                const GenericRequest& genericRequest,
                SecurityPolicy& policy
                ) const;
        };                

    };
};
