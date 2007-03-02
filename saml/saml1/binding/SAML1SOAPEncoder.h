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
 * @file saml/saml1/binding/SAML1SOAPEncoder.h
 * 
 * SAML 1.x SOAP binding message encoder
 */

#include <saml/binding/MessageEncoder.h>


namespace opensaml {
    namespace saml1p {

        /**
         * SAML 1.x POST binding message encoder
         */
        class SAML_API SAML1SOAPEncoder : public MessageEncoder
        {
        public:
            SAML1SOAPEncoder(const DOMElement* e);
            virtual ~SAML1SOAPEncoder() {}
            
            long encode(
                GenericResponse& genericResponse,
                xmltooling::XMLObject* xmlObject,
                const char* destination,
                const char* recipientID=NULL,
                const char* relayState=NULL,
                const xmltooling::CredentialResolver* credResolver=NULL,
                const XMLCh* sigAlgorithm=NULL
                ) const;
        };

    };
};
