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
 * @file saml/saml1/binding/SAML1ArtifactEncoder.h
 * 
 * SAML 1.x Artifact binding/profile message encoder
 */

#include <saml/binding/MessageEncoder.h>


namespace opensaml {
    namespace saml1p {

        /**
         * SAML 1.x Artifact binding/profile message encoder
         */
        class SAML_API SAML1ArtifactEncoder : public MessageEncoder
        {
        public:
            SAML1ArtifactEncoder(const DOMElement* e);
            virtual ~SAML1ArtifactEncoder();
            
            void encode(
                std::map<std::string,std::string>& outputFields,
                xmltooling::XMLObject* xmlObject,
                const char* recipientID=NULL,
                const char* relayState=NULL,
                const xmlsignature::CredentialResolver* credResolver=NULL,
                const XMLCh* sigAlgorithm=NULL
                ) const;
        };                

    };
};