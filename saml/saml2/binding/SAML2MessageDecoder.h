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
 * @file saml/saml2/binding/SAML2MessageDecoder.h
 * 
 * Base class for SAML 2.0 MessageDecoders.
 */

#ifndef __saml2_msgdecoder_h__
#define __saml2_msgdecoder_h__

#include <saml/binding/MessageDecoder.h>

namespace opensaml {
    namespace saml2p {
        
        /**
         *  Base class for SAML 2.0 MessageDecoders.
         */
        class SAML_API SAML2MessageDecoder : public MessageDecoder
        {
        protected:
            SAML2MessageDecoder();
            virtual ~SAML2MessageDecoder();

        public:
            const XMLCh* getProtocolFamily() const;
            void extractMessageDetails (
                const xmltooling::XMLObject& message,
                const xmltooling::GenericRequest& genericRequest,
                const XMLCh* protocol,
                SecurityPolicy& policy
                ) const;
        };
    };
};

#endif /* __saml2_msgdecoder_h__ */
