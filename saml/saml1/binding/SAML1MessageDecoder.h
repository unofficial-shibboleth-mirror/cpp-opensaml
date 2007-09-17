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
 * @file saml/saml1/binding/SAML1MessageDecoder.h
 * 
 * Base class for SAML 1.x MessageDecoders.
 */

#ifndef __saml1_msgdecoder_h__
#define __saml1_msgdecoder_h__

#include <saml/binding/MessageDecoder.h>

namespace opensaml {

    namespace saml1p {
        
        /**
         *  Base class for SAML 1.x MessageDecoders.
         */
        class SAML_API SAML1MessageDecoder : public MessageDecoder
        {
        protected:
            SAML1MessageDecoder() {}
            virtual ~SAML1MessageDecoder() {}

        public:
            void extractMessageDetails (
                const xmltooling::XMLObject& message,
                const xmltooling::GenericRequest& genericRequest,
                const XMLCh* protocol,
                SecurityPolicy& policy
                ) const;
        };
    };
};

#endif /* __saml1_msgdecoder_h__ */
