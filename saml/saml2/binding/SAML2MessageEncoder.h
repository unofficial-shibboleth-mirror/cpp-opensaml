/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * @file saml/saml2/binding/SAML2MessageDecoder.h
 * 
 * Base class for SAML 2.0 MessageDecoders.
 */

#ifndef __saml2_msgencoder_h__
#define __saml2_msgencoder_h__

#include <saml/binding/MessageEncoder.h>
#include <saml/saml2/core/Protocols.h>

namespace xmltooling {
    class HTTPResponse;
}

namespace opensaml {
    namespace saml2p {
        
        /**
         *  Base class for SAML 2.0 MessageEncoders.
         */
        class SAML_API SAML2MessageEncoder : public MessageEncoder
        {
        protected:
            SAML2MessageEncoder();
            virtual ~SAML2MessageEncoder();

            /**
             * If the message is a request and relay state is provided, the request ID is preserved in a correlation cookie.
             *
             * @param response HTTP response
             * @param message the SAML message
             * @param relayState the RelayState token
             */
            void preserveCorrelationID(
                xmltooling::HTTPResponse& response, const RequestAbstractType& message, const char* relayState
                ) const;

        public:
            const XMLCh* getProtocolFamily() const;
        };
    };
};

#endif /* __saml2_msgencoder_h__ */
