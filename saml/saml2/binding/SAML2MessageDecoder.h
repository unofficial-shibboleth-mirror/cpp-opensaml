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

#ifndef __saml2_msgdecoder_h__
#define __saml2_msgdecoder_h__

#include <saml/binding/MessageDecoder.h>

namespace xmltooling {
    class HTTPRequest;
    class HTTPResponse;
}

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

            /**
            * If relay state is provided, the previous request ID is extracted from a correlation cookie
            * and supplied to the policy.
            *
            * @param request HTTP request
            * @param response optional HTTP response
            * @param relayState the RelayState token
            * @param policy the SecurityPolicy to attach the ID to
            */
            void extractCorrelationID(
                const xmltooling::HTTPRequest& request,
                xmltooling::HTTPResponse* response,
                const std::string& relayState,
                SecurityPolicy& policy
                ) const;

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
