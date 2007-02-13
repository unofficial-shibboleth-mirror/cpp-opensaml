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
 * @file saml/saml2/binding/SAML2SOAPClient.h
 * 
 * Specialized SOAPClient for SAML 2.0 SOAP binding.
 */

#ifndef __saml2_soap11client_h__
#define __saml2_soap11client_h__

#include <saml/binding/SOAPClient.h>

namespace opensaml {
    namespace saml2p {
        
        class SAML_API RequestAbstractType;
        class SAML_API StatusResponseType;
        class SAML_API Status;

        /**
         * Specialized SOAPClient for SAML 2.0 SOAP binding.
         */
        class SAML_API SAML2SOAPClient : public opensaml::SOAPClient
        {
        public:
            /**
             * Creates a SOAP client instance with a particular SecurityPolicy.
             * 
             * @param policy        reference to SecurityPolicy to apply
             * @param validating    controls schema validation
             */
            SAML2SOAPClient(SecurityPolicy& policy, bool validating=false) : opensaml::SOAPClient(policy, validating) {}
            
            virtual ~SAML2SOAPClient() {}
    
            /**
             * Specialized method for sending SAML 2.0 requests. The SOAP layer will be
             * constructed automatically.
             * 
             * <p>The request will be freed by the client object regardless of the outcome.
             * 
             * @param request   SAML request to send
             * @param peer      peer to send message to, expressed in metadata terms
             * @param endpoint  URL of endpoint to recieve message
             */
            virtual void sendSAML(RequestAbstractType* request, const saml2md::RoleDescriptor& peer, const char* endpoint);
            
            /**
             * Specialized method for receiving SAML 2.0 responses. The SOAP layer will be
             * evaluated automatically, and the attached policy will be applied to the Response.
             * 
             * <p>The caller is responsible for freeing the response.
             * 
             * @return SAML 2.0 response, after SecurityPolicy has been applied
             */
            virtual StatusResponseType* receiveSAML();

        protected:
            /**
             * Handling of SAML errors.
             * 
             * @param status SAML Status received by client
             * @return true iff the error should be treated as a fatal error
             */
            virtual bool handleError(const Status& status);
        };
        
    };
};

#endif /* __saml2_soap11client_h__ */
