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
 * @file saml/saml1/binding/SAML1SOAPClient.h
 * 
 * Client class for SAML 1.x SOAP binding.
 */

#ifndef __saml1_soap11client_h__
#define __saml1_soap11client_h__

#include <saml/binding/SOAPClient.h>

namespace opensaml {

    namespace saml1p {
        
        class SAML_API Request;
        class SAML_API Response;
        class SAML_API Status;

        /**
         *  Client class for SAML 1.x SOAP binding.
         */
        class SAML_API SAML1SOAPClient
        {
        public:
            /**
             * Constructor
             * 
             * @param soaper            reference to SOAPClient object to use for call
             * @param fatalSAMLErrors   true iff a non-successful SAML Status code should be fatal
             */
            SAML1SOAPClient(SOAPClient& soaper, bool fatalSAMLErrors=true) : m_soaper(soaper), m_fatal(fatalSAMLErrors), m_correlate(NULL) {
            }
            
            virtual ~SAML1SOAPClient() {
                xercesc::XMLString::release(&m_correlate);
            }
    
            /**
             * Specialized method for sending SAML 1.x requests. The SOAP layer will be
             * constructed automatically.
             * 
             * <p>The request will be freed by the client object regardless of the outcome.
             * 
             * @param request   SAML request to send
             * @param peer      peer to send message to, expressed in metadata criteria terms
             * @param endpoint  URL of endpoint to recieve message
             */
            virtual void sendSAML(Request* request, saml2md::MetadataCredentialCriteria& peer, const char* endpoint);
            
            /**
             * Specialized method for receiving SAML 1.x responses. The SOAP layer will be
             * evaluated automatically, and the attached policy will be applied to the Response.
             * 
             * <p>The caller is responsible for freeing the Response.
             * 
             * @return SAML 1.x Response, after SecurityPolicy has been applied
             */
            virtual Response* receiveSAML();

        protected:
            /**
             * Handling of SAML errors.
             * 
             * @param status SAML Status received by client
             * @return true iff the error should be treated as a fatal error
             */
            virtual bool handleError(const Status& status);

            /** SOAP client object. */
            SOAPClient& m_soaper;

            /** Flag controlling default error handler. */
            bool m_fatal;

        private:
            XMLCh* m_correlate;
        };
        
    };
};

#endif /* __saml1_soap11client_h__ */
