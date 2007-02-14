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
 * @file saml/binding/SOAPClient.h
 * 
 * Specialized SOAPClient for SAML SOAP bindings.
 */

#ifndef __saml_soap11client_h__
#define __saml_soap11client_h__

#include <saml/binding/SecurityPolicy.h>
#include <xmltooling/soap/SOAPClient.h>

namespace opensaml {

    /**
     * Specialized SOAPClient for SAML SOAP bindings.
     */
    class SAML_API SOAPClient : public soap11::SOAPClient
    {
    public:
        /**
         * Creates a SOAP client instance with a particular SecurityPolicy.
         * 
         * @param policy        reference to SecurityPolicy to apply
         * @param validating    controls schema validation
         */
        SOAPClient(SecurityPolicy& policy, bool validating=false)
            : soap11::SOAPClient(validating), m_policy(policy), m_force(true), m_peer(NULL) {}
        
        virtual ~SOAPClient() {}

        /**
         * Controls whether to force transport/peer authentication via an X509TrustEngine.
         * 
         * <p>Only makes sense if an X509TrustEngine is supplied by the SecurityPolicy. 
         * 
         * @param force  true iff the client should refuse to communicate without this protection
         */
        void forceTransportAuthentication(bool force=true) {
            m_force = force;
        }
        
        /**
         * Override prepares the SecurityPolicy by clearing Issuer identity, in case the policy
         * is reused.
         * 
         * @param env       SOAP envelope to send
         * @param peer      peer to send message to, expressed in TrustEngine terms
         * @param endpoint  URL of endpoint to recieve message
         */
        void send(const soap11::Envelope& env, const xmltooling::KeyInfoSource& peer, const char* endpoint);
        
        /**
         * Override applies SecurityPolicy to envelope before returning it.
         * 
         * @return response envelope after SecurityPolicy has been applied
         */
        soap11::Envelope* receive();
        
        void reset();

        /**
         * Returns the SecurityPolicy supplied to the client.
         *
         * @return  the associated SecurityPolicy
         */
        SecurityPolicy& getPolicy() const {
            return m_policy;
        }

    protected:
        /**
         * Override prepares transport by assigning an X509TrustEngine to it, if one is
         * attached to the policy.
         * 
         * @param transport reference to transport layer
         */
        void prepareTransport(const xmltooling::SOAPTransport& transport);
        
        /** Reference to security policy to apply. */
        SecurityPolicy& m_policy;
        
        /** Flag controlling whether transport/peer authn is mandatory. */
        bool m_force;
    
        /** Metadata-based peer identity. */        
        const saml2md::RoleDescriptor* m_peer;
    };

};

#endif /* __saml_soap11client_h__ */
