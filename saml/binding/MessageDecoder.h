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
 * @file saml/binding/MessageDecoder.h
 * 
 * Interface to SAML protocol binding message decoders. 
 */

#ifndef __saml_decoder_h__
#define __saml_decoder_h__

#include <saml/binding/GenericRequest.h>
#include <saml/binding/SecurityPolicy.h>
#include <xmltooling/XMLObject.h>

namespace opensaml {
    
    class SAML_API SAMLArtifact;
    namespace saml1p {
        class SAML_API Response;
    };
    namespace saml2p {
        class SAML_API SAML2Artifact;
        class SAML_API ArtifactResponse;
    };
    namespace saml2md {
        class SAML_API MetadataProvider;
        class SAML_API IDPSSODescriptor;
        class SAML_API RoleDescriptor;
        class SAML_API SSODescriptorType;
    };

    /**
     * Interface to SAML protocol binding message decoders.
     */
    class SAML_API MessageDecoder
    {
        MAKE_NONCOPYABLE(MessageDecoder);
    public:
        virtual ~MessageDecoder() {}

        /**
         * Interface to caller-supplied artifact resolution mechanism.
         * 
         * Resolving artifacts requires internally performing a SOAP-based
         * call to the artifact source, usually in a mutually authenticated fashion.
         * The potential options vary widely, so the work is encapsulated by this
         * interface, though of course other library facilities may be used.
         * 
         * <p>A MessageDecoder implementation will invoke the supplied interface
         * when it requires an artifact be resolved.
         */
        class SAML_API ArtifactResolver {
            MAKE_NONCOPYABLE(ArtifactResolver);
        protected:
            ArtifactResolver() {}

        public:
            virtual ~ArtifactResolver() {}

            /**
             * Resolves one or more SAML 1.x artifacts into a response containing a set of
             * resolved Assertions. The caller is responsible for the resulting Response.
             * The supplied SecurityPolicy is used to access caller-supplied infrastructure
             * and to pass back the result of authenticating the resolution process. 
             * 
             * @param artifacts         one or more SAML 1.x artifacts
             * @param idpDescriptor     reference to IdP role of artifact issuer
             * @param policy            reference to policy containing rules, MetadataProvider, TrustEngine, etc. 
             * @return the corresponding SAML Assertions wrapped in a Response.
             */
            virtual saml1p::Response* resolve(
                const std::vector<SAMLArtifact*>& artifacts,
                const saml2md::IDPSSODescriptor& idpDescriptor,
                SecurityPolicy& policy
                ) const=0;

            /**
             * Resolves a SAML 2.0 artifact into the corresponding SAML protocol message.
             * The caller is responsible for the resulting ArtifactResponse message.
             * The supplied SecurityPolicy is used to access caller-supplied infrastructure
             * and to pass back the result of authenticating the resolution process. 
             * 
             * @param artifact          reference to a SAML 2.0 artifact
             * @param ssoDescriptor     reference to SSO role of artifact issuer (may be SP or IdP)
             * @param policy            reference to policy containing rules, MetadataProvider, TrustEngine, etc. 
             * @return the corresponding SAML protocol message or NULL
             */
            virtual saml2p::ArtifactResponse* resolve(
                const saml2p::SAML2Artifact& artifact,
                const saml2md::SSODescriptorType& ssoDescriptor,
                SecurityPolicy& policy
                ) const=0;
        };

        /**
         * Provides an ArtifactResolver implementation for the MessageDecoder to use.
         * The implementation's lifetime must be longer than the lifetime of this object. 
         * This method must be externally synchronized. 
         * 
         * @param artifactResolver   an ArtifactResolver implementation to use
         */
        void setArtifactResolver(const ArtifactResolver* artifactResolver) {
            m_artifactResolver = artifactResolver;
        }
        
        /**
         * Decodes a transport request into a SAML protocol message, and evaluates it
         * against a supplied SecurityPolicy. If the transport request does not contain
         * the information necessary to decode the request, NULL will be returned.
         * Errors during the decoding process will be raised as exceptions.
         * 
         * <p>Artifact-based bindings require an ArtifactResolver be set to
         * turn an artifact into the corresponding message.
         * 
         * @param relayState        will be set to RelayState/TARGET value accompanying message
         * @param genericRequest    reference to interface for accessing transport request to decode
         * @param policy            reference to policy containing rules, MetadataProvider, TrustEngine, etc. 
         * @return  the decoded message, or NULL if the decoder did not recognize the request content
         */
        virtual xmltooling::XMLObject* decode(
            std::string& relayState,
            const GenericRequest& genericRequest,
            SecurityPolicy& policy
            ) const=0;

    protected:
        MessageDecoder() : m_artifactResolver(NULL) {}

        /** Pointer to an ArtifactResolver implementation. */
        const ArtifactResolver* m_artifactResolver;
    };

    /**
     * Registers MessageDecoder plugins into the runtime.
     */
    void SAML_API registerMessageDecoders();
};

#endif /* __saml_decoder_h__ */
