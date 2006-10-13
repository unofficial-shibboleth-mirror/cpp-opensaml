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
 * @file saml/binding/MessageDecoder.h
 * 
 * Interface to SAML protocol binding message decoders. 
 */

#ifndef __saml_decoder_h__
#define __saml_decoder_h__

#include <saml/base.h>

#include <xmltooling/XMLObject.h>

namespace opensaml {
    
    class SAML_API SAMLArtifact;
    class SAML_API X509TrustEngine;
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
    }

    /**
     * Interface to SAML protocol binding message decoders.
     */
    class SAML_API MessageDecoder
    {
        MAKE_NONCOPYABLE(MessageDecoder);
    public:
        virtual ~MessageDecoder() {}

        /**
         * Interface to caller-supplied shim for accessing HTTP request context.
         * 
         * To supply information from the surrounding web server environment,
         * a shim must be supplied in the form of this interface to adapt the
         * library to different proprietary server APIs.
         */
        class SAML_API HTTPRequest {
            MAKE_NONCOPYABLE(HTTPRequest);
        protected:
            HTTPRequest() {}
        public:
            virtual ~HTTPRequest() {}
            
            /**
             * Returns the HTTP method of the request (GET, POST, etc.)
             * 
             * @return the HTTP method
             */
            virtual const char* getMethod() const=0;
            
            /**
             * Returns the complete request URL, including scheme, host, port.
             * 
             * @return the request URL
             */
            virtual const char* getRequestURL() const=0;
            
            /**
             * Returns the HTTP query string appened to the request. The query
             * string is returned without any decoding applied, everything found
             * after the ? delimiter. 
             * 
             * @return the query string
             */
            virtual const char* getQueryString() const=0;
            
            /**
             * Returns a decoded named parameter value from the query string or form body.
             * If a parameter has multiple values, only one will be returned.
             * 
             * @param name  the name of the parameter to return
             * @return a single parameter value or NULL
             */
            virtual const char* getParameter(const char* name) const=0;

            /**
             * Returns all of the decoded values of a named parameter from the query string
             * or form body. All values found will be returned.
             * 
             * @param name      the name of the parameter to return
             * @param values    a vector in which to return pointers to the decoded values
             * @return  the number of values returned
             */            
            virtual std::vector<const char*>::size_type getParameters(
                const char* name, std::vector<const char*>& values
                ) const=0;
        };

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
            
            /** Flag controlling schema validation. */
            bool m_validate;

        public:
            virtual ~ArtifactResolver() {}

            /**
             * Controls schema validation of incoming XML messages.
             * This is separate from other forms of programmatic validation of objects,
             * but can detect a much wider range of syntax errors. 
             * 
             * @param validate  true iff the resolver should use a validating XML parser
             */
            void setValidating(bool validate=true) {
                m_validate = validate;
            }
            
            /**
             * Resolves one or more SAML 1.x artifacts into a response containing a set of
             * resolved Assertions. The caller is responsible for the resulting Response. 
             * 
             * @param authenticated     output flag set to true iff the resolution channel was authenticated
             * @param artifacts         one or more SAML 1.x artifacts
             * @param idpDescriptor     reference to IdP role of artifact issuer
             * @param trustEngine       optional pointer to X509TrustEngine supplied to MessageDecoder
             * @return the corresponding SAML Assertions wrapped in a Response.
             */
            virtual saml1p::Response* resolve(
                bool& authenticated,
                const std::vector<SAMLArtifact*>& artifacts,
                const saml2md::IDPSSODescriptor& idpDescriptor,
                const X509TrustEngine* trustEngine=NULL
                ) const=0;

            /**
             * Resolves a SAML 2.0 artifact into the corresponding SAML protocol message.
             * The caller is responsible for the resulting ArtifactResponse message.
             * 
             * @param authenticated     output flag set to true iff the resolution channel was authenticated
             * @param artifact          reference to a SAML 2.0 artifact
             * @param ssoDescriptor     reference to SSO role of artifact issuer (may be SP or IdP)
             * @param trustEngine       optional pointer to X509TrustEngine supplied to MessageDecoder
             * @return the corresponding SAML protocol message or NULL
             */
            virtual saml2p::ArtifactResponse* resolve(
                bool& authenticated,
                const saml2p::SAML2Artifact& artifact,
                const saml2md::SSODescriptorType& ssoDescriptor,
                const X509TrustEngine* trustEngine=NULL
                ) const=0;
        };

        /**
         * Provides an ArtifactResolver implementation for the MessageDecoder to use.
         * The implementation's lifetime must be longer than the lifetime of this object. 
         * This method must be externally synchronized. 
         * 
         * @param artifactResolver   an ArtifactResolver implementation to use
         */
        void setArtifactResolver(ArtifactResolver* artifactResolver) {
            m_artifactResolver = artifactResolver;
            if (m_artifactResolver)
                m_artifactResolver->setValidating(m_validate);
        }
        
        /**
         * Controls schema validation of incoming XML messages.
         * This is separate from other forms of programmatic validation of objects,
         * but can detect a much wider range of syntax errors. 
         * 
         * @param validate  true iff the decoder should use a validating XML parser
         */
        void setValidating(bool validate=true) {
            m_validate = validate;
            if (m_artifactResolver)
                m_artifactResolver->setValidating(m_validate);
        }

        /**
         * Decodes an HTTP request into a SAML protocol message, and returns related
         * information about the issuer of the message and whether it can be trusted.
         * If the HTTP request does not contain the information necessary to decode
         * the request, a NULL will be returned. Errors during the decoding process
         * will be raised as exceptions.
         * 
         * <p>Artifact-based bindings require an ArtifactResolver be set to
         * turn an artifact into the corresponding message.
         * 
         * <p>In some cases, a message may be returned but not authenticated. The caller
         * should examine the issuerTrusted output value to establish this.  
         * 
         * @param relayState        RelayState/TARGET value accompanying message
         * @param issuer            role descriptor of issuing party
         * @param issuerTrusted     output flag set to true iff the message was authenticated
         *                          (signed or obtained via secure backchannel)
         * @param httpRequest       reference to interface for accessing HTTP message to decode
         * @param metadataProvider  optional MetadataProvider instance to authenticate the message
         * @param role              optional, identifies the role (generally IdP or SP) of the peer who issued the message 
         * @param trustEngine       optional TrustEngine to authenticate the message
         * @return  the decoded message, or NULL if the decoder did not recognize the request content
         */
        virtual xmltooling::XMLObject* decode(
            std::string& relayState,
            const saml2md::RoleDescriptor*& issuer,
            bool& issuerTrusted,
            const HTTPRequest& httpRequest,
            const saml2md::MetadataProvider* metadataProvider=NULL,
            const xmltooling::QName* role=NULL,
            const TrustEngine* trustEngine=NULL
            ) const=0;

    protected:
        MessageDecoder() : m_artifactResolver(NULL), m_validate(false) {}

        /** Pointer to an ArtifactResolver implementation. */
        ArtifactResolver* m_artifactResolver;
        
        /** Flag controlling schema validation. */
        bool m_validate;
    };

    /**
     * Registers MessageDecoder plugins into the runtime.
     */
    void SAML_API registerMessageDecoders();
};

#endif /* __saml_decoder_h__ */
