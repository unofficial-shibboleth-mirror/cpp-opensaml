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
 * @file saml/binding/MessageEncoder.h
 * 
 * Interface to SAML protocol binding message encoders. 
 */

#ifndef __saml_encoder_h__
#define __saml_encoder_h__

#include <saml/base.h>

#include <map>
#include <string>
#include <istream>
#include <xmltooling/XMLObject.h>
#include <xmltooling/signature/CredentialResolver.h>

namespace opensaml {

    class SAML_API SAMLArtifact;
    namespace saml2p {
        class SAML_API SAML2Artifact;
    };

    /**
     * Interface to SAML protocol binding message encoders.
     */
    class SAML_API MessageEncoder
    {
        MAKE_NONCOPYABLE(MessageEncoder);
    public:
        virtual ~MessageEncoder() {}

        /**
         * Interface to caller-supplied shim for issuing an HTTP response.
         * 
         * <p>To supply information to the surrounding web server environment,
         * a shim must be supplied in the form of this interface to adapt the
         * library to different proprietary server APIs.
         * 
         * <p>This interface need not be threadsafe.
         */
        class SAML_API HTTPResponse {
            MAKE_NONCOPYABLE(HTTPResponse);
        protected:
            HTTPResponse() {}
        public:
            virtual ~HTTPResponse() {}
            
            /**
             * Sets or clears a response header.
             * 
             * @param name  header name
             * @param value value to set, or NULL to clear
             */
            virtual void setHeader(const char* name, const char* value)=0;

            /**
             * Sets a client cookie.
             * 
             * @param name  cookie name
             * @param value value to set, or NULL to clear
             */
            virtual void setCookie(const char* name, const char* value)=0;
            
            /**
             * Redirect the client to the specified URL and complete the response.
             * Any headers previously set will be sent ahead of the redirect.
             * 
             * @param url   location to redirect client
             * @return a result code to return from the calling MessageEncoder
             */
            virtual long sendRedirect(const char* url)=0;

            /**
             * Sends a completed response to the client. Any headers previously set
             * will be sent ahead of the data.
             * 
             * @param inputStream   reference to source of response data
             * @param status        HTTP status code to return
             * @param contentType   Content-Type header to return
             * @return a result code to return from the calling MessageEncoder
             */
            virtual long sendResponse(std::istream& inputStream, int status = 200, const char* contentType = "text/html")=0;
        };

        /**
         * Interface to caller-supplied artifact generation mechanism.
         * 
         * Generating an artifact for storage and retrieval requires knowledge of
         * the sender's SourceID (or sometimes SourceLocation), and the relying party's
         * preferred artifact type. This information can be supplied using whatever
         * configuration or defaults are appropriate for the SAML application.
         * A MessageEncoder implementation will invoke the supplied generator interface
         * when it requires an artifact be created.
         */
        class SAML_API ArtifactGenerator {
            MAKE_NONCOPYABLE(ArtifactGenerator);
        protected:
            ArtifactGenerator() {}
        public:
            virtual ~ArtifactGenerator() {}
            
            /**
             * Generate a SAML 1.x artifact suitable for consumption by the relying party.
             * 
             * @param relyingParty  the party that will recieve the artifact
             * @return a SAML 1.x artifact with a random assertion handle
             */
            virtual SAMLArtifact* generateSAML1Artifact(const char* relyingParty) const=0;

            /**
             * Generate a SAML 2.0 artifact suitable for consumption by the relying party.
             * 
             * @param relyingParty  the party that will recieve the artifact
             * @return a SAML 2.0 artifact with a random message handle
             */
            virtual saml2p::SAML2Artifact* generateSAML2Artifact(const char* relyingParty) const=0;
        };

        /**
         * Provides an ArtifactGenerator implementation for the MessageEncoder to use.
         * The implementation's lifetime must be longer than the lifetime of this object. 
         * This method must be externally synchronized. 
         * 
         * @param artifactGenerator   an ArtifactGenerator implementation to use
         */
        void setArtifactGenerator(ArtifactGenerator* artifactGenerator) {
            m_artifactGenerator = artifactGenerator;
        }
        
        /**
         * Encodes an XML object/message into a binding-specific HTTP response.
         * The XML content cannot have a parent object, and any existing references to
         * the content will be invalidated if the encode method returns successfully.
         * 
         * If a CredentialResolver is supplied, the message is also signed in a
         * binding-specific manner. The CredentialResolver <strong>MUST</strong>
         * be locked by the caller. 
         * 
         * <p>Artifact-based bindings require an ArtifactGenerator be set to
         * produce an artifact suitable for the intended recipient.
         * 
         * @param httpResponse      reference to interface for sending encoded response to client      
         * @param xmlObject         XML message to encode
         * @param destination       destination URL for message
         * @param recipientID       optional entityID of message recipient
         * @param relayState        optional RelayState value to accompany message
         * @param credResolver      optional CredentialResolver instance to supply signing material
         * @param sigAlgorithm      optional signature algorithm identifier
         */
        virtual long encode(
            HTTPResponse& httpResponse,
            xmltooling::XMLObject* xmlObject,
            const char* destination,
            const char* recipientID=NULL,
            const char* relayState=NULL,
            const xmlsignature::CredentialResolver* credResolver=NULL,
            const XMLCh* sigAlgorithm=NULL
            ) const=0;

    protected:
        MessageEncoder() : m_artifactGenerator(NULL) {}
        
        /**
         * Helper function to build a new XML Signature with KeyInfo, based
         * on the supplied CredentialResolver.
         * 
         * @param credResolver      CredentialResolver instance to supply signing material
         * @param sigAlgorithm      optional signature algorithm identifier
         * @return  a new Signature object
         */
        xmlsignature::Signature* buildSignature(
            const xmlsignature::CredentialResolver* credResolver,
            const XMLCh* sigAlgorithm=NULL
            ) const;
        
        /** Pointer to an ArtifactGenerator implementation. */
        const ArtifactGenerator* m_artifactGenerator;
    };

    /**
     * Registers MessageEncoder plugins into the runtime.
     */
    void SAML_API registerMessageEncoders();
};

#endif /* __saml_encoder_h__ */
