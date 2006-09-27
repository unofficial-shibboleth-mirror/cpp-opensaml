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
#include <xmltooling/XMLObject.h>
#include <xmltooling/signature/CredentialResolver.h>
#include <xmltooling/util/StorageService.h>

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
         * Interface to caller-supplied artifact generation mechanism.
         * 
         * Generating an artifact for storage and retrieval requires knowledge of
         * the sender's SourceID (or sometimes SourceLocation), and the relying party's
         * preferred artifact type. This information can be supplied using whatever
         * configuration or defaults are appropriate for the SAML application.
         * An ArtifactMap implementation will invoke the supplied generator interface
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
         * Encodes an XML object/message into a set of binding-specific data "fields".
         * The XML content cannot have a parent object, and any existing references to
         * the content will be invalidated if the encode method returns successfully.
         * 
         * If a CredentialResolver is supplied, the message is also signed in a
         * binding-specific manner. The CredentialResolver <strong>MUST</strong>
         * be locked by the caller. 
         * 
         * <p>An embedded URLEncoder instance may be required by some bindings
         * in order to produce predictable signature input.
         * 
         * <p>Artifact-based bindings require an ArtifactGenerator be set to
         * produce an artifact suitable for the intended recipient.
         * 
         * <p>Note that the name/value pairs resulting from the encoding operation are
         * <strong>NOT</strong> URL-encoded or otherwise transformed. It is the caller's
         * responsibility to apply any necessary encoding when preparing the data for
         * transport.
         * 
         * @param outputFields      name/value pairs containing the results of encoding the message
         * @param xmlObject         XML object/message to encode
         * @param recipientID       optional entityID of message recipient
         * @param relayState        optional RelayState value to accompany message
         * @param credResolver      optional CredentialResolver instance to supply signing material
         * @param sigAlgorithm      optional signature algorithm identifier
         */
        virtual void encode(
            std::map<std::string,std::string>& outputFields,
            xmltooling::XMLObject* xmlObject,
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

    /** MessageEncoder for SAML 1.x Browser/Artifact "binding" (really part of profile) */
    #define SAML1_ARTIFACT_ENCODER  "urn:oasis:names:tc:SAML:1.0:profiles:artifact-01"

    /** MessageEncoder for SAML 1.x Browser/POST "binding" (really part of profile) */
    #define SAML1_POST_ENCODER  "urn:oasis:names:tc:SAML:1.0:profiles:browser-post"
    
    /** MessageEncoder for SAML 2.0 HTTP-Artifact binding */
    #define SAML2_ARTIFACT_ENCODER "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"

    /** MessageEncoder for SAML 2.0 HTTP-POST binding */
    #define SAML2_POST_ENCODER "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

    /** MessageEncoder for SAML 2.0 HTTP-Redirect binding */
    #define SAML2_REDIRECT_ENCODER "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
};

#endif /* __saml_encoder_h__ */
