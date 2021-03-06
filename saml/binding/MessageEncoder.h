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
 * @file saml/binding/MessageEncoder.h
 * 
 * Interface to SAML protocol binding message encoders. 
 */

#ifndef __saml_encoder_h__
#define __saml_encoder_h__

#include <saml/base.h>

namespace xmltooling {
    class XMLTOOL_API Credential;
    class XMLTOOL_API GenericResponse;
    class XMLTOOL_API XMLObject;
};

namespace opensaml {

    class SAML_API SAMLArtifact;
    namespace saml2p {
        class SAML_API SAML2Artifact;
    };
    namespace saml2md {
        class SAML_API EntityDescriptor;
    };

    /**
     * Interface to SAML protocol binding message encoders.
     */
    class SAML_API MessageEncoder
    {
        MAKE_NONCOPYABLE(MessageEncoder);
    public:
        virtual ~MessageEncoder();

        /**
         * Indicates whether the encoding format requires that messages be as compact as possible.
         *
         * @return  true iff the encoding has size constraints
         */
        virtual bool isCompact() const;

        /**
         * Indicates whether a web browser or similar user agent will receive the message.
         *
         * @return true iff the message will be handled by a user agent
         */
        virtual bool isUserAgentPresent() const;

        /**
         * Returns identifier for the protocol family associated with the encoder.
         *
         * @return  a protocol family identifier, or nullptr
         */
        virtual const XMLCh* getProtocolFamily() const;

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
            ArtifactGenerator();
        public:
            virtual ~ArtifactGenerator();
            
            /**
             * Generate a SAML 1.x artifact suitable for consumption by the relying party.
             * 
             * @param relyingParty  the party that will recieve the artifact
             * @return a SAML 1.x artifact with a random assertion handle
             */
            virtual SAMLArtifact* generateSAML1Artifact(const saml2md::EntityDescriptor* relyingParty) const=0;

            /**
             * Generate a SAML 2.0 artifact suitable for consumption by the relying party.
             * 
             * @param relyingParty  the party that will recieve the artifact
             * @return a SAML 2.0 artifact with a random message handle
             */
            virtual saml2p::SAML2Artifact* generateSAML2Artifact(const saml2md::EntityDescriptor* relyingParty) const=0;
        };

        /**
         * Encodes an XML object/message into a binding- and transport-specific response.
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
         * @param genericResponse   reference to interface for sending transport response      
         * @param xmlObject         XML message to encode
         * @param destination       destination URL for message
         * @param recipient         optional message recipient
         * @param relayState        optional RelayState value to accompany message
         * @param artifactGenerator optional interface for generation of artifacts
         * @param credential        optional Credential to supply signing key
         * @param signatureAlg      optional signature algorithm identifier
         * @param digestAlg         optional reference digest algorithm identifier
         */
        virtual long encode(
            xmltooling::GenericResponse& genericResponse,
            xmltooling::XMLObject* xmlObject,
            const char* destination,
            const saml2md::EntityDescriptor* recipient=nullptr,
            const char* relayState=nullptr,
            const ArtifactGenerator* artifactGenerator=nullptr,
            const xmltooling::Credential* credential=nullptr,
            const XMLCh* signatureAlg=nullptr,
            const XMLCh* digestAlg=nullptr
            ) const=0;

    protected:
        MessageEncoder();
    };

    /**
     * Registers MessageEncoder plugins into the runtime.
     */
    void SAML_API registerMessageEncoders();
};

#endif /* __saml_encoder_h__ */
