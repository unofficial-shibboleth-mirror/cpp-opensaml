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
 * @file saml/binding/SecurityPolicy.h
 *
 * Overall policy used to verify the security of an incoming message.
 */

#ifndef __saml_secpol_h__
#define __saml_secpol_h__

#include <saml/saml2/metadata/MetadataProvider.h>

#include <ctime>
#include <vector>
#include <xmltooling/io/GenericRequest.h>
#include <xmltooling/security/TrustEngine.h>

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

namespace opensaml {

    namespace saml2 {
        class SAML_API Issuer;
    };

    class SAML_API SecurityPolicyRule;

    /**
     * A policy used to verify the security of an incoming message.
     *
     * <p>Its security mechanisms may be used to examine the transport layer
     * (e.g client certificates and HTTP basic auth passwords) or to check the
     * payload of a request to ensure it meets certain criteria (e.g. valid
     * digital signature, freshness, replay).
     *
     * <p>Policy objects can be reused, but are not thread-safe.
     */
    class SAML_API SecurityPolicy
    {
        MAKE_NONCOPYABLE(SecurityPolicy);
    public:
        /**
         * Constructor for policy.
         *
         * @param metadataProvider  locked MetadataProvider instance
         * @param role              identifies the role (generally IdP or SP) of the policy peer
         * @param trustEngine       TrustEngine to authenticate policy peer
         * @param validate          true iff XML parsing should be done with validation
         */
        SecurityPolicy(
            const saml2md::MetadataProvider* metadataProvider=NULL,
            const xmltooling::QName* role=NULL,
            const xmltooling::TrustEngine* trustEngine=NULL,
            bool validate=true
            ) : m_metadataCriteria(NULL), m_messageID(NULL), m_issueInstant(0), m_issuer(NULL), m_issuerRole(NULL), m_authenticated(false),
                m_matchingPolicy(NULL), m_metadata(metadataProvider), m_role(NULL), m_trust(trustEngine), m_validate(validate), m_entityOnly(true) {
            if (role)
                m_role = new xmltooling::QName(*role);
        }

        virtual ~SecurityPolicy();

        /**
         * Returns the locked MetadataProvider supplied to the policy.
         *
         * @return the supplied MetadataProvider or NULL
         */
        const saml2md::MetadataProvider* getMetadataProvider() const {
            return m_metadata;
        }

        /**
         * Returns a reference to a MetadataProvider::Criteria instance suitable for use with the
         * installed MetadataProvider.
         *
         * @return reference to a MetadataProvider::Criteria instance
         */
        virtual saml2md::MetadataProvider::Criteria& getMetadataProviderCriteria() const;

        /**
         * Returns the peer role element/type supplied to the policy.
         *
         * @return the peer role element/type, or an empty QName
         */
        const xmltooling::QName* getRole() const {
            return m_role;
        }

        /**
         * Returns the TrustEngine supplied to the policy.
         *
         * @return the supplied TrustEngine or NULL
         */
        const xmltooling::TrustEngine* getTrustEngine() const {
            return m_trust;
        }

        /**
         * Returns XML message validation setting.
         *
         * @return validation flag
         */
        bool getValidating() const {
            return m_validate;
        }

        /**
         * Returns flag controlling non-entity issuer support.
         *
         * @return flag controlling non-entity issuer support
         */
        bool requireEntityIssuer() const {
            return m_entityOnly;
        }

        /**
         * Gets a mutable array of installed policy rules.
         *
         * <p>If adding rules, their lifetime must be at least as long as the policy object.
         *
         * @return  mutable array of rules
         */
        std::vector<const SecurityPolicyRule*>& getRules() {
            return m_rules;
        }

        /**
         * Sets a locked MetadataProvider for the policy.
         *
         * @param metadata a locked MetadataProvider or NULL
         */
        void setMetadataProvider(const saml2md::MetadataProvider* metadata) {
            m_metadata = metadata;
        }

        /**
         * Sets a peer role element/type for to the policy.
         *
         * @param role the peer role element/type or NULL
         */
        void setRole(const xmltooling::QName* role) {
            delete m_role;
            m_role = role ? new xmltooling::QName(*role) : NULL;
        }

        /**
         * Sets a TrustEngine for the policy.
         *
         * @param trust a TrustEngine or NULL
         */
        void setTrustEngine(const xmltooling::TrustEngine* trust) {
            m_trust = trust;
        }

        /**
         * Controls schema validation of incoming XML messages.
         * This is separate from other forms of programmatic validation of objects,
         * but can detect a much wider range of syntax errors.
         *
         * @param validate  validation setting
         */
        void setValidating(bool validate=true) {
            m_validate = validate;
        }

        /**
         * Sets flag controlling non-entity issuer support.
         *
         * @param entityOnly require that Issuer be in entity format
         */
        void requireEntityIssuer(bool entityOnly=true) {
            m_entityOnly = entityOnly;
        }

        /**
         * Evaluates the policy against the given request and message,
         * possibly populating message information in the policy object.
         *
         * @param message           the incoming message
         * @param request           the protocol request
         *
         * @throws BindingException raised if the message/request is invalid according to the supplied rules
         */
        void evaluate(
            const xmltooling::XMLObject& message, const xmltooling::GenericRequest* request=NULL
            );

        /**
         * Resets the policy object and/or clears any per-message state.
         *
         * <p>Resets can be complete (the default) or merely clear the previous message ID and timestamp
         * when evaluating multiple layers of a message.
         *
         * @param messageOnly   true iff security and issuer state should be left in place
         */
        void reset(bool messageOnly=false);

        /**
         * Returns the message identifier as determined by the registered policies.
         *
         * @return message identifier as determined by the registered policies
         */
        const XMLCh* getMessageID() const {
            return m_messageID;
        }

        /**
         * Returns the message timestamp as determined by the registered policies.
         *
         * @return message timestamp as determined by the registered policies
         */
        time_t getIssueInstant() const {
            return m_issueInstant;
        }

        /**
         * Gets the issuer of the message as determined by the registered policies.
         *
         * @return issuer of the message as determined by the registered policies
         */
        const saml2::Issuer* getIssuer() const {
            return m_issuer;
        }

        /**
         * Gets the metadata for the role the issuer is operating in.
         *
         * @return metadata for the role the issuer is operating in
         */
        const saml2md::RoleDescriptor* getIssuerMetadata() const {
            return m_issuerRole;
        }

        /**
         * Returns the authentication status of the message as determined by the registered policies.
         *
         * @return true iff a SecurityPolicyRule has indicated the issuer/message has been authenticated
         */
        bool isAuthenticated() const {
            return m_authenticated;
        }

        /**
         * Sets the message identifier as determined by the registered policies.
         *
         * @param id message identifier
         */
        void setMessageID(const XMLCh* id) {
            xercesc::XMLString::release(&m_messageID);
            m_messageID = xercesc::XMLString::replicate(id);
        }

        /**
         * Sets the message timestamp as determined by the registered policies.
         *
         * @param issueInstant message timestamp
         */
        void setIssueInstant(time_t issueInstant) {
            m_issueInstant = issueInstant;
        }

        /**
         * Sets the issuer of the message as determined by the registered policies.
         *
         * @param issuer issuer of the message
         */
        void setIssuer(const saml2::Issuer* issuer);

        /**
         * Sets the issuer of the message as determined by the registered policies.
         *
         * @param issuer issuer of the message
         */
        void setIssuer(const XMLCh* issuer);

        /**
         * Sets the metadata for the role the issuer is operating in.
         *
         * @param issuerRole metadata for the role the issuer is operating in
         */
        void setIssuerMetadata(const saml2md::RoleDescriptor* issuerRole);

        /**
         * Sets the authentication status of the message as determined by the registered policies.
         *
         * @param auth indicates whether the issuer/message has been authenticated
         */
        void setAuthenticated(bool auth) {
            m_authenticated = auth;
        }

        /** Allows override of rules for comparing saml2:Issuer information. */
        class SAML_API IssuerMatchingPolicy {
            MAKE_NONCOPYABLE(IssuerMatchingPolicy);
        public:
            IssuerMatchingPolicy() {}
            virtual ~IssuerMatchingPolicy() {}

            /**
             * Returns true iff the two operands "match". Applications can override this method to
             * support non-standard issuer matching for complex policies.
             *
             * <p>The default implementation does a basic comparison of the XML content, treating
             * an unsupplied Format as an "entityID".
             *
             * @param issuer1   the first Issuer to match
             * @param issuer2   the second Issuer to match
             * @return  true iff the operands match
             */
            virtual bool issuerMatches(const saml2::Issuer* issuer1, const saml2::Issuer* issuer2) const;

            /**
             * Returns true iff the two operands "match". Applications can override this method to
             * support non-standard issuer matching for complex policies.
             *
             * <p>The default implementation does a basic comparison of the XML content, treating
             * an unsupplied Format as an "entityID".
             *
             * @param issuer1   the first Issuer to match
             * @param issuer2   the second Issuer to match
             * @return  true iff the operands match
             */
            virtual bool issuerMatches(const saml2::Issuer* issuer1, const XMLCh* issuer2) const;
        };

        /**
         * Returns the IssuerMatchingPolicy in effect.
         *
         * @return the effective IssuerMatchingPolicy
         */
        const IssuerMatchingPolicy& getIssuerMatchingPolicy() const {
            return m_matchingPolicy ? *m_matchingPolicy : m_defaultMatching;
        }

        /**
         * Sets the IssuerMatchingPolicy in effect. Setting no policy will
         * cause the simple, default approach to be used.
         *
         * <p>The matching object will be freed by the SecurityPolicy.
         *
         * @param matchingPolicy the IssuerMatchingPolicy to use
         */
        void setIssuerMatchingPolicy(IssuerMatchingPolicy* matchingPolicy) {
            delete m_matchingPolicy;
            m_matchingPolicy = matchingPolicy;
        }

    protected:
        /** A shared matching object that just supports the default matching rules. */
        static IssuerMatchingPolicy m_defaultMatching;

        /** Manufactured MetadataProvider::Criteria instance. */
        mutable saml2md::MetadataProvider::Criteria* m_metadataCriteria;

    private:
        // information extracted from message
        XMLCh* m_messageID;
        time_t m_issueInstant;
        saml2::Issuer* m_issuer;
        const saml2md::RoleDescriptor* m_issuerRole;
        bool m_authenticated;

        // components governing policy rules
        IssuerMatchingPolicy* m_matchingPolicy;
        std::vector<const SecurityPolicyRule*> m_rules;
        const saml2md::MetadataProvider* m_metadata;
        xmltooling::QName* m_role;
        const xmltooling::TrustEngine* m_trust;
        bool m_validate;
        bool m_entityOnly;
    };

};

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

#endif /* __saml_secpol_h__ */
