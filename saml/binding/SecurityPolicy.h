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
 * @file saml/binding/SecurityPolicy.h
 *
 * Overall policy used to verify the security of an incoming message.
 */

#ifndef __saml_secpol_h__
#define __saml_secpol_h__

#include <saml/saml2/metadata/MetadataProvider.h>

#include <ctime>
#include <vector>
#include <boost/scoped_ptr.hpp>
#include <xmltooling/unicode.h>

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

namespace xmltooling {
    class XMLTOOL_API GenericRequest;
    class XMLTOOL_API TrustEngine;
};

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
            const saml2md::MetadataProvider* metadataProvider=nullptr,
            const xmltooling::QName* role=nullptr,
            const xmltooling::TrustEngine* trustEngine=nullptr,
            bool validate=true
            );

        virtual ~SecurityPolicy();

        /**
         * Returns the locked MetadataProvider supplied to the policy.
         *
         * @return the supplied MetadataProvider or nullptr
         */
        const saml2md::MetadataProvider* getMetadataProvider() const;

        /**
         * Returns a reference to a MetadataProvider::Criteria instance suitable for use with the
         * installed MetadataProvider.
         *
         * <p>The object will be cleared/reset when returned, so do not mutate it and then
         * call the method again before using it.
         *
         * @return reference to a MetadataProvider::Criteria instance
         */
        virtual saml2md::MetadataProvider::Criteria& getMetadataProviderCriteria() const;

        /**
         * Returns the peer role element/type supplied to the policy.
         *
         * @return the peer role element/type, or an empty QName
         */
        const xmltooling::QName* getRole() const;

        /**
         * Returns the TrustEngine supplied to the policy.
         *
         * @return the supplied TrustEngine or nullptr
         */
        const xmltooling::TrustEngine* getTrustEngine() const;

        /**
         * Returns XML message validation setting.
         *
         * @return validation flag
         */
        bool getValidating() const;

        /**
         * Returns flag controlling non-entity issuer support.
         *
         * @return flag controlling non-entity issuer support
         */
        bool requireEntityIssuer() const;

        /**
         * Returns the SAML audiences that represent the receiving peer.
         *
         * @return audience values of the peer processing the message
         */
        const std::vector<xmltooling::xstring>& getAudiences() const;

        /**
         * Returns the SAML audiences that represent the receiving peer.
         *
         * @return audience values of the peer processing the message
         */
        std::vector<xmltooling::xstring>& getAudiences();

        /**
         * Gets the effective time of message processing.
         *
         * @return  the time at which the message is being processed
         */
        time_t getTime() const;

        /**
         * Returns the message identifier to which the message being evaluated
         * is a response.
         *
         * @return correlated message identifier
         */
        const XMLCh* getCorrelationID() const;

        /**
         * Gets a mutable array of installed policy rules.
         *
         * <p>If adding rules, their lifetime must be at least as long as the policy object.
         *
         * @return  mutable array of rules
         */
        std::vector<const SecurityPolicyRule*>& getRules();

        /**
         * Sets a locked MetadataProvider for the policy.
         *
         * @param metadata a locked MetadataProvider or nullptr
         */
        void setMetadataProvider(const saml2md::MetadataProvider* metadata);

        /**
         * Sets a MetadataProvider::Criteria instance suitable for use with the
         * installed MetadataProvider.
         *
         * <p>The policy will take ownership of the criteria object when this
         * method completes.
         *
         * @param criteria a MetadataProvider::Criteria instance, or nullptr
         */
        void setMetadataProviderCriteria(saml2md::MetadataProvider::Criteria* criteria);

        /**
         * Sets a peer role element/type for to the policy.
         *
         * @param role the peer role element/type or nullptr
         */
        void setRole(const xmltooling::QName* role);

        /**
         * Sets a TrustEngine for the policy.
         *
         * @param trust a TrustEngine or nullptr
         */
        void setTrustEngine(const xmltooling::TrustEngine* trust);

        /**
         * Controls schema validation of incoming XML messages.
         * This is separate from other forms of programmatic validation of objects,
         * but can detect a much wider range of syntax errors.
         *
         * @param validate  validation setting
         */
        void setValidating(bool validate=true);

        /**
         * Sets flag controlling non-entity issuer support.
         *
         * @param entityOnly require that Issuer be in entity format
         */
        void requireEntityIssuer(bool entityOnly=true);

        /**
         * Sets effective time of message processing.
         *
         * <p>Assumed to be the time of policy instantiation, can be adjusted to pre- or post-date
         * message processing.
         *
         * @param ts    the time at which the message is being processed
         */
        void setTime(time_t ts);

        /**
         * Sets the message identifier to which the message being evaluated
         * is a response.
         *
         * @param correlationID correlated message identifier
         */
        void setCorrelationID(const XMLCh* correlationID);

        /**
         * Evaluates the policy against the given request and message,
         * possibly populating message information in the policy object.
         *
         * @param message           the incoming message
         * @param request           the protocol request
         *
         * @throws BindingException raised if the message/request is invalid according to the supplied rules
         */
        void evaluate(const xmltooling::XMLObject& message, const xmltooling::GenericRequest* request=nullptr);

        /**
         * Resets the policy object and/or clears any per-message state.
         *
         * <p>Resets can be complete (the default) or merely clear the previous message ID and timestamp
         * when evaluating multiple layers of a message.
         *
         * @param messageOnly   true iff security and issuer state should be left in place
         */
        virtual void reset(bool messageOnly=false);

        /**
         * Resets the policy object and/or clears any per-message state for only this specific class.
         *
         * <p>Resets can be complete (the default) or merely clear the previous message ID and timestamp
         * when evaluating multiple layers of a message.
         *
         * @param messageOnly   true iff security and issuer state should be left in place
         */
        void _reset(bool messageOnly=false);

        /**
         * Returns the message identifier as determined by the registered policies.
         *
         * @return message identifier as determined by the registered policies
         */
        const XMLCh* getMessageID() const;

        /**
         * Returns the message timestamp as determined by the registered policies.
         *
         * @return message timestamp as determined by the registered policies
         */
        time_t getIssueInstant() const;

        /**
         * Gets the issuer of the message as determined by the registered policies.
         *
         * @return issuer of the message as determined by the registered policies
         */
        const saml2::Issuer* getIssuer() const;

        /**
         * Gets the metadata for the role the issuer is operating in.
         *
         * @return metadata for the role the issuer is operating in
         */
        const saml2md::RoleDescriptor* getIssuerMetadata() const;

        /**
         * Returns the authentication status of the message as determined by the registered policies.
         *
         * @return true iff a SecurityPolicyRule has indicated the issuer/message has been authenticated
         */
        bool isAuthenticated() const;

        /**
         * Sets the message identifier as determined by the registered policies.
         *
         * @param id message identifier
         */
        void setMessageID(const XMLCh* id);

        /**
         * Sets the message timestamp as determined by the registered policies.
         *
         * @param issueInstant message timestamp
         */
        void setIssueInstant(time_t issueInstant);

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
        void setAuthenticated(bool auth);

        /** Allows override of rules for comparing saml2:Issuer information. */
        class SAML_API IssuerMatchingPolicy {
            MAKE_NONCOPYABLE(IssuerMatchingPolicy);
        public:
            IssuerMatchingPolicy();
            virtual ~IssuerMatchingPolicy();

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
        const IssuerMatchingPolicy& getIssuerMatchingPolicy() const;

        /**
         * Sets the IssuerMatchingPolicy in effect. Setting no policy will
         * cause the simple, default approach to be used.
         *
         * <p>The matching object will be freed by the SecurityPolicy.
         *
         * @param matchingPolicy the IssuerMatchingPolicy to use
         */
        void setIssuerMatchingPolicy(IssuerMatchingPolicy* matchingPolicy);

    protected:
        /** A shared matching object that just supports the default matching rules. */
        static IssuerMatchingPolicy m_defaultMatching;

        /** Manufactured MetadataProvider::Criteria instance. */
        mutable saml2md::MetadataProvider::Criteria* m_metadataCriteria;

    private:
        // information extracted from message
        xmltooling::xstring m_messageID;
        time_t m_issueInstant;
        boost::scoped_ptr<saml2::Issuer> m_issuer;
        const saml2md::RoleDescriptor* m_issuerRole;
        bool m_authenticated;

        // components governing policy rules
        boost::scoped_ptr<IssuerMatchingPolicy> m_matchingPolicy;
        std::vector<const SecurityPolicyRule*> m_rules;
        const saml2md::MetadataProvider* m_metadata;
        boost::scoped_ptr<xmltooling::QName> m_role;
        const xmltooling::TrustEngine* m_trust;
        bool m_validate;
        bool m_entityOnly;

        // contextual information
        mutable time_t m_ts;
        xmltooling::xstring m_correlationID;
        std::vector<xmltooling::xstring> m_audiences;
    };

};

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

#endif /* __saml_secpol_h__ */
