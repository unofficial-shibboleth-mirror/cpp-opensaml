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
 * @file saml/binding/SecurityPolicy.h
 * 
 * Overall policy used to verify the security of an incoming message.
 */

#ifndef __saml_secpol_h__
#define __saml_secpol_h__

#include <saml/binding/SecurityPolicyRule.h>
#include <vector>

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

namespace opensaml {

    namespace saml2md {
        class SAML_API MetadataProvider;
    };
    
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
         * @param rules             reference to array of policy rules to use 
         * @param metadataProvider  locked MetadataProvider instance
         * @param role              identifies the role (generally IdP or SP) of the policy peer 
         * @param trustEngine       TrustEngine to authenticate policy peer
         */
        SecurityPolicy(
            const std::vector<const SecurityPolicyRule*>& rules,
            const saml2md::MetadataProvider* metadataProvider=NULL,
            const xmltooling::QName* role=NULL,
            const TrustEngine* trustEngine=NULL
            ) : m_issuer(NULL), m_issuerRole(NULL), m_rules(rules), m_metadata(metadataProvider),
                m_role(role ? *role : xmltooling::QName()), m_trust(trustEngine) {
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
         * Returns the peer role element/type supplied to the policy.
         * 
         * @return the peer role element/type, or an empty QName
         */
        const xmltooling::QName* getRole() const {
            return &m_role;
        }

        /**
         * Returns the TrustEngine supplied to the policy.
         * 
         * @return the supplied TrustEngine or NULL
         */
        const TrustEngine* getTrustEngine() const {
            return m_trust;
        }

        /**
         * Evaluates the rule against the given request and message,
         * possibly populating issuer information in the policy object.
         * 
         * @param request           the protocol request
         * @param message           the incoming message
         * @return the identity of the message issuer, in one or more of two forms, or NULL
         * 
         * @throws BindingException thrown if the request/message do not meet the requirements of this rule
         */
        void evaluate(const GenericRequest& request, const xmltooling::XMLObject& message);

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
         * Sets the issuer of the message as determined by external factors.
         * The policy object takes ownership of the Issuer object.
         * 
         * @param issuer issuer of the message
         */
        void setIssuer(saml2::Issuer* issuer);
        
        /**
         * Sets the metadata for the role the issuer is operating in.
         * 
         * @param issuerRole metadata for the role the issuer is operating in
         */
        void setIssuerMetadata(const saml2md::RoleDescriptor* issuerRole);

    protected:
        /**
         * Returns true iff the two operands "match". Applications can override this method to
         * support non-standard issuer matching for complex policies. 
         * 
         * <p>The default implementation does a basic comparison of the XML content, treating
         * an unsupplied Format as "entityID".
         * 
         * @param issuer1   the first Issuer to match
         * @param issuer2   the second Issuer to match
         * @return  true iff the operands match
         */
        virtual bool issuerMatches(const saml2::Issuer* issuer1, const saml2::Issuer* issuer2) const;

    private:
        saml2::Issuer* m_issuer;
        const saml2md::RoleDescriptor* m_issuerRole;
        
        std::vector<const SecurityPolicyRule*> m_rules;
        const saml2md::MetadataProvider* m_metadata;
        xmltooling::QName m_role;
        const TrustEngine* m_trust;
    };

};

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

#endif /* __saml_secpol_h__ */
