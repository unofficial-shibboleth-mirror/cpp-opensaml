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
 * @file saml/binding/SecurityPolicyRule.h
 *
 * Policy rules that secure and authenticate bindings.
 */

#ifndef __saml_secrule_h__
#define __saml_secrule_h__

#include <saml/base.h>

namespace xmltooling {
    class XMLTOOL_API GenericRequest;
    class XMLTOOL_API XMLObject;
};

namespace opensaml {
    class SAML_API SecurityPolicy;

    /**
     * A rule that a protocol request and message must meet in order to be valid and secure.
     *
     * <p>Rules must be stateless and thread-safe across evaluations. Evaluation should not
     * result in an exception if the request/message properties do not apply to the rule
     * (e.g. particular security mechanisms that are not present).
     */
    class SAML_API SecurityPolicyRule
    {
        MAKE_NONCOPYABLE(SecurityPolicyRule);
    protected:
        SecurityPolicyRule();
    public:
        virtual ~SecurityPolicyRule();

        /**
         * Returns the rule's class/type.
         *
         * @return  the class/type of the object
         */
        virtual const char* getType() const=0;

        /**
         * Evaluates the rule against the given request and message.
         *
         * <p>An exception will be raised if the message is fatally invalid according to
         * a policy rule.
         *
         * <p>The return value is used to indicate whether a message was ignored or
         * successfully processed. A false value signals that the rule wasn't successful
         * because the rule was inapplicable to the message, but allows other rules to
         * return an alternate result.
         *
         * @param message   the incoming message
         * @param request   the protocol request
         * @param policy    SecurityPolicy to provide various components and track message data
         * @return  indicator as to whether a message was understood and processed
         */
        virtual bool evaluate(
            const xmltooling::XMLObject& message,
            const xmltooling::GenericRequest* request,
            SecurityPolicy& policy
            ) const=0;
    };

    /**
     * Registers SecurityPolicyRule plugins into the runtime.
     */
    void SAML_API registerSecurityPolicyRules();

    /**
     * SecurityPolicyRule for evaluation of SAML AudienceRestriction Conditions.
     */
    #define AUDIENCE_POLICY_RULE        "Audience"

    /**
     * SecurityPolicyRule for evaluation of SAML DelegationRestriction Conditions.
     */
    #define DELEGATION_POLICY_RULE        "Delegation"

    /**
     * SecurityPolicyRule for TLS client certificate authentication.
     *
     * Evaluates client certificates against the issuer's metadata.
     */
    #define CLIENTCERTAUTH_POLICY_RULE  "ClientCertAuth"

    /**
     * SecurityPolicyRule for evaluation of SAML Conditions.
     */
    #define CONDITIONS_POLICY_RULE      "Conditions"

    /**
     * SecurityPolicyRule for ignoring a SAML Condition.
     */
    #define IGNORE_POLICY_RULE          "Ignore"

    /**
     * SecurityPolicyRule for replay detection and freshness checking.
     *
     * <p>A ReplayCache instance must be available from the runtime, unless
     * a "checkReplay" XML attribute is set to "0" or "false" when instantiating
     * the policy rule.
     *
     * <p>Messages must have been issued in the past, but no more than 60 seconds ago,
     * or up to a number of seconds set by an "expires" XML attribute when
     * instantiating the policy rule.
     */
    #define MESSAGEFLOW_POLICY_RULE     "MessageFlow"

    /**
     * SecurityPolicyRule for disabling security.
     *
     * Allows the message issuer to be authenticated regardless of the message or
     * transport. Used mainly for debugging or in situations that I wouldn't care to
     * comment on.
     */
    #define NULLSECURITY_POLICY_RULE    "NullSecurity"

    /**
     * SecurityPolicyRule for protocol message "blob" signing.
     *
     * Allows the message issuer to be authenticated using a non-XML digital signature
     * over the message body. The transport layer is not considered.
     */
    #define SIMPLESIGNING_POLICY_RULE   "SimpleSigning"

    /**
     * SecurityPolicyRule for protocol message XML signing.
     *
     * Allows the message issuer to be authenticated using an XML digital signature
     * over the message. The transport layer is not considered.
     */
    #define XMLSIGNING_POLICY_RULE      "XMLSigning"

    /**
     * SecurityPolicyRule for SAML 1.x Browser SSO profile validation.
     *
     * Enforces presence of time conditions and proper subject confirmation.
     */
    #define SAML1BROWSERSSO_POLICY_RULE "SAML1BrowserSSO"

    /**
     * SecurityPolicyRule for SAML 2.0 bearer SubjectConfirmation.
     *
     * <p>Optionally enforces message delivery requirements based on SubjectConfirmationData.
     *
     * <p>The XML attributes "checkValidity", "checkRecipient", and "checkCorrelation" can be set
     * "false" to disable checks of NotBefore/NotOnOrAfter, Recipient, and InResponseTo confirmation
     * data respectively.
     */
    #define BEARER_POLICY_RULE "Bearer"
};

#endif /* __saml_secrule_h__ */
