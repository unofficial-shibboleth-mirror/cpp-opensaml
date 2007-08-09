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
 * @file saml/binding/SecurityPolicyRule.h
 * 
 * Policy rules that secure and authenticate bindings.
 */

#ifndef __saml_secrule_h__
#define __saml_secrule_h__

#include <saml/binding/SecurityPolicy.h>

namespace opensaml {
    
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
        SecurityPolicyRule() {}
    public:
        virtual ~SecurityPolicyRule() {}

        /**
         * Returns the rule's class/type.
         *
         * @return  the class/type of the object
         */
        virtual const char* getType() const=0;

        /**
         * Evaluates the rule against the given request and message.
         * 
         * <p>An exception will be raised if the message is invalid according to
         * a policy rule.
         * 
         * @param message   the incoming message
         * @param request   the protocol request
         * @param protocol  the protocol family in use
         * @param policy    SecurityPolicy to provide various components and track message data
         */
        virtual void evaluate(
            const xmltooling::XMLObject& message,
            const xmltooling::GenericRequest* request,
            const XMLCh* protocol,
            SecurityPolicy& policy
            ) const=0;
    };

    /**
     * Registers SecurityPolicyRule plugins into the runtime.
     */
    void SAML_API registerSecurityPolicyRules();

    /**
     * SecurityPolicyRule for processing SAML 1.x messages.
     * 
     * Extracts message ID, timestamp, and issuer information.
     */
    #define SAML1MESSAGE_POLICY_RULE  "SAML1Message"

    /**
     * SecurityPolicyRule for processing SAML 2.0 messages.
     * 
     * Extracts message ID, timestamp, and issuer information.
     */
    #define SAML2MESSAGE_POLICY_RULE  "SAML2Message"

    /**
     * SecurityPolicyRule for TLS client certificate authentication.
     * 
     * Evaluates client certificates against the issuer's metadata.
     */
    #define CLIENTCERTAUTH_POLICY_RULE  "ClientCertAuth"

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
    #define MESSAGEFLOW_POLICY_RULE  "MessageFlow"

    /**
     * SecurityPolicyRule for disabling security.
     * 
     * Allows the message issuer to be authenticated regardless of the message or
     * transport. Used mainly for debugging or in situations that I wouldn't care to
     * comment on.
     */
    #define NULLSECURITY_POLICY_RULE  "NullSecurity"

    /**
     * SecurityPolicyRule for protocol message "blob" signing.
     * 
     * Allows the message issuer to be authenticated using a non-XML digital signature
     * over the message body. The transport layer is not considered.
     */
    #define SIMPLESIGNING_POLICY_RULE  "SimpleSigning"

    /**
     * SecurityPolicyRule for protocol message XML signing.
     * 
     * Allows the message issuer to be authenticated using an XML digital signature
     * over the message. The transport layer is not considered.
     */
    #define XMLSIGNING_POLICY_RULE  "XMLSigning"
};

#endif /* __saml_secrule_h__ */
