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
 * @file saml/binding/MessageFlowRule.h
 * 
 * SAML replay and freshness checking SecurityPolicyRule
 */

#include <saml/binding/SecurityPolicyRule.h>


namespace opensaml {
    /**
     * SAML replay and freshness checking SecurityPolicyRule
     * 
     * Subclasses can provide support for additional message types
     * by overriding the main method and then calling the check method.
     */
    class SAML_API MessageFlowRule : public SecurityPolicyRule
    {
    public:
        MessageFlowRule(const DOMElement* e);
        virtual ~MessageFlowRule() {}
        
        std::pair<saml2::Issuer*,const saml2md::RoleDescriptor*> evaluate(
            const GenericRequest& request,
            const xmltooling::XMLObject& message,
            const saml2md::MetadataProvider* metadataProvider,
            const xmltooling::QName* role,
            const TrustEngine* trustEngine
            ) const;
    
    protected:
        /**
         * Performs the check.
         * 
         * @param id            message identifier
         * @param issueInstant  timestamp of protocol message
         * 
         * @exception BindingException  raised if a check fails  
         */
        void check(const XMLCh* id, time_t issueInstant) const;
    
    private:
        bool m_checkReplay;
        time_t m_expires;
    };
    
};
