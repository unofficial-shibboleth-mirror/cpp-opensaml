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
 * @file saml/binding/MessageFlowRule.h
 * 
 * SAML replay and freshness checking SecurityPolicyRule
 */

#ifndef __saml_flowrule_h__
#define __saml_flowrule_h__

#include <saml/binding/SecurityPolicyRule.h>


namespace opensaml {
    /**
     * SAML replay and freshness checking SecurityPolicyRule
     * 
     * Some form of message rule to extract ID and timestamp must be
     * run prior to this rule.
     */
    class SAML_API MessageFlowRule : public SecurityPolicyRule
    {
    public:
        MessageFlowRule(const DOMElement* e);
        virtual ~MessageFlowRule() {}
        
        void evaluate(const xmltooling::XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const;

        /**
         * Controls whether rule executes replay checking.
         * 
         * @param checkReplay  replay checking value to set
         */
        void setCheckReplay(bool checkReplay) {
            m_checkReplay = checkReplay;
        }
    
        /**
         * Controls maximum elapsed time between message issue and rule execution.
         * 
         * @param expires  maximum elapsed time in seconds
         */
        void setExpires(time_t expires) {
            m_expires = expires;
        }
    
    private:
        bool m_checkReplay;
        time_t m_expires;
    };
    
};

#endif /* __saml_flowrule_h__ */
