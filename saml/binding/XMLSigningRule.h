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
 * @file saml/binding/XMLSigningRule.h
 * 
 * XML Signature checking SecurityPolicyRule
 */

#ifndef __saml_xmlsignrule_h__
#define __saml_xmlsignrule_h__

#include <saml/binding/SecurityPolicyRule.h>


namespace opensaml {
    /**
     * XML Signature checking SecurityPolicyRule
     */
    class SAML_API XMLSigningRule : public SecurityPolicyRule
    {
    public:
        XMLSigningRule(const DOMElement* e) {}
        virtual ~XMLSigningRule() {}
        
        void evaluate(const xmltooling::XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const;
    };
    
};

#endif /* __saml_xmlsignrule_h__ */
