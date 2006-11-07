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
 * @file saml/binding/MessageRoutingRule.h
 * 
 * Routing rule that enforces message delivery to an intended destination
 */

#include <saml/binding/SecurityPolicyRule.h>


namespace opensaml {
    /**
     * Routing rule that enforces message delivery to an intended destination
     * 
     * Subclasses can provide support for additional message types
     * by overriding the destination derivation method.
     */
    class SAML_API MessageRoutingRule : public SecurityPolicyRule
    {
    public:
        /**
         * Constructor.
         * 
         * If an XML attribute named mandatory is set to "true" or "1", then
         * a destination address <strong>MUST</strong> be present in the message.
         * 
         * @param e DOM tree to initialize rule
         */
        MessageRoutingRule(const DOMElement* e);
        virtual ~MessageRoutingRule() {}
        
        std::pair<saml2::Issuer*,const saml2md::RoleDescriptor*> evaluate(
            const GenericRequest& request,
            const xmltooling::XMLObject& message,
            const saml2md::MetadataProvider* metadataProvider,
            const xmltooling::QName* role,
            const TrustEngine* trustEngine
            ) const;
    
    protected:
        /**
         * Examines the message and/or its contents and extracts the destination
         * address/URL, if specified. 
         * 
         * @param message       message to examine
         * @return  the destination address/URL, or NULL
         */
        virtual const XMLCh* getDestination(const xmltooling::XMLObject& message) const;

    private:
        bool m_mandatory;
    };
    
};
