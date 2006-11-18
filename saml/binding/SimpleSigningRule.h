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
 * @file saml/binding/SimpleSigningRule.h
 * 
 * Blob-oriented signature checking SecurityPolicyRule
 */

#include <saml/binding/SecurityPolicyRule.h>


namespace opensaml {
    /**
     * Blob-oriented signature checking SecurityPolicyRule for
     * bindings that support non-XML signature techniques.
     * 
     * Subclasses can provide support for additional message types
     * by overriding the issuer derivation method.
     */
    class SAML_API SimpleSigningRule : public SecurityPolicyRule
    {
    public:
        SimpleSigningRule(const DOMElement* e) {}
        virtual ~SimpleSigningRule() {}
        
        std::pair<saml2::Issuer*,const saml2md::RoleDescriptor*> evaluate(
            const GenericRequest& request,
            const xmltooling::XMLObject& message,
            const saml2md::MetadataProvider* metadataProvider,
            const xmltooling::QName* role,
            const xmltooling::TrustEngine* trustEngine
            ) const;
    
    protected:
        /**
         * Examines the message and/or its contents and extracts the issuer's claimed
         * identity along with a protocol identifier. The two together can be used to
         * locate metadata to use in validating the signature. Conventions may be needed
         * to properly encode non-SAML2 issuer information into a compatible form. 
         * 
         * <p>The caller is responsible for freeing the Issuer object.
         * 
         * @param message       message to examine
         * @return  a pair consisting of a SAML 2.0 Issuer object and a protocol constant.
         */
        virtual std::pair<saml2::Issuer*,const XMLCh*> getIssuerAndProtocol(const xmltooling::XMLObject& message) const;
    };
    
};
