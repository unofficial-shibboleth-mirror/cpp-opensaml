/*
 *  Copyright 2001-2009 Internet2
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
 * @file saml/signature/SignatureProfileValidator.h
 * 
 * SAML-specific signature profile validator.
 */

#ifndef __saml_sigval_h__
#define __saml_sigval_h__

#include <saml/base.h>
#include <xmltooling/validation/Validator.h>

namespace xmlsignature {
    class XMLTOOL_API Signature;
};

namespace opensaml {

    /**
     * SAML-specific signature profile validator.
     */
    class SAML_API SignatureProfileValidator : public virtual xmltooling::Validator
    {
    public:
        SignatureProfileValidator();
        virtual ~SignatureProfileValidator();

        void validate(const xmltooling::XMLObject* xmlObject) const;
        
        /**
         * Type-safe validation method.
         *
         * @param signature Signature to validate
         */
        void validateSignature(const xmlsignature::Signature& signature) const;
    };

};

#endif /* __saml_sigval_h__ */
