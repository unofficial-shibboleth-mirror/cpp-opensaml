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
 * @file saml/saml1/profile/AssertionValidator.h
 * 
 * SAML 1.x basic assertion validator
 */

#ifndef __saml1_assval_h__
#define __saml1_assval_h__

#include <saml/base.h>
#include <xmltooling/validation/Validator.h>

namespace opensaml {
    namespace saml1 {
        
        class SAML_API Assertion;
        class SAML_API Condition;
        
        /**
         * SAML 1.x basic assertion validator provides time and audience condition checking.
         */
        class SAML_API AssertionValidator : public virtual xmltooling::Validator
        {
        public:
            /**
             * Constructor
             * 
             * @param recipient name of assertion recipient (implicit audience)
             * @param audiences additional audience values
             * @param ts        timestamp to evaluate assertion conditions, or 0 to bypass check
             */
            AssertionValidator(const XMLCh* recipient, const std::vector<const XMLCh*>* audiences=NULL, time_t ts=0)
                : m_recipient(recipient), m_audiences(audiences), m_ts(ts) {
            }

            virtual ~AssertionValidator() {}
    
            void validate(const xmltooling::XMLObject* xmlObject) const;

            /**
             * Type-safe validation method.
             * 
             * @param assertion assertion to validate
             */
            virtual void validateAssertion(const Assertion& assertion) const;

            /**
             * Condition validation.
             *
             * <p>The base class version only understands AudienceRestrictionConditions.
             * All other condition types will be rejected and require subclassing to
             * prevent validation failure.
             * 
             * @param condition condition to validate
             */
            virtual void validateCondition(const Condition* condition) const;

        protected:
            /** Name of recipient (implicit audience). */
            const XMLCh* m_recipient;
            
            /** Additional audience values. */
            const std::vector<const XMLCh*>* m_audiences;

            /** Timestamp to evaluate assertion conditions. */
            time_t m_ts;
        };
        
    };
};

#endif /* __saml1_assval_h__ */
