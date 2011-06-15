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
 * @file saml/saml1/profile/BrowserSSOProfileValidator.h
 *
 * SAML 1.x Browser SSO Profile Assertion Validator.
 */

#ifndef __saml1_ssoval_h__
#define __saml1_ssoval_h__

#include <saml/saml1/profile/AssertionValidator.h>

namespace opensaml {
    namespace saml1 {

        /**
         * @deprecated
         * SAML 1.x Browser SSO Profile Assertion Validator
         *
         * <p>In addition to standard core requirements for validity, SSO assertions
         * <strong>MUST</strong> have NotBefore/NotOnOrAfter attributes and each subject statement
         * <strong>MUST</strong> be confirmable via bearer or artifact method.
         */
        class SAML_API BrowserSSOProfileValidator : public AssertionValidator
        {
        public:
            /**
             * Constructor
             *
             * @recipient       name of assertion recipient (implicit audience)
             * @param audiences additional audience values
             * @param ts        timestamp to evaluate assertion conditions, or 0 to bypass check
             */
            BrowserSSOProfileValidator(const XMLCh* recipient, const std::vector<const XMLCh*>* audiences=nullptr, time_t ts=0);

            virtual ~BrowserSSOProfileValidator();

            void validateAssertion(const Assertion& assertion) const;
        };

    };
};

#endif /* __saml1_ssoval_h__ */
