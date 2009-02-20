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
 * @file saml/saml2/profile/BrowserSSOProfileValidator.h
 *
 * SAML 2.0 Browser SSO Profile Assertion Validator
 */

#ifndef __saml2_ssoval_h__
#define __saml2_ssoval_h__

#include <saml/saml2/profile/AssertionValidator.h>

namespace opensaml {

    namespace saml2 {

        /**
         * @deprecated
         * SAML 2.0 Browser SSO Profile Assertion Validator
         *
         * <p>In addition to standard core requirements for validity, SSO assertions
         * <strong>MUST</strong> have NotBefore/NotOnOrAfter attributes and each subject statement
         * <strong>MUST</strong> be confirmable via bearer method.
         */
        class SAML_API BrowserSSOProfileValidator : public AssertionValidator
        {
        public:
            /**
             * Constructor
             *
             * @param recipient     name of assertion recipient (implicit audience)
             * @param audiences     additional audience values
             * @param ts            timestamp to evaluate assertion conditions, or 0 to bypass check
             * @param destination   server location to which assertion was delivered, or 0 to bypass check
             * @param requestID     ID of request that resulted in assertion, or NULL if unsolicited
             */
            BrowserSSOProfileValidator(
                const XMLCh* recipient,
                const std::vector<const XMLCh*>* audiences=NULL,
                time_t ts=0,
                const char* destination=NULL,
                const char* requestID=NULL
                ) : AssertionValidator(recipient, audiences, ts), m_destination(destination), m_requestID(requestID) {
            }
            virtual ~BrowserSSOProfileValidator() {}

            void validateAssertion(const Assertion& assertion) const;

            /**
             * Return address information from the confirmed bearer SubjectConfirmation, if any.
             *
             * @return  address information
             */
            const char* getAddress() const {
                return m_address.c_str();
            }

        protected:
            /** Server location to which assertion was delivered. */
            xmltooling::auto_ptr_XMLCh m_destination;

            /** ID of request that resulted in assertions. */
            xmltooling::auto_ptr_XMLCh m_requestID;

        private:
            /** Address in confirmed bearer SubjectConfirmationData. */
            mutable std::string m_address;
        };

    };
};

#endif /* __saml2_ssoval_h__ */
