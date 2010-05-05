/*
 *  Copyright 2009-2010 Internet2
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
 * @file saml/saml2/profile/SAML2AssertionPolicy.h
 *
 * Policy subclass to track SAML 2.0 Assertion SubjectConfirmation.
 */

#ifndef __saml_saml2asspol_h__
#define __saml_saml2asspol_h__

#include <saml/binding/SecurityPolicy.h>

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

namespace opensaml {

    namespace saml2 {
        class SAML_API SubjectConfirmation;

        /**
         * Policy subclass to track SAML 2.0 Assertion SubjectConfirmation.
         */
        class SAML_API SAML2AssertionPolicy : virtual public SecurityPolicy
        {
        public:
            /**
             * Constructor for policy.
             *
             * @param metadataProvider  locked MetadataProvider instance
             * @param role              identifies the role (generally IdP or SP) of the policy peer
             * @param trustEngine       TrustEngine to authenticate policy peer
             * @param validate          true iff XML parsing should be done with validation
             */
            SAML2AssertionPolicy(
                const saml2md::MetadataProvider* metadataProvider=nullptr,
                const xmltooling::QName* role=nullptr,
                const xmltooling::TrustEngine* trustEngine=nullptr,
                bool validate=true
                );

            virtual ~SAML2AssertionPolicy();

            virtual void reset(bool messageOnly=false);
            void _reset(bool messageOnly=false);

            /**
             * Returns the subject confirmation that was successfully accepted by the policy.
             *
             * @return a successfully evaluated SubjectConfirmation
             */
            const saml2::SubjectConfirmation* getSubjectConfirmation() const;

            /**
             * Sets the SubjectConfirmation that was successfully accepted by the policy.
             *
             * <p>The lifetime of the SubjectConfirmation object <strong>MUST</strong> be longer
             * than the lifetime of the policy object.
             *
             * @param confirmation the successfully evaluated SubjectConfirmation
             */
            void setSubjectConfirmation(const saml2::SubjectConfirmation* confirmation);

        private:
            const saml2::SubjectConfirmation* m_confirmation;
        };
    };
};

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

#endif /* __saml_saml2asspol_h__ */
