/*
 *  Copyright 2009 Internet2
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
 * SAML1BrowserSSORule.cpp
 *
 * SAML 1.x Browser SSO Profile SecurityPolicyRule
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/SecurityPolicyRule.h"
#include "saml1/core/Assertions.h"

#include <xmltooling/logging.h>

using namespace opensaml::saml1;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml1 {

        class SAML_DLLLOCAL BrowserSSORule : public opensaml::SecurityPolicyRule
        {
        public:
            BrowserSSORule() {}
            virtual ~BrowserSSORule() {}

            const char* getType() const {
                return SAML1BROWSERSSO_POLICY_RULE;
            }

            bool evaluate(const XMLObject& message, const GenericRequest* request, opensaml::SecurityPolicy& policy) const;
        };

        opensaml::SecurityPolicyRule* SAML_DLLLOCAL BrowserSSORuleFactory(const DOMElement* const &)
        {
            return new BrowserSSORule();
        }

        class SAML_DLLLOCAL _checkMethod : public unary_function<const SubjectStatement*,void>,
            public unary_function<const ConfirmationMethod*,bool>
        {
        public:
            void operator()(const SubjectStatement* s) const {
                const Subject* sub = s->getSubject();
                if (s) {
                    const SubjectConfirmation* sc = sub->getSubjectConfirmation();
                    if (sc) {
                        const vector<ConfirmationMethod*>& methods = sc->getConfirmationMethods();
                        if (find_if(methods.begin(), methods.end(), _checkMethod())!=methods.end())
                            return;     // methods checked out
                    }
                }
                throw SecurityPolicyException("Assertion contained a statement without a supported ConfirmationMethod.");
            }

            bool operator()(const ConfirmationMethod* cm) const {
                const XMLCh* m = cm->getMethod();
                return (XMLString::equals(m,SubjectConfirmation::BEARER) ||
                    XMLString::equals(m,SubjectConfirmation::ARTIFACT) ||
                    XMLString::equals(m,SubjectConfirmation::ARTIFACT01));
            }
        };
    };
};

bool BrowserSSORule::evaluate(const XMLObject& message, const GenericRequest* request, opensaml::SecurityPolicy& policy) const
{
    const Assertion* a=dynamic_cast<const Assertion*>(&message);
    if (!a)
        return false;

    // Make sure the assertion is bounded.
    const Conditions* conds = a->getConditions();
    if (!conds || !conds->getNotBefore() || !conds->getNotOnOrAfter())
        throw SecurityPolicyException("Browser SSO assertions MUST contain NotBefore/NotOnOrAfter attributes.");

    // Each statement MUST have proper confirmation requirements.
    const vector<AuthenticationStatement*>& authn = a->getAuthenticationStatements();
    for_each(authn.begin(), authn.end(), _checkMethod());
    const vector<AttributeStatement*>& attr = a->getAttributeStatements();
    for_each(attr.begin(), attr.end(), _checkMethod());

    return true;
}
