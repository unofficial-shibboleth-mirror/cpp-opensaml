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
 * BrowserSSOProfileValidator.cpp
 * 
 * SAML 1.x Browser SSO Profile Assertion Validator
 */

#include "internal.h"
#include "saml1/core/Assertions.h"
#include "saml1/profile/BrowserSSOProfileValidator.h"

#include <log4cpp/Category.hh>
#include <xmltooling/util/NDC.h>

using namespace opensaml::saml1;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace {
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
            throw ValidationException("Assertion contained a statement without a supported ConfirmationMethod.");
        }

        bool operator()(const ConfirmationMethod* cm) const {
            const XMLCh* m = cm->getMethod();
            return (XMLString::equals(m,SubjectConfirmation::BEARER) ||
                XMLString::equals(m,SubjectConfirmation::ARTIFACT) ||
                XMLString::equals(m,SubjectConfirmation::ARTIFACT01));
        }
    };
};

void BrowserSSOProfileValidator::validateAssertion(const Assertion& assertion) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("validate");
#endif

    // Make sure the assertion is bounded.
    const Conditions* conds = assertion.getConditions();
    if (!conds || !conds->getNotBefore() || !conds->getNotOnOrAfter())
        throw ValidationException("SSO assertions MUST contain NotBefore/NotOnOrAfter attributes.");

    // Each statement MUST have proper confirmation requirements.
    const vector<AuthenticationStatement*>& authn = assertion.getAuthenticationStatements();
    for_each(authn.begin(), authn.end(), _checkMethod());
    const vector<AttributeStatement*>& attr = assertion.getAttributeStatements();
    for_each(attr.begin(), attr.end(), _checkMethod());
    const vector<SubjectStatement*>& sub = assertion.getSubjectStatements();
    for_each(sub.begin(), sub.end(), _checkMethod());

    // Pass up for additional checking.
    AssertionValidator::validateAssertion(assertion);
}
