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
 * AssertionValidator.cpp
 * 
 * SAML 1.x basic assertion validator
 */

#include "internal.h"
#include "saml1/core/Assertions.h"
#include "saml1/profile/AssertionValidator.h"

#include <xmltooling/logging.h>
#include <xmltooling/util/NDC.h>

using namespace opensaml::saml1;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

void AssertionValidator::validate(const xmltooling::XMLObject* xmlObject) const
{
    const Assertion* a=dynamic_cast<const Assertion*>(xmlObject);
    if (!a)
        throw ValidationException("Validator only applies to SAML 1.x Assertion objects.");
    validateAssertion(*a);
}

void AssertionValidator::validateAssertion(const Assertion& assertion) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("validate");
#endif

    const Conditions* conds = assertion.getConditions();
    // First verify the time conditions, using the specified timestamp, if non-zero.
    if (m_ts>0 && conds) {
        unsigned int skew = XMLToolingConfig::getConfig().clock_skew_secs;
        time_t t=conds->getNotBeforeEpoch();
        if (m_ts+skew < t)
            throw ValidationException("Assertion is not yet valid.");
        t=conds->getNotOnOrAfterEpoch();
        if (t <= m_ts-skew)
            throw ValidationException("Assertion is no longer valid.");
    }

    // Now we process conditions, starting with the known types and then extensions.

    const vector<AudienceRestrictionCondition*>& acvec = conds->getAudienceRestrictionConditions();
    for (vector<AudienceRestrictionCondition*>::const_iterator ac = acvec.begin(); ac!=acvec.end(); ++ac)
        validateCondition(*ac);

    const vector<DoNotCacheCondition*>& dncvec = conds->getDoNotCacheConditions();
    for (vector<DoNotCacheCondition*>::const_iterator dnc = dncvec.begin(); dnc!=dncvec.end(); ++dnc) 
        validateCondition(*dnc);

    const vector<Condition*>& convec = conds->getConditions();
    for (vector<Condition*>::const_iterator c = convec.begin(); c!=convec.end(); ++c)
        validateCondition(*c);
}

void AssertionValidator::validateCondition(const Condition* c) const
{
    const AudienceRestrictionCondition* ac=dynamic_cast<const AudienceRestrictionCondition*>(c);
    if (!ac) {
        Category::getInstance(SAML_LOGCAT".AssertionValidator").error("unrecognized Condition in assertion (%s)",
            c->getSchemaType() ? c->getSchemaType()->toString().c_str() : c->getElementQName().toString().c_str());
        throw ValidationException("Assertion contains an unrecognized condition.");
    }

    bool found = false;
    const vector<Audience*>& auds1 = ac->getAudiences();
    for (vector<Audience*>::const_iterator a = auds1.begin(); !found && a!=auds1.end(); ++a) {
        for (vector<const XMLCh*>::const_iterator a2 = m_audiences.begin(); !found && a2!=m_audiences.end(); ++a2) {
            found = XMLString::equals((*a)->getAudienceURI(), *a2);
        }
    }

    if (!found) {
        ostringstream os;
        os << *ac;
        Category::getInstance(SAML_LOGCAT".AssertionValidator").error(
            "unacceptable AudienceRestrictionCondition in assertion (%s)", os.str().c_str()
            );
        throw ValidationException("Assertion contains an unacceptable AudienceRestrictionCondition.");
    }
}
