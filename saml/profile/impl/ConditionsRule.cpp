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
 * ConditionsRule.cpp
 *
 * SAML Conditions SecurityPolicyRule.
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/SecurityPolicy.h"
#include "binding/SecurityPolicyRule.h"
#include "saml1/core/Assertions.h"
#include "saml2/core/Assertions.h"

#include <boost/ptr_container/ptr_vector.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/ParserPool.h>

using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace opensaml {
    class SAML_DLLLOCAL ConditionsRule : public SecurityPolicyRule
    {
    public:
        ConditionsRule(const DOMElement* e, bool deprecationSupport=true);

        virtual ~ConditionsRule() {
            if (m_doc)
                m_doc->release();
        }
        const char* getType() const {
            return CONDITIONS_POLICY_RULE;
        }
        bool evaluate(const XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const;

    private:
        DOMDocument* m_doc;
        ptr_vector<SecurityPolicyRule> m_rules;
    };

    SecurityPolicyRule* SAML_DLLLOCAL ConditionsRuleFactory(const DOMElement* const & e, bool deprecationSupport)
    {
        return new ConditionsRule(e, deprecationSupport);
    }

    static const XMLCh Rule[] =     UNICODE_LITERAL_10(P,o,l,i,c,y,R,u,l,e);
    static const XMLCh type[] =     UNICODE_LITERAL_4(t,y,p,e);

    const char config[] =
        "<PolicyRule type=\"Conditions\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\">"
            "<PolicyRule type=\"Audience\"/>"
            "<PolicyRule type=\"Ignore\">saml:DoNotCacheCondition</PolicyRule>"
            "<PolicyRule type=\"Ignore\">saml2:OneTimeUse</PolicyRule>"
            "<PolicyRule type=\"Ignore\">saml2:ProxyRestriction</PolicyRule>"
        "</PolicyRule>";
};

ConditionsRule::ConditionsRule(const DOMElement* e, bool deprecationSupport) : SecurityPolicyRule(e), m_doc(nullptr)
{
    Category& log=Category::getInstance(SAML_LOGCAT ".SecurityPolicyRule.Conditions");

    if (!e || !e->hasChildNodes()) {
        // Default the configuration.
        istringstream in(config);
        m_doc = XMLToolingConfig::getConfig().getParser().parse(in);
        e = m_doc->getDocumentElement();
    }

    e = XMLHelper::getFirstChildElement(e, Rule);
    while (e) {
        string t = XMLHelper::getAttrString(e, nullptr, type);
        if (!t.empty()) {
            try {
                log.info("building SecurityPolicyRule of type %s", t.c_str());
                m_rules.push_back(SAMLConfig::getConfig().SecurityPolicyRuleManager.newPlugin(t.c_str(), e, deprecationSupport));
            }
            catch (std::exception& ex) {
                log.crit("error building SecurityPolicyRule: %s", ex.what());
            }
        }
        e = XMLHelper::getNextSiblingElement(e, Rule);
    }
}

bool ConditionsRule::evaluate(const XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const
{
    if (!SecurityPolicyRule::evaluate(message, request, policy)) {
        return false;
    }

    const saml2::Assertion* a2=dynamic_cast<const saml2::Assertion*>(&message);
    if (a2) {
        const saml2::Conditions* conds = a2->getConditions();
        if (!conds)
            return true;

        // First verify the time conditions, using the specified timestamp.
        time_t now = policy.getTime();
        unsigned int skew = XMLToolingConfig::getConfig().clock_skew_secs;
        time_t t = conds->getNotBeforeEpoch();
        if (now + skew < t)
            throw SecurityPolicyException("Assertion is not yet valid.");
        t = conds->getNotOnOrAfterEpoch();
        if (t <= now - skew)
            throw SecurityPolicyException("Assertion is no longer valid.");

        // Now we process conditions, starting with the known types and then extensions.

        bool valid;

        const vector<saml2::AudienceRestriction*>& acvec = conds->getAudienceRestrictions();
        for (vector<saml2::AudienceRestriction*>::const_iterator ac = acvec.begin(); ac != acvec.end(); ++ac) {
            valid = false;
            for (ptr_vector<SecurityPolicyRule>::const_iterator r = m_rules.begin(); !valid && r != m_rules.end(); ++r)
                valid = r->evaluate(*(*ac), request, policy);
            if (!valid)
                throw SecurityPolicyException("AudienceRestriction condition not successfully validated by policy.");
        }

        const vector<saml2::OneTimeUse*>& otvec = conds->getOneTimeUses();
        for (vector<saml2::OneTimeUse*>::const_iterator ot = otvec.begin(); ot!=otvec.end(); ++ot) {
            valid = false;
            for (ptr_vector<SecurityPolicyRule>::const_iterator r = m_rules.begin(); !valid && r != m_rules.end(); ++r)
                valid = r->evaluate(*(*ot), request, policy);
            if (!valid)
                throw SecurityPolicyException("OneTimeUse condition not successfully validated by policy.");
        }

        const vector<saml2::ProxyRestriction*> pvec = conds->getProxyRestrictions();
        for (vector<saml2::ProxyRestriction*>::const_iterator p = pvec.begin(); p != pvec.end(); ++p) {
            valid = false;
            for (ptr_vector<SecurityPolicyRule>::const_iterator r = m_rules.begin(); !valid && r != m_rules.end(); ++r)
                valid = r->evaluate(*(*p), request, policy);
            if (!valid)
                throw SecurityPolicyException("ProxyRestriction condition not successfully validated by policy.");
        }

        const vector<saml2::Condition*>& convec = conds->getConditions();
        for (vector<saml2::Condition*>::const_iterator c = convec.begin(); c != convec.end(); ++c) {
            valid = false;
            for (ptr_vector<SecurityPolicyRule>::const_iterator r = m_rules.begin(); !valid && r != m_rules.end(); ++r)
                valid = r->evaluate(*(*c), request, policy);
            if (!valid) {
                throw SecurityPolicyException(
                    "Extension condition ($1) not successfully validated by policy.",
                    params(1,((*c)->getSchemaType() ? (*c)->getSchemaType()->toString().c_str() : "Unknown Type"))
                    );
            }
        }

        return true;
    }

    const saml1::Assertion* a1=dynamic_cast<const saml1::Assertion*>(&message);
    if (a1) {
        const saml1::Conditions* conds = a1->getConditions();
        if (!conds)
            return true;

        // First verify the time conditions, using the specified timestamp.
        time_t now = policy.getTime();
        unsigned int skew = XMLToolingConfig::getConfig().clock_skew_secs;
        time_t t = conds->getNotBeforeEpoch();
        if (now + skew < t)
            throw SecurityPolicyException("Assertion is not yet valid.");
        t = conds->getNotOnOrAfterEpoch();
        if (t <= now - skew)
            throw SecurityPolicyException("Assertion is no longer valid.");

        // Now we process conditions, starting with the known types and then extensions.

        bool valid;

        const vector<saml1::AudienceRestrictionCondition*>& acvec = conds->getAudienceRestrictionConditions();
        for (vector<saml1::AudienceRestrictionCondition*>::const_iterator ac = acvec.begin(); ac != acvec.end(); ++ac) {
            valid = false;
            for (ptr_vector<SecurityPolicyRule>::const_iterator r = m_rules.begin(); !valid && r != m_rules.end(); ++r)
                valid = r->evaluate(*(*ac), request, policy);
            if (!valid)
                throw SecurityPolicyException("AudienceRestrictionCondition not successfully validated by policy.");
        }

        const vector<saml1::DoNotCacheCondition*>& dncvec = conds->getDoNotCacheConditions();
        for (vector<saml1::DoNotCacheCondition*>::const_iterator dnc = dncvec.begin(); dnc != dncvec.end(); ++dnc) {
            valid = false;
            for (ptr_vector<SecurityPolicyRule>::const_iterator r = m_rules.begin(); !valid && r != m_rules.end(); ++r)
                valid = r->evaluate(*(*dnc), request, policy);
            if (!valid)
                throw SecurityPolicyException("DoNotCacheCondition not successfully validated by policy.");
        }

        const vector<saml1::Condition*>& convec = conds->getConditions();
        for (vector<saml1::Condition*>::const_iterator c = convec.begin(); c != convec.end(); ++c) {
            valid = false;
            for (ptr_vector<SecurityPolicyRule>::const_iterator r = m_rules.begin(); !valid && r != m_rules.end(); ++r)
                valid = r->evaluate(*(*c), request, policy);
            if (!valid) {
                throw SecurityPolicyException(
                    "Extension condition ($1) not successfully validated by policy.",
                    params(1,((*c)->getSchemaType() ? (*c)->getSchemaType()->toString().c_str() : (*c)->getElementQName().toString().c_str()))
                    );
            }
        }

        return true;
    }

    return false;
}
