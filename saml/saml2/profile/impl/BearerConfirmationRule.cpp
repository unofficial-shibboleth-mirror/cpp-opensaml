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
 * BearerConfirmationRule.cpp
 *
 * SAML 2.0 Bearer SubjectConfirmation SecurityPolicyRule
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/SecurityPolicyRule.h"
#include "saml2/core/Assertions.h"
#include "saml2/profile/SAML2AssertionPolicy.h"

#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/io/HTTPRequest.h>

using namespace opensaml::saml2;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml2 {

        class SAML_DLLLOCAL BearerConfirmationRule : public opensaml::SecurityPolicyRule
        {
        public:
            BearerConfirmationRule(const DOMElement* e);

            virtual ~BearerConfirmationRule() {
            }
            const char* getType() const {
                return BEARER_POLICY_RULE;
            }
            bool evaluate(const XMLObject& message, const GenericRequest* request, opensaml::SecurityPolicy& policy) const;
        
        private:
            bool m_validity, m_recipient, m_correlation, m_fatal;
        };

        opensaml::SecurityPolicyRule* SAML_DLLLOCAL BearerConfirmationRuleFactory(const DOMElement* const & e)
        {
            return new BearerConfirmationRule(e);
        }
        
        static const XMLCh checkValidity[] =    UNICODE_LITERAL_13(c,h,e,c,k,V,a,l,i,d,i,t,y);
        static const XMLCh checkRecipient[] =   UNICODE_LITERAL_14(c,h,e,c,k,R,e,c,i,p,i,e,n,t);
        static const XMLCh checkCorrelation[] = UNICODE_LITERAL_16(c,h,e,c,k,C,o,r,r,e,l,a,t,i,o,n);
        static const XMLCh missingFatal[] =     UNICODE_LITERAL_12(m,i,s,s,i,n,g,F,a,t,a,l);
    };
};

BearerConfirmationRule::BearerConfirmationRule(const DOMElement* e) : m_validity(true), m_recipient(true), m_correlation(true), m_fatal(true)
{
    const XMLCh* flag = e ? e->getAttributeNS(NULL, checkValidity) : NULL;
    m_validity = (!flag || (*flag != chLatin_f && *flag != chDigit_0));
    flag = e ? e->getAttributeNS(NULL, checkRecipient) : NULL;
    m_recipient = (!flag || (*flag != chLatin_f && *flag != chDigit_0));
    flag = e ? e->getAttributeNS(NULL, checkCorrelation) : NULL;
    m_correlation = (!flag || (*flag != chLatin_f && *flag != chDigit_0));
    flag = e ? e->getAttributeNS(NULL, missingFatal) : NULL;
    m_fatal = (!flag || (*flag != chLatin_f && *flag != chDigit_0));
}

bool BearerConfirmationRule::evaluate(const XMLObject& message, const GenericRequest* request, opensaml::SecurityPolicy& policy) const
{
    const Assertion* a=dynamic_cast<const Assertion*>(&message);
    if (!a)
        return false;

    logging::Category& log = logging::Category::getInstance(SAML_LOGCAT".SecurityPolicyRule.BearerConfirmation");

    const char* msg="assertion is missing bearer SubjectConfirmation";
    const Subject* subject = a->getSubject();
    if (subject) {
        const vector<SubjectConfirmation*>& confs = subject->getSubjectConfirmations();
        for (vector<SubjectConfirmation*>::const_iterator sc = confs.begin(); sc!=confs.end(); ++sc) {
            if (XMLString::equals((*sc)->getMethod(), SubjectConfirmation::BEARER)) {

                const SubjectConfirmationDataType* data = dynamic_cast<const SubjectConfirmationDataType*>((*sc)->getSubjectConfirmationData());

                if (m_recipient) {
                    const HTTPRequest* httpRequest = dynamic_cast<const HTTPRequest*>(request);
                    if (httpRequest && httpRequest->getRequestURL()) {
                        string dest = httpRequest->getRequestURL();
                        auto_ptr_XMLCh destination(dest.substr(0,dest.find('?')).c_str());
                        if (!XMLString::equals(destination.get(), data ? data->getRecipient() : NULL)) {
                            msg = "bearer confirmation failed with recipient mismatch";
                            continue;
                        }
                    }
                }

                if (m_correlation && policy.getCorrelationID() && *(policy.getCorrelationID())) {
                    if (!XMLString::equals(policy.getCorrelationID(), data ? data->getInResponseTo() : NULL)) {
                        msg = "bearer confirmation failed with request correlation mismatch";
                        continue;
                    }
                }

                if (m_validity) {
                    if (!data || !data->getNotOnOrAfter()) {
                        msg = "bearer SubjectConfirmationData missing NotOnOrAfter attribute";
                        continue;
                    }
                    else if (data->getNotOnOrAfterEpoch() <= policy.getTime() - XMLToolingConfig::getConfig().clock_skew_secs) {
                        msg = "bearer confirmation has expired";
                        continue;
                    }

                    if (data && data->getNotBefore() && policy.getTime() + XMLToolingConfig::getConfig().clock_skew_secs < data->getNotBeforeEpoch()) {
                        msg = "bearer confirmation not yet valid";
                        continue;
                    }
                }

                SAML2AssertionPolicy* saml2policy = dynamic_cast<SAML2AssertionPolicy*>(&policy);
                if (saml2policy)
                    saml2policy->setSubjectConfirmation(*sc);
                log.debug("assertion satisfied bearer confirmation requirements");
                return true;
            }
        }
    }

    log.error(msg ? msg : "no error message");
    if (m_fatal)
        throw SecurityPolicyException("Unable to locate satisfiable bearer SubjectConfirmation in assertion.");
    return false;
}
