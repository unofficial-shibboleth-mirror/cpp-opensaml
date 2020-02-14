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
 * BearerConfirmationRule.cpp
 *
 * SAML 2.0 Bearer SubjectConfirmation SecurityPolicyRule.
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/SecurityPolicyRule.h"
#include "saml2/core/Assertions.h"
#include "saml2/profile/SAML2AssertionPolicy.h"

#include <xercesc/util/XMLUniDefs.hpp>
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
            logging::Category& m_log;
            bool m_validity, m_recipient, m_correlation, m_blockUnsolicited, m_fatal;
        };

        opensaml::SecurityPolicyRule* SAML_DLLLOCAL BearerConfirmationRuleFactory(const DOMElement* const & e, bool)
        {
            return new BearerConfirmationRule(e);
        }
        
        static const XMLCh blockUnsolicited[] = UNICODE_LITERAL_16(b,l,o,c,k,U,n,s,o,l,i,c,i,t,e,d);
        static const XMLCh checkValidity[] =    UNICODE_LITERAL_13(c,h,e,c,k,V,a,l,i,d,i,t,y);
        static const XMLCh checkRecipient[] =   UNICODE_LITERAL_14(c,h,e,c,k,R,e,c,i,p,i,e,n,t);
        static const XMLCh checkCorrelation[] = UNICODE_LITERAL_16(c,h,e,c,k,C,o,r,r,e,l,a,t,i,o,n);
        static const XMLCh missingFatal[] =     UNICODE_LITERAL_12(m,i,s,s,i,n,g,F,a,t,a,l);
    };
};

BearerConfirmationRule::BearerConfirmationRule(const DOMElement* e) : SecurityPolicyRule(e),
    m_log(logging::Category::getInstance(SAML_LOGCAT ".SecurityPolicyRule.BearerConfirmation")),
    m_validity(XMLHelper::getAttrBool(e, true, checkValidity)),
    m_recipient(XMLHelper::getAttrBool(e, true, checkRecipient)),
    m_correlation(XMLHelper::getAttrBool(e, false, checkCorrelation)),
    m_blockUnsolicited(XMLHelper::getAttrBool(e, false, blockUnsolicited)),
    m_fatal(XMLHelper::getAttrBool(e, true, missingFatal))
{
    if (m_profiles.empty()) {
        m_profiles.insert(samlconstants::SAML20_PROFILE_SSO_BROWSER);
        m_profiles.insert(samlconstants::SAML20_PROFILE_SSO_ECP);
    }

    if (m_blockUnsolicited && !m_correlation) {
        m_correlation = true;
        m_log.info("enabling request/response correlation checking to block unsolicited responses");
    }
}

bool BearerConfirmationRule::evaluate(const XMLObject& message, const GenericRequest* request, opensaml::SecurityPolicy& policy) const
{
    if (!SecurityPolicyRule::evaluate(message, request, policy)) {
        return false;
    }

    const Assertion* a=dynamic_cast<const Assertion*>(&message);
    if (!a)
        return false;

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
                        if (!XMLString::equals(destination.get(), data ? data->getRecipient() : nullptr)) {
                            msg = "bearer confirmation failed with recipient mismatch";
                            continue;
                        }
                    }
                }

                if (m_correlation) {
                    if (policy.getCorrelationID() && *(policy.getCorrelationID())) {
                        if (XMLString::equals(policy.getCorrelationID(), data ? data->getInResponseTo() : nullptr)) {
                            m_log.debug("request/response correlation validated");
                        }
                        else {
                            msg = "bearer confirmation failed on lack of request/response correlation";
                            continue;
                        }
                    }
                    else if (data && data->getInResponseTo() && *(data->getInResponseTo())) {
                        msg = "bearer confirmation issued in response to request failed on lack of correlation ID";
                        continue;
                    }
                    else {
                        msg = "unsolicited bearer confirmation rejected by policy";
                        continue;
                    }
                }
                else {
                    m_log.debug("ignoring InResponseTo, correlation checking is disabled");
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
                m_log.debug("assertion satisfied bearer confirmation requirements");
                return true;
            }
        }
    }

    m_log.warn(msg ? msg : "no error message");
    if (m_fatal)
        throw SecurityPolicyException("Unable to locate satisfiable bearer SubjectConfirmation in assertion.");
    return false;
}
