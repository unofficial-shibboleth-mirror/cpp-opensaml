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
 * MessageFlowRule.cpp
 *
 * SAML replay and freshness checking SecurityPolicyRule.
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/SecurityPolicy.h"
#include "binding/SecurityPolicyRule.h"

#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/ReplayCache.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    class SAML_DLLLOCAL MessageFlowRule : public SecurityPolicyRule
    {
    public:
        MessageFlowRule(const DOMElement* e);
        virtual ~MessageFlowRule() {}

        const char* getType() const {
            return MESSAGEFLOW_POLICY_RULE;
        }
        bool evaluate(const XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const;

    private:
        logging::Category& m_log;
        bool m_checkReplay, m_correlation, m_blockUnsolicited;
        time_t m_expires;
    };

    SecurityPolicyRule* SAML_DLLLOCAL MessageFlowRuleFactory(const DOMElement* const & e, bool)
    {
        return new MessageFlowRule(e);
    }

    static const XMLCh blockUnsolicited[] = UNICODE_LITERAL_16(b,l,o,c,k,U,n,s,o,l,i,c,i,t,e,d);
    static const XMLCh checkReplay[] =      UNICODE_LITERAL_11(c,h,e,c,k,R,e,p,l,a,y);
    static const XMLCh checkCorrelation[] = UNICODE_LITERAL_16(c,h,e,c,k,C,o,r,r,e,l,a,t,i,o,n);
    static const XMLCh expires[] =          UNICODE_LITERAL_7(e,x,p,i,r,e,s);
};

MessageFlowRule::MessageFlowRule(const DOMElement* e) : SecurityPolicyRule(e),
    m_log(logging::Category::getInstance(SAML_LOGCAT ".SecurityPolicyRule.MessageFlow")),
        m_checkReplay(XMLHelper::getAttrBool(e, true, checkReplay)),
        m_correlation(XMLHelper::getAttrBool(e, false, checkCorrelation)),
        m_blockUnsolicited(XMLHelper::getAttrBool(e, false, blockUnsolicited)),
        m_expires(XMLHelper::getAttrInt(e, XMLToolingConfig::getConfig().clock_skew_secs, expires))
{
    if (m_blockUnsolicited && !m_correlation) {
        m_correlation = true;
        m_log.info("enabling request/response correlation checking to block unsolicited responses");
    }
}

bool MessageFlowRule::evaluate(const XMLObject& message, const GenericRequest* request, SecurityPolicy& policy) const
{
    if (!SecurityPolicyRule::evaluate(message, request, policy)) {
        return false;
    }

    Category& log=Category::getInstance(SAML_LOGCAT ".SecurityPolicyRule.MessageFlow");
    log.debug("evaluating message flow policy (correlation %s, replay checking %s, expiration %lu)",
        m_correlation ? "on" : "off", m_checkReplay ? "on" : "off", m_expires);

    time_t now = policy.getTime();
    time_t skew = XMLToolingConfig::getConfig().clock_skew_secs;
    time_t issueInstant = policy.getIssueInstant();
    if (issueInstant == 0) {
        issueInstant = now;
    }
    else {
        if (issueInstant > now + skew) {
            log.warnStream() << "rejected not-yet-valid message, timestamp (" << issueInstant <<
                "), newest allowed (" << now + skew << ")" << logging::eol;
            throw SecurityPolicyException("Message rejected, was issued in the future.");
        }
        else if (issueInstant < now - skew - m_expires) {
            log.warnStream() << "rejected expired message, timestamp (" << issueInstant <<
                "), oldest allowed (" << (now - skew - m_expires) << ")" << logging::eol;
            throw SecurityPolicyException("Message expired, was issued too long ago.");
        }
    }

    if (m_correlation) {
        if (policy.getCorrelationID() && *(policy.getCorrelationID())) {
            if (XMLString::equals(policy.getCorrelationID(), policy.getInResponseTo())) {
                log.debug("request/response correlation validated");
            }
            else {
                auto_ptr_char requestID(policy.getCorrelationID());
                log.warn("response correlation ID did not match request ID (%s)", requestID.get());
                throw SecurityPolicyException("Rejecting non-correlated response to request ID.");
            }
        }
        else if (policy.getInResponseTo() && *(policy.getInResponseTo())) {
            log.warn("request/response correlation failed due to lack of request ID to compare");
            throw SecurityPolicyException("Response correlation failed with lack of correlation ID");
        }
        else if (m_blockUnsolicited) {
            log.warn("unsolicited response rejected by policy");
            throw SecurityPolicyException("Unsolicited response rejected by policy");
        }
    }
    else {
        log.debug("ignoring InResponseTo, correlation checking is disabled");
    }

    // Check replay.
    if (m_checkReplay) {
        const XMLCh* id = policy.getMessageID();
        if (!id || !*id)
            return false;

        ReplayCache* replayCache = XMLToolingConfig::getConfig().getReplayCache();
        if (!replayCache) {
            log.warn("no ReplayCache available, skipping requested replay check");
            return false;
        }

        auto_ptr_char temp(id);
        if (!replayCache->check("MessageFlow", temp.get(), issueInstant + skew + m_expires)) {
            log.error("replay detected of message ID (%s)", temp.get());
            throw SecurityPolicyException("Rejecting replayed message ID ($1).", params(1,temp.get()));
        }
        return true;
    }
    return false;
}
