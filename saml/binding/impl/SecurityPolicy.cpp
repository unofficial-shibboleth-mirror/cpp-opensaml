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
 * SecurityPolicy.cpp
 *
 * Overall policy used to verify the security of an incoming message.
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/SecurityPolicy.h"
#include "binding/SecurityPolicyRule.h"
#include "saml2/core/Assertions.h"

#include <boost/bind.hpp>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace opensaml::saml2md;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace opensaml {
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,string,const DOMElement*>::Factory AudienceRestrictionRuleFactory;
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,string,const DOMElement*>::Factory ClientCertAuthRuleFactory;
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,string,const DOMElement*>::Factory ConditionsRuleFactory;
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,string,const DOMElement*>::Factory IgnoreRuleFactory;
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,string,const DOMElement*>::Factory MessageFlowRuleFactory;
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,string,const DOMElement*>::Factory NullSecurityRuleFactory;
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,string,const DOMElement*>::Factory SimpleSigningRuleFactory;
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,string,const DOMElement*>::Factory XMLSigningRuleFactory;

    namespace saml1 {
        SAML_DLLLOCAL PluginManager<SecurityPolicyRule,string,const DOMElement*>::Factory BrowserSSORuleFactory;
    }

    namespace saml2 {
        SAML_DLLLOCAL PluginManager<SecurityPolicyRule,string,const DOMElement*>::Factory BearerConfirmationRuleFactory;
        SAML_DLLLOCAL PluginManager<SecurityPolicyRule,string,const DOMElement*>::Factory DelegationRestrictionRuleFactory;
    }
};

void SAML_API opensaml::registerSecurityPolicyRules()
{
    SAMLConfig& conf=SAMLConfig::getConfig();
    conf.SecurityPolicyRuleManager.registerFactory(AUDIENCE_POLICY_RULE, AudienceRestrictionRuleFactory);
    conf.SecurityPolicyRuleManager.registerFactory(CLIENTCERTAUTH_POLICY_RULE, ClientCertAuthRuleFactory);
    conf.SecurityPolicyRuleManager.registerFactory(CONDITIONS_POLICY_RULE, ConditionsRuleFactory);
    conf.SecurityPolicyRuleManager.registerFactory(IGNORE_POLICY_RULE, IgnoreRuleFactory);
    conf.SecurityPolicyRuleManager.registerFactory(MESSAGEFLOW_POLICY_RULE, MessageFlowRuleFactory);
    conf.SecurityPolicyRuleManager.registerFactory(NULLSECURITY_POLICY_RULE, NullSecurityRuleFactory);
    conf.SecurityPolicyRuleManager.registerFactory(SIMPLESIGNING_POLICY_RULE, SimpleSigningRuleFactory);
    conf.SecurityPolicyRuleManager.registerFactory(XMLSIGNING_POLICY_RULE, XMLSigningRuleFactory);
    conf.SecurityPolicyRuleManager.registerFactory(SAML1BROWSERSSO_POLICY_RULE, saml1::BrowserSSORuleFactory);
    conf.SecurityPolicyRuleManager.registerFactory(BEARER_POLICY_RULE, saml2::BearerConfirmationRuleFactory);
    conf.SecurityPolicyRuleManager.registerFactory(DELEGATION_POLICY_RULE, saml2::DelegationRestrictionRuleFactory);
}

SecurityPolicyRule::SecurityPolicyRule()
{
}

SecurityPolicyRule::~SecurityPolicyRule()
{
}

SecurityPolicy::SecurityPolicy(
    const saml2md::MetadataProvider* metadataProvider,
    const xmltooling::QName* role,
    const xmltooling::TrustEngine* trustEngine,
    bool validate
    ) : m_metadataCriteria(nullptr),
        m_issueInstant(0),
        m_issuerRole(nullptr),
        m_authenticated(false),
        m_metadata(metadataProvider),
        m_role(role ? new xmltooling::QName(*role) : nullptr),
        m_trust(trustEngine),
        m_validate(validate),
        m_entityOnly(true),
        m_ts(0)
{
}

SecurityPolicy::~SecurityPolicy()
{
    delete m_metadataCriteria;
}

const MetadataProvider* SecurityPolicy::getMetadataProvider() const
{
    return m_metadata;
}

MetadataProvider::Criteria& SecurityPolicy::getMetadataProviderCriteria() const
{
    if (!m_metadataCriteria)
        m_metadataCriteria=new MetadataProvider::Criteria();
    else
        m_metadataCriteria->reset();
    return *m_metadataCriteria;
}

const xmltooling::QName* SecurityPolicy::getRole() const
{
    return m_role.get();
}

const TrustEngine* SecurityPolicy::getTrustEngine() const
{
    return m_trust;
}

bool SecurityPolicy::getValidating() const
{
    return m_validate;
}

bool SecurityPolicy::requireEntityIssuer() const
{
    return m_entityOnly;
}

const vector<xstring>& SecurityPolicy::getAudiences() const
{
    return m_audiences;
}

vector<xstring>& SecurityPolicy::getAudiences()
{
    return m_audiences;
}

time_t SecurityPolicy::getTime() const
{
    if (m_ts == 0)
        return m_ts = time(nullptr);
    return m_ts;
}

const XMLCh* SecurityPolicy::getCorrelationID() const
{
    return m_correlationID.c_str();
}

const XMLCh* SecurityPolicy::getInResponseTo() const
{
    return m_inResponseTo.c_str();
}

vector<const SecurityPolicyRule*>& SecurityPolicy::getRules()
{
    return m_rules;
}

void SecurityPolicy::setMetadataProvider(const MetadataProvider* metadata)
{
    m_metadata = metadata;
}

void SecurityPolicy::setMetadataProviderCriteria(MetadataProvider::Criteria* criteria)
{
    if (m_metadataCriteria)
        delete m_metadataCriteria;
    m_metadataCriteria=criteria;
}

void SecurityPolicy::setRole(const xmltooling::QName* role)
{
    m_role.reset(role ? new xmltooling::QName(*role) : nullptr);
}

void SecurityPolicy::setTrustEngine(const TrustEngine* trust)
{
    m_trust = trust;
}

void SecurityPolicy::setValidating(bool validate)
{
    m_validate = validate;
}

void SecurityPolicy::requireEntityIssuer(bool entityOnly)
{
    m_entityOnly = entityOnly;
}

void SecurityPolicy::setTime(time_t ts)
{
    m_ts = ts;
}

void SecurityPolicy::setCorrelationID(const XMLCh* correlationID)
{
    m_correlationID.erase();
    if (correlationID)
        m_correlationID = correlationID;
}

void SecurityPolicy::setInResponseTo(const XMLCh* id)
{
    m_inResponseTo.erase();
    if (id)
        m_inResponseTo = id;
}

void SecurityPolicy::evaluate(const XMLObject& message, const GenericRequest* request)
{
    for_each(
        m_rules.begin(), m_rules.end(),
        boost::bind(&SecurityPolicyRule::evaluate, _1, boost::ref(message), request, boost::ref(*this))
        );
}

void SecurityPolicy::reset(bool messageOnly)
{
    _reset(messageOnly);
}

void SecurityPolicy::_reset(bool messageOnly)
{
    m_messageID.erase();
    m_issueInstant=0;
    if (!messageOnly) {
        m_issuer.reset();
        m_issuerRole=nullptr;
        m_authenticated=false;
    }
}

const XMLCh* SecurityPolicy::getMessageID() const
{
    return m_messageID.c_str();
}

time_t SecurityPolicy::getIssueInstant() const
{
    return m_issueInstant;
}

const Issuer* SecurityPolicy::getIssuer() const
{
    return m_issuer.get();
}

const RoleDescriptor* SecurityPolicy::getIssuerMetadata() const
{
    return m_issuerRole;
}

bool SecurityPolicy::isAuthenticated() const
{
    return m_authenticated;
}

void SecurityPolicy::setMessageID(const XMLCh* id)
{
    m_messageID.erase();
    if (id)
        m_messageID = id;
}

void SecurityPolicy::setIssueInstant(time_t issueInstant)
{
    m_issueInstant = issueInstant;
}

void SecurityPolicy::setIssuer(const Issuer* issuer)
{
    if (!getIssuerMatchingPolicy().issuerMatches(m_issuer.get(), issuer))
        throw SecurityPolicyException("An Issuer was supplied that conflicts with previous results.");

    if (!m_issuer.get()) {
        if (m_entityOnly && issuer->getFormat() && !XMLString::equals(issuer->getFormat(), NameIDType::ENTITY))
            throw SecurityPolicyException("A non-entity Issuer was supplied, violating policy.");
        m_issuerRole = nullptr;
        m_issuer.reset(issuer->cloneIssuer());
    }
}

void SecurityPolicy::setIssuer(const XMLCh* issuer)
{
    if (!getIssuerMatchingPolicy().issuerMatches(m_issuer.get(), issuer))
        throw SecurityPolicyException("An Issuer was supplied that conflicts with previous results.");

    if (!m_issuer.get() && issuer && *issuer) {
        m_issuerRole = nullptr;
        m_issuer.reset(IssuerBuilder::buildIssuer());
        m_issuer->setName(issuer);
    }
}

void SecurityPolicy::setIssuerMetadata(const RoleDescriptor* issuerRole)
{
    if (issuerRole && m_issuerRole && issuerRole!=m_issuerRole)
        throw SecurityPolicyException("A rule supplied a RoleDescriptor that conflicts with previous results.");
    m_issuerRole = issuerRole;
}

void SecurityPolicy::setAuthenticated(bool auth)
{
    m_authenticated = auth;
}

SecurityPolicy::IssuerMatchingPolicy::IssuerMatchingPolicy()
{
}

SecurityPolicy::IssuerMatchingPolicy::~IssuerMatchingPolicy()
{
}

bool SecurityPolicy::IssuerMatchingPolicy::issuerMatches(const Issuer* issuer1, const Issuer* issuer2) const
{
    // nullptr matches anything for the purposes of this interface.
    if (!issuer1 || !issuer2)
        return true;

    const XMLCh* op1=issuer1->getName();
    const XMLCh* op2=issuer2->getName();
    if (!op1 || !op2 || !XMLString::equals(op1,op2))
        return false;

    op1=issuer1->getFormat();
    op2=issuer2->getFormat();
    if (!XMLString::equals(op1 ? op1 : NameIDType::ENTITY, op2 ? op2 : NameIDType::ENTITY))
        return false;

    op1=issuer1->getNameQualifier();
    op2=issuer2->getNameQualifier();
    if (!XMLString::equals(op1 ? op1 : &chNull, op2 ? op2 : &chNull))
        return false;

    op1=issuer1->getSPNameQualifier();
    op2=issuer2->getSPNameQualifier();
    if (!XMLString::equals(op1 ? op1 : &chNull, op2 ? op2 : &chNull))
        return false;

    return true;
}

bool SecurityPolicy::IssuerMatchingPolicy::issuerMatches(const Issuer* issuer1, const XMLCh* issuer2) const
{
    // nullptr matches anything for the purposes of this interface.
    if (!issuer1 || !issuer2 || !*issuer2)
        return true;

    const XMLCh* op1=issuer1->getName();
    if (!op1 || !XMLString::equals(op1,issuer2))
        return false;

    op1=issuer1->getFormat();
    if (op1 && *op1 && !XMLString::equals(op1, NameIDType::ENTITY))
        return false;

    op1=issuer1->getNameQualifier();
    if (op1 && *op1)
        return false;

    op1=issuer1->getSPNameQualifier();
    if (op1 && *op1)
        return false;

    return true;
}

SecurityPolicy::IssuerMatchingPolicy SecurityPolicy::m_defaultMatching;

const SecurityPolicy::IssuerMatchingPolicy& SecurityPolicy::getIssuerMatchingPolicy() const
{
    return m_matchingPolicy.get() ? *m_matchingPolicy.get() : m_defaultMatching;
}

void SecurityPolicy::setIssuerMatchingPolicy(IssuerMatchingPolicy* matchingPolicy)
{
    m_matchingPolicy.reset(matchingPolicy);
}
