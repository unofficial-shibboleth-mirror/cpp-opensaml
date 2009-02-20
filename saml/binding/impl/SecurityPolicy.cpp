/*
 *  Copyright 2001-2009 Internet2
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
 * SecurityPolicy.cpp
 *
 * Overall policy used to verify the security of an incoming message.
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/SecurityPolicyRule.h"
#include "saml2/core/Assertions.h"

using namespace opensaml::saml2md;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace xmltooling;
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
}

SecurityPolicy::IssuerMatchingPolicy SecurityPolicy::m_defaultMatching;

SecurityPolicy::SecurityPolicy(
    const saml2md::MetadataProvider* metadataProvider,
    const xmltooling::QName* role,
    const xmltooling::TrustEngine* trustEngine,
    bool validate
    ) : m_metadataCriteria(NULL),
        m_messageID(NULL),
        m_issueInstant(0),
        m_issuer(NULL),
        m_issuerRole(NULL),
        m_authenticated(false),
        m_matchingPolicy(NULL),
        m_metadata(metadataProvider),
        m_role(NULL),
        m_trust(trustEngine),
        m_validate(validate),
        m_entityOnly(true),
        m_ts(0)
{
    if (role)
        m_role = new xmltooling::QName(*role);
}

SecurityPolicy::~SecurityPolicy()
{
    XMLString::release(&m_messageID);
    delete m_metadataCriteria;
    delete m_issuer;
}

void SecurityPolicy::reset(bool messageOnly)
{
    _reset();
}

void SecurityPolicy::_reset(bool messageOnly)
{
    XMLString::release(&m_messageID);
    m_messageID=NULL;
    m_issueInstant=0;
    if (!messageOnly) {
        delete m_issuer;
        m_issuer=NULL;
        m_issuerRole=NULL;
        m_authenticated=false;
    }
}

MetadataProvider::Criteria& SecurityPolicy::getMetadataProviderCriteria() const
{
    if (!m_metadataCriteria)
        m_metadataCriteria=new MetadataProvider::Criteria();
    else
        m_metadataCriteria->reset();
    return *m_metadataCriteria;
}

void SecurityPolicy::setMetadataProviderCriteria(saml2md::MetadataProvider::Criteria* criteria)
{
    if (m_metadataCriteria)
        delete m_metadataCriteria;
    m_metadataCriteria=criteria;
}

void SecurityPolicy::evaluate(const XMLObject& message, const GenericRequest* request)
{
    for (vector<const SecurityPolicyRule*>::const_iterator i=m_rules.begin(); i!=m_rules.end(); ++i)
        (*i)->evaluate(message,request,*this);
}

void SecurityPolicy::setIssuer(const Issuer* issuer)
{
    if (!getIssuerMatchingPolicy().issuerMatches(m_issuer, issuer))
        throw SecurityPolicyException("An Issuer was supplied that conflicts with previous results.");

    if (!m_issuer) {
        if (m_entityOnly && issuer->getFormat() && !XMLString::equals(issuer->getFormat(), NameIDType::ENTITY))
            throw SecurityPolicyException("A non-entity Issuer was supplied, violating policy.");
        m_issuerRole = NULL;
        m_issuer=issuer->cloneIssuer();
    }
}

void SecurityPolicy::setIssuer(const XMLCh* issuer)
{
    if (!getIssuerMatchingPolicy().issuerMatches(m_issuer, issuer))
        throw SecurityPolicyException("An Issuer was supplied that conflicts with previous results.");

    if (!m_issuer && issuer && *issuer) {
        m_issuerRole = NULL;
        m_issuer = IssuerBuilder::buildIssuer();
        m_issuer->setName(issuer);
    }
}

void SecurityPolicy::setIssuerMetadata(const RoleDescriptor* issuerRole)
{
    if (issuerRole && m_issuerRole && issuerRole!=m_issuerRole)
        throw SecurityPolicyException("A rule supplied a RoleDescriptor that conflicts with previous results.");
    m_issuerRole=issuerRole;
}

bool SecurityPolicy::IssuerMatchingPolicy::issuerMatches(const Issuer* issuer1, const Issuer* issuer2) const
{
    // NULL matches anything for the purposes of this interface.
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
    // NULL matches anything for the purposes of this interface.
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
