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
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,const DOMElement*>::Factory ClientCertAuthRuleFactory;
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,const DOMElement*>::Factory MessageFlowRuleFactory;
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,const DOMElement*>::Factory SAML1MessageRuleFactory;
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,const DOMElement*>::Factory SAML2MessageRuleFactory;
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,const DOMElement*>::Factory SimpleSigningRuleFactory;
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,const DOMElement*>::Factory XMLSigningRuleFactory;
};

void SAML_API opensaml::registerSecurityPolicyRules()
{
    SAMLConfig& conf=SAMLConfig::getConfig();
    conf.SecurityPolicyRuleManager.registerFactory(CLIENTCERTAUTH_POLICY_RULE, ClientCertAuthRuleFactory);
    conf.SecurityPolicyRuleManager.registerFactory(MESSAGEFLOW_POLICY_RULE, MessageFlowRuleFactory);
    conf.SecurityPolicyRuleManager.registerFactory(SAML1MESSAGE_POLICY_RULE, SAML1MessageRuleFactory);
    conf.SecurityPolicyRuleManager.registerFactory(SAML2MESSAGE_POLICY_RULE, SAML2MessageRuleFactory);
    conf.SecurityPolicyRuleManager.registerFactory(SIMPLESIGNING_POLICY_RULE, SimpleSigningRuleFactory);
    conf.SecurityPolicyRuleManager.registerFactory(XMLSIGNING_POLICY_RULE, XMLSigningRuleFactory);
}

SecurityPolicy::IssuerMatchingPolicy SecurityPolicy::m_defaultMatching;

SecurityPolicy::~SecurityPolicy()
{
    reset();
}

void SecurityPolicy::reset()
{
    delete m_messageQName;
    XMLString::release(&m_messageID);
    delete m_issuer;
    m_messageQName=NULL;
    m_messageID=NULL;
    m_issueInstant=0;
    m_issuer=NULL;
    m_issuerRole=NULL;
    m_secure=false;
}

void SecurityPolicy::evaluate(const XMLObject& message, const GenericRequest* request)
{
    for (vector<const SecurityPolicyRule*>::const_iterator i=m_rules.begin(); i!=m_rules.end(); ++i)
        (*i)->evaluate(message,request,*this);
}

void SecurityPolicy::setIssuer(saml2::Issuer* issuer)
{
    if (!getIssuerMatchingPolicy().issuerMatches(issuer, m_issuer))
        throw SecurityPolicyException("A rule supplied an Issuer that conflicts with previous results.");
    
    delete m_issuer;
    m_issuer=issuer;
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
