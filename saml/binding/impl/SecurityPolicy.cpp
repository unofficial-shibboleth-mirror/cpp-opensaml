/*
 *  Copyright 2001-2006 Internet2
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
#include "binding/SecurityPolicy.h"
#include "saml2/core/Assertions.h"

using namespace opensaml::saml2md;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,const DOMElement*>::Factory MessageFlowRuleFactory;
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,const DOMElement*>::Factory MessageRoutingRuleFactory;
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,const DOMElement*>::Factory MessageSigningRuleFactory;
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,const DOMElement*>::Factory SimpleSigningRuleFactory;
};

void SAML_API opensaml::registerSecurityPolicyRules()
{
    SAMLConfig& conf=SAMLConfig::getConfig();
    conf.SecurityPolicyRuleManager.registerFactory(MESSAGEFLOW_POLICY_RULE, MessageFlowRuleFactory);
    conf.SecurityPolicyRuleManager.registerFactory(MESSAGEROUTING_POLICY_RULE, MessageRoutingRuleFactory);
    conf.SecurityPolicyRuleManager.registerFactory(MESSAGESIGNING_POLICY_RULE, MessageSigningRuleFactory);
    conf.SecurityPolicyRuleManager.registerFactory(SIMPLESIGNING_POLICY_RULE, SimpleSigningRuleFactory);
}

SecurityPolicy::~SecurityPolicy()
{
    delete m_issuer;
}

void SecurityPolicy::evaluate(const GenericRequest& request, const XMLObject& message)
{
    for (vector<const SecurityPolicyRule*>::const_iterator i=m_rules.begin(); i!=m_rules.end(); ++i) {

        // Run the rule...
        pair<Issuer*,const RoleDescriptor*> ident = (*i)->evaluate(request,message,m_metadata,&m_role,m_trust);

        // Make sure returned issuer doesn't conflict.
         
        if (ident.first) {
            if (!issuerMatches(ident.first, m_issuer)) {
                delete ident.first;
                throw BindingException("Policy rules returned differing Issuers.");
            }
            delete m_issuer;
            m_issuer=ident.first;
        }

        if (ident.second) {
            if (m_issuerRole && ident.second!=m_issuerRole)
                throw BindingException("Policy rules returned differing issuer RoleDescriptors.");
            m_issuerRole=ident.second;
        }
    }
}

void SecurityPolicy::setIssuer(saml2::Issuer* issuer)
{
    if (!issuerMatches(issuer, m_issuer)) {
        delete issuer;
        throw BindingException("Externally provided Issuer conflicts with policy results.");
    }
    
    delete m_issuer;
    m_issuer=issuer;
}

void SecurityPolicy::setIssuerMetadata(const RoleDescriptor* issuerRole)
{
    if (issuerRole && m_issuerRole && issuerRole!=m_issuerRole)
        throw BindingException("Externally provided RoleDescriptor conflicts with policy results.");
    m_issuerRole=issuerRole;
}

bool SecurityPolicy::issuerMatches(const Issuer* issuer1, const Issuer* issuer2) const
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
