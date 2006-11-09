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
#include "saml1/core/Assertions.h"
#include "saml1/core/Protocols.h"
#include "saml2/core/Assertions.h"
#include "saml2/core/Protocols.h"

using namespace opensaml::saml2md;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,const DOMElement*>::Factory MessageFlowRuleFactory;
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,const DOMElement*>::Factory SimpleSigningRuleFactory;
    SAML_DLLLOCAL PluginManager<SecurityPolicyRule,const DOMElement*>::Factory XMLSigningRuleFactory;
};

void SAML_API opensaml::registerSecurityPolicyRules()
{
    SAMLConfig& conf=SAMLConfig::getConfig();
    conf.SecurityPolicyRuleManager.registerFactory(MESSAGEFLOW_POLICY_RULE, MessageFlowRuleFactory);
    conf.SecurityPolicyRuleManager.registerFactory(SIMPLESIGNING_POLICY_RULE, SimpleSigningRuleFactory);
    conf.SecurityPolicyRuleManager.registerFactory(XMLSIGNING_POLICY_RULE, XMLSigningRuleFactory);
}

SecurityPolicy::IssuerMatchingPolicy SecurityPolicy::m_defaultMatching;

SecurityPolicyRule::MessageExtractor SecurityPolicy::m_defaultExtractor;

SecurityPolicy::~SecurityPolicy()
{
    delete m_extractor;
    delete m_matchingPolicy;
    delete m_issuer;
}

void SecurityPolicy::evaluate(const GenericRequest& request, const XMLObject& message)
{
    for (vector<const SecurityPolicyRule*>::const_iterator i=m_rules.begin(); i!=m_rules.end(); ++i) {

        // Run the rule...
        pair<Issuer*,const RoleDescriptor*> ident =
            (*i)->evaluate(request,message,m_metadata,&m_role,m_trust,getMessageExtractor());

        // Make sure returned issuer doesn't conflict.
         
        if (ident.first) {
            if (!getIssuerMatchingPolicy().issuerMatches(ident.first, m_issuer)) {
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
    if (!getIssuerMatchingPolicy().issuerMatches(issuer, m_issuer)) {
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


pair<saml2::Issuer*,const XMLCh*> SecurityPolicyRule::MessageExtractor::getIssuerAndProtocol(const XMLObject& message) const
{
    // We just let any bad casts throw here.
    
    saml2::Issuer* issuer;

    // Shortcuts some of the casting.
    const XMLCh* ns = message.getElementQName().getNamespaceURI();
    if (ns) {
        if (XMLString::equals(ns, samlconstants::SAML20P_NS) || XMLString::equals(ns, samlconstants::SAML20_NS)) {
            // 2.0 namespace should be castable to a specialized 2.0 root.
            const saml2::RootObject& root = dynamic_cast<const saml2::RootObject&>(message);
            issuer = root.getIssuer();
            if (issuer && issuer->getName()) {
                return make_pair(issuer->cloneIssuer(), samlconstants::SAML20P_NS);
            }
            
            // No issuer in the message, so we have to try the Response approach. 
            const vector<saml2::Assertion*>& assertions = dynamic_cast<const saml2p::Response&>(message).getAssertions();
            if (!assertions.empty()) {
                issuer = assertions.front()->getIssuer();
                if (issuer && issuer->getName())
                    return make_pair(issuer->cloneIssuer(), samlconstants::SAML20P_NS);
            }
        }
        else if (XMLString::equals(ns, samlconstants::SAML1P_NS)) {
            // Should be a samlp:Response, at least in OpenSAML.
            const vector<saml1::Assertion*>& assertions = dynamic_cast<const saml1p::Response&>(message).getAssertions();
            if (!assertions.empty()) {
                const saml1::Assertion* a = assertions.front();
                if (a->getIssuer()) {
                    issuer = saml2::IssuerBuilder::buildIssuer();
                    issuer->setName(a->getIssuer());
                    pair<bool,int> minor = a->getMinorVersion();
                    return make_pair(
                        issuer,
                        (minor.first && minor.second==0) ? samlconstants::SAML10_PROTOCOL_ENUM : samlconstants::SAML11_PROTOCOL_ENUM
                        );
                }
            }
        }
        else if (XMLString::equals(ns, samlconstants::SAML1_NS)) {
            // Should be a saml:Assertion.
            const saml1::Assertion& a = dynamic_cast<const saml1::Assertion&>(message);
            if (a.getIssuer()) {
                issuer = saml2::IssuerBuilder::buildIssuer();
                issuer->setName(a.getIssuer());
                pair<bool,int> minor = a.getMinorVersion();
                return make_pair(
                    issuer,
                    (minor.first && minor.second==0) ? samlconstants::SAML10_PROTOCOL_ENUM : samlconstants::SAML11_PROTOCOL_ENUM
                    );
            }
        }
    }
    return pair<saml2::Issuer*,const XMLCh*>(NULL,NULL);
}
