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
 * SOAPClient.cpp
 * 
 * Implements SOAP 1.1 messaging over a transport.
 */

#include "internal.h"
#include "exceptions.h"
#include "version.h"
#include "binding/SOAPClient.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataProvider.h"

#include <xmltooling/security/X509TrustEngine.h>
#include <xmltooling/soap/SOAP.h>
#include <xmltooling/soap/HTTPSOAPTransport.h>

using namespace opensaml::saml2;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

void SOAPClient::send(const soap11::Envelope& env, const char* from, MetadataCredentialCriteria& to, const char* endpoint)
{
    // Clear policy.
    m_policy.reset();

    m_criteria = &to;
    m_peer = &(to.getRole());
    
    const QName& role = m_peer->getElementQName();
    if (XMLString::equals(role.getLocalPart(),RoleDescriptor::LOCAL_NAME))
        m_policy.setRole(m_peer->getSchemaType());
    else
        m_policy.setRole(&role);

    auto_ptr_char pn(dynamic_cast<const EntityDescriptor*>(m_peer->getParent())->getEntityID());
    soap11::SOAPClient::send(env, SOAPTransport::Address(from, pn.get(), endpoint));
}

void SOAPClient::prepareTransport(xmltooling::SOAPTransport& transport)
{
    HTTPSOAPTransport* http = dynamic_cast<HTTPSOAPTransport*>(&transport);
    if (http) {
        http->setRequestHeader("SOAPAction", "http://www.oasis-open.org/committees/security");
        http->setRequestHeader("Xerces-C", XERCES_FULLVERSIONDOT);
        http->setRequestHeader("XML-Security-C", XSEC_FULLVERSIONDOT);
        http->setRequestHeader("OpenSAML-C", OPENSAML_FULLVERSIONDOT);
    }
    
    const X509TrustEngine* engine = dynamic_cast<const X509TrustEngine*>(m_policy.getTrustEngine());
    if (engine) {
        if (!transport.setTrustEngine(engine, m_policy.getMetadataProvider(), m_criteria, m_force))
            throw BindingException("Unable to install X509TrustEngine into SOAPTransport.");
    }
}

soap11::Envelope* SOAPClient::receive()
{
    auto_ptr<soap11::Envelope> env(soap11::SOAPClient::receive());
    if (env.get()) {
        if (m_peer && m_transport->isSecure()) {
            // Set issuer based on peer identity.
            m_policy.setIssuer(dynamic_cast<EntityDescriptor*>(m_peer->getParent())->getEntityID());
            m_policy.setIssuerMetadata(m_peer);
            m_policy.setSecure(true);
        }
        m_policy.evaluate(*(env.get()));
    }
    return env.release();
}

void SOAPClient::reset()
{
    m_criteria = NULL;
    m_peer = NULL;
    soap11::SOAPClient::reset();
    m_policy.reset();
}
