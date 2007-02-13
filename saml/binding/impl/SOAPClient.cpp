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

void SOAPClient::send(const soap11::Envelope& env, const KeyInfoSource& peer, const char* endpoint)
{
    // Clear policy.
    m_policy.reset();
    
    m_peer = dynamic_cast<const RoleDescriptor*>(&peer);
    
    soap11::SOAPClient::send(env, peer, endpoint);
}

void SOAPClient::prepareTransport(const xmltooling::SOAPTransport& transport)
{
    const HTTPSOAPTransport* http = dynamic_cast<const HTTPSOAPTransport*>(&transport);
    if (http) {
        http->setRequestHeader("SOAPAction", "http://www.oasis-open.org/committees/security");
        http->setRequestHeader("Xerces-C", XERCES_FULLVERSIONDOT);
        http->setRequestHeader("XML-Security-C", XSEC_VERSION);
        http->setRequestHeader("OpenSAML-C", OPENSAML_FULLVERSIONDOT);
    }
    
    const X509TrustEngine* engine = dynamic_cast<const X509TrustEngine*>(m_policy.getTrustEngine());
    if (engine) {
        const MetadataProvider* metadata = m_policy.getMetadataProvider();
        if (!transport.setTrustEngine(engine, m_force, metadata ? metadata->getKeyResolver() : NULL))
            throw BindingException("Unable to install X509TrustEngine into SOAPTransport.");
    }
}

soap11::Envelope* SOAPClient::receive()
{
    auto_ptr<soap11::Envelope> env(soap11::SOAPClient::receive());
    if (env.get()) {
        if (m_peer && m_transport->isSecure()) {
            // Set issuer based on peer identity.
            EntityDescriptor* parent = dynamic_cast<EntityDescriptor*>(m_peer->getParent());
            if (parent) {
                Issuer* issuer = IssuerBuilder::buildIssuer();
                issuer->setName(parent->getEntityID());
                m_policy.setIssuer(issuer);
                m_policy.setIssuerMetadata(m_peer);
                m_policy.setSecure(true);
            }
        }
        m_policy.evaluate(*(env.get()));
    }
    return env.release();
}

void SOAPClient::reset()
{
    soap11::SOAPClient::reset();
    m_policy.reset();
    XMLString::release(&m_correlate);
    m_correlate=NULL;
}
