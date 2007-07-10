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
 * SAML1SOAPClient.cpp
 * 
 * Specialized SOAPClient for SAML 1.x SOAP binding.
 */

#include "internal.h"
#include "exceptions.h"
#include "saml1/binding/SAML1SOAPClient.h"
#include "saml1/core/Protocols.h"
#include "saml2/metadata/Metadata.h"

#include <log4cpp/Category.hh>
#include <xmltooling/soap/SOAP.h>

using namespace opensaml::saml1p;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace soap11;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

void SAML1SOAPClient::sendSAML(Request* request, MetadataCredentialCriteria& peer, const char* endpoint)
{
    auto_ptr<Envelope> env(EnvelopeBuilder::buildEnvelope());
    Body* body = BodyBuilder::buildBody();
    env->setBody(body);
    body->getUnknownXMLObjects().push_back(request);
    m_soaper.send(*env.get(), peer, endpoint);
    m_correlate = XMLString::replicate(request->getRequestID());
}

Response* SAML1SOAPClient::receiveSAML()
{
    auto_ptr<Envelope> env(m_soaper.receive());
    if (env.get()) {
        Body* body = env->getBody();
        if (body && body->hasChildren()) {
            // Check for SAML Response.
            Response* response = dynamic_cast<Response*>(body->getUnknownXMLObjects().front());
            if (response) {

                // Check InResponseTo.
                if (m_correlate && response->getInResponseTo() && !XMLString::equals(m_correlate, response->getInResponseTo()))
                    throw SecurityPolicyException("InResponseTo attribute did not correlate with the Request ID.");
                
                m_soaper.getPolicy().evaluate(*response);
                
                if (!m_soaper.getPolicy().isSecure()) {
                    SecurityPolicyException ex("Security policy could not authenticate the message.");
                    if (m_soaper.getPolicy().getIssuerMetadata())
                        annotateException(&ex, m_soaper.getPolicy().getIssuerMetadata());   // throws it
                    else
                        ex.raise();
                }
                
                // Check Status.
                Status* status = response->getStatus();
                if (status) {
                    const QName* code = status->getStatusCode() ? status->getStatusCode()->getValue() : NULL;
                    if (code && *code != StatusCode::SUCCESS && handleError(*status)) {
                        BindingException ex("SAML Response contained an error.");
                        if (m_soaper.getPolicy().getIssuerMetadata())
                            annotateException(&ex, m_soaper.getPolicy().getIssuerMetadata());   // throws it
                        else
                            ex.raise();
                    }
                }
                
                env.release();
                body->detach(); // frees Envelope
                response->detach();   // frees Body
                return response;
            }
        }
        
        BindingException ex("SOAP Envelope did not contain a SAML Response or a Fault.");
        if (m_soaper.getPolicy().getIssuerMetadata())
            annotateException(&ex, m_soaper.getPolicy().getIssuerMetadata());   // throws it
        else
            ex.raise();
    }
    return NULL;
}

bool SAML1SOAPClient::handleError(const Status& status)
{
    const QName* code = status.getStatusCode() ? status.getStatusCode()->getValue() : NULL;
    auto_ptr_char str((status.getStatusMessage() ? status.getStatusMessage()->getMessage() : NULL));
    Category::getInstance(SAML_LOGCAT".SOAPClient").error(
        "SOAP client detected a SAML error: (%s) (%s)",
        (code ? code->toString().c_str() : "no code"),
        (str.get() ? str.get() : "no message")
        );
    return m_fatal;
}
