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
 * SAML2MessageEncoder.cpp
 *
 * Base class for SAML 2.0 MessageEncoders.
 */

#include "internal.h"
#include "saml2/binding/SAML2MessageEncoder.h"
#include "saml2/core/Protocols.h"
#include "util/SAMLConstants.h"

#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/io/HTTPResponse.h>
#include <xmltooling/util/URLEncoder.h>

using namespace opensaml::saml2p;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

SAML2MessageEncoder::SAML2MessageEncoder()
{
}

SAML2MessageEncoder::~SAML2MessageEncoder()
{
}

const XMLCh* SAML2MessageEncoder::getProtocolFamily() const
{
    return samlconstants::SAML20P_NS;
}

void SAML2MessageEncoder::preserveCorrelationID(HTTPResponse& response, const RequestAbstractType& message, const char* relayState) const
{
    Category& log = Category::getInstance(SAML_LOGCAT ".MessageEncoder.SAML2");

    if (relayState && *relayState) {
        string cookie_name = string("_opensaml_req_").append(
            XMLToolingConfig::getConfig().getURLEncoder()->encode(relayState));
        auto_ptr_char id(message.getID());
        log.debug("tracking request (%s) against RelayState token (%s)", id.get(), relayState);
        response.setCookie(cookie_name.c_str(),
            XMLToolingConfig::getConfig().getURLEncoder()->encode(id.get()).c_str(),
            0,
            HTTPResponse::SAMESITE_NONE);
    }
    else {
        log.debug("no relay state, request/response correlation is disabled");
    }
}
