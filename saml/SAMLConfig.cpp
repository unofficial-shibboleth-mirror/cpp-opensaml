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
 * SAMLConfig.cpp
 * 
 * Library configuration.
 */

#include "internal.h"

#if defined(XMLTOOLING_LOG4SHIB)
# ifndef OPENSAML_LOG4SHIB
#  error "Logging library mismatch (XMLTooling is using log4shib)."
# endif
#elif defined(XMLTOOLING_LOG4CPP)
# ifndef OPENSAML_LOG4CPP
#  error "Logging library mismatch (XMLTooling is using log4cpp)."
# endif
#else
# error "No supported logging library."
#endif

#include "exceptions.h"
#include "SAMLConfig.h"
#include "binding/ArtifactMap.h"
#include "binding/MessageDecoder.h"
#include "binding/MessageEncoder.h"
#include "binding/SAMLArtifact.h"
#include "binding/SecurityPolicyRule.h"
#include "saml1/core/Assertions.h"
#include "saml1/core/Protocols.h"
#include "saml2/core/Protocols.h"
#include "saml2/metadata/EntityMatcher.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataFilter.h"
#include "saml2/metadata/MetadataProvider.h"
#include "util/SAMLConstants.h"

#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/security/SecurityHelper.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/PathResolver.h>
#include <xmltooling/util/Threads.h>

#include <boost/lambda/bind.hpp>
#include <boost/lambda/casts.hpp>
#include <boost/lambda/lambda.hpp>

#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/enc/XSECCryptoProvider.hpp>
#include <xsec/utils/XSECPlatformUtils.hpp>
#include <xercesc/util/XMLStringTokenizer.hpp>

using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace boost::lambda;
using namespace boost;
using namespace std;

// Expose entry points when used as an extension library

extern "C" int SAML_API xmltooling_extension_init(void*)
{
    if (SAMLConfig::getConfig().init(false))
        return 0;
    return -1;
}

extern "C" void SAML_API xmltooling_extension_term()
{
    SAMLConfig::getConfig().term(false);
}

DECL_XMLTOOLING_EXCEPTION_FACTORY(ArtifactException,opensaml);
DECL_XMLTOOLING_EXCEPTION_FACTORY(SecurityPolicyException,opensaml);
DECL_XMLTOOLING_EXCEPTION_FACTORY(MetadataException,opensaml::saml2md);
DECL_XMLTOOLING_EXCEPTION_FACTORY(MetadataFilterException,opensaml::saml2md);
DECL_XMLTOOLING_EXCEPTION_FACTORY(BindingException,opensaml);
DECL_XMLTOOLING_EXCEPTION_FACTORY(ProfileException,opensaml);
DECL_XMLTOOLING_EXCEPTION_FACTORY(FatalProfileException,opensaml);
DECL_XMLTOOLING_EXCEPTION_FACTORY(RetryableProfileException,opensaml);

namespace opensaml {
   SAMLInternalConfig g_config;
}

SAMLConfig& SAMLConfig::getConfig()
{
    return g_config;
}

SAMLInternalConfig& SAMLInternalConfig::getInternalConfig()
{
    return g_config;
}

SAMLConfig::SAMLConfig() : m_artifactMap(nullptr)
{
}

SAMLConfig::~SAMLConfig()
{
    delete m_artifactMap;
}

ArtifactMap* SAMLConfig::getArtifactMap() const
{
    return m_artifactMap;
}

void SAMLConfig::setArtifactMap(ArtifactMap* artifactMap)
{
    delete m_artifactMap;
    m_artifactMap = artifactMap;
}

SAMLInternalConfig::SAMLInternalConfig() : m_initCount(0), m_lock(Mutex::create())
{
}

SAMLInternalConfig::~SAMLInternalConfig()
{
}

bool SAMLInternalConfig::init(bool initXMLTooling)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("init");
#endif
    Category& log=Category::getInstance(SAML_LOGCAT ".Config");

    Lock initLock(m_lock);

    if (m_initCount == INT_MAX) {
        log.crit("library initialized too many times");
        return false;
    }

    if (m_initCount >= 1) {
        ++m_initCount;
        return true;
    }

    log.debug("library initialization started");

    if (initXMLTooling && !XMLToolingConfig::getConfig().init()) {
        return false;
    }

    XMLToolingConfig::getConfig().getPathResolver()->setDefaultPackageName("opensaml");

    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(ArtifactException,opensaml);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(SecurityPolicyException,opensaml);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(MetadataException,opensaml::saml2md);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(MetadataFilterException,opensaml::saml2md);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(BindingException,opensaml);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(ProfileException,opensaml);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(FatalProfileException,opensaml);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(RetryableProfileException,opensaml);

    saml1::registerAssertionClasses();
    saml1p::registerProtocolClasses();
    saml2::registerAssertionClasses();
    saml2p::registerProtocolClasses();
    saml2md::registerMetadataClasses();
    saml2md::registerMetadataProviders();
    saml2md::registerMetadataFilters();
    saml2md::registerEntityMatchers();
    registerSAMLArtifacts();
    registerMessageEncoders();
    registerMessageDecoders();
    registerSecurityPolicyRules();

    m_contactPriority.push_back(saml2md::ContactPerson::CONTACT_SUPPORT);
    m_contactPriority.push_back(saml2md::ContactPerson::CONTACT_TECHNICAL);

    log.info("%s library initialization complete", PACKAGE_STRING);
    ++m_initCount;
    return true;
}

void SAMLInternalConfig::term(bool termXMLTooling)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("term");
#endif

    Lock initLock(m_lock);
    if (m_initCount == 0) {
        Category::getInstance(SAML_LOGCAT ".Config").crit("term without corresponding init");
        return;
    }
    else if (--m_initCount > 0) {
        return;
    }

    MessageDecoderManager.deregisterFactories();
    MessageEncoderManager.deregisterFactories();
    SecurityPolicyRuleManager.deregisterFactories();
    SAMLArtifactManager.deregisterFactories();
    EntityMatcherManager.deregisterFactories();
    MetadataFilterManager.deregisterFactories();
    MetadataProviderManager.deregisterFactories();

    delete m_artifactMap;
    m_artifactMap = nullptr;

    if (termXMLTooling)
        XMLToolingConfig::getConfig().term();
    
    Category::getInstance(SAML_LOGCAT ".Config").info("%s library shutdown complete", PACKAGE_STRING);
}

void SAMLInternalConfig::generateRandomBytes(void* buf, unsigned int len)
{
    try {
        if (XSECPlatformUtils::g_cryptoProvider->getRandom(reinterpret_cast<unsigned char*>(buf),len)<len)
            throw XMLSecurityException("Unable to generate random data; was PRNG seeded?");
    }
    catch (XSECCryptoException& e) {
        throw XMLSecurityException("Unable to generate random data: $1",params(1,e.getMsg()));
    }
}

void SAMLInternalConfig::generateRandomBytes(std::string& buf, unsigned int len)
{
    buf.erase();
    auto_arrayptr<unsigned char> hold(new unsigned char[len]);
    generateRandomBytes(const_cast<unsigned char*>(hold.get()), len);
    for (unsigned int i=0; i<len; i++)
        buf+=(hold.get())[i];
}

XMLCh* SAMLInternalConfig::generateIdentifier()
{
    unsigned char key[17];
    generateRandomBytes(key,16);
    
    char hexform[34];
    sprintf(hexform,"_%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            key[0],key[1],key[2],key[3],key[4],key[5],key[6],key[7],
            key[8],key[9],key[10],key[11],key[12],key[13],key[14],key[15]);
    hexform[33]=0;
    return XMLString::transcode(hexform);
}

void SAMLInternalConfig::setContactPriority(const XMLCh* contactTypes)
{
    const XMLCh* ctype;
    m_contactPriority.clear();
    XMLStringTokenizer tokens(contactTypes);
    while (tokens.hasMoreTokens()) {
        ctype = tokens.nextToken();
        if (ctype && *ctype)
            m_contactPriority.push_back(ctype);
    }
}

using namespace saml2md;

const ContactPerson* SAMLInternalConfig::getContactPerson(const EntityDescriptor& entity) const
{
    for (vector<xstring>::const_iterator ctype = m_contactPriority.begin(); ctype != m_contactPriority.end(); ++ctype) {
        const ContactPerson* cp = find_if(entity.getContactPersons(), *ctype == lambda::bind(&ContactPerson::getContactType, _1));
        if (cp)
            return cp;
    }
    return nullptr;
}

const ContactPerson* SAMLInternalConfig::getContactPerson(const RoleDescriptor& role) const
{
    for (vector<xstring>::const_iterator ctype = m_contactPriority.begin(); ctype != m_contactPriority.end(); ++ctype) {
        const ContactPerson* cp = find_if(role.getContactPersons(), *ctype == lambda::bind(&ContactPerson::getContactType, _1));
        if (cp)
            return cp;
    }
    return getContactPerson(*(dynamic_cast<const EntityDescriptor*>(role.getParent())));
}

SignableObject::SignableObject()
{
}

SignableObject::~SignableObject()
{
}

RootObject::RootObject()
{
}

RootObject::~RootObject()
{
}

Assertion::Assertion()
{
}

Assertion::~Assertion()
{
}

Status::Status()
{
}

Status::~Status()
{
}

void opensaml::annotateException(XMLToolingException* e, const EntityDescriptor* entity, const Status* status, bool rethrow)
{
    time_t now = time(nullptr);
    const RoleDescriptor* role = nullptr;
    static bool (TimeBoundSAMLObject::* isValid)(time_t) const = &TimeBoundSAMLObject::isValid;

    if (entity) {
        const XMLObject* r = find_if(
            entity->getOrderedChildren(),
            (ll_dynamic_cast<const RoleDescriptor*>(_1) != ((const RoleDescriptor*)nullptr) &&
                    lambda::bind(isValid, ll_dynamic_cast<const TimeBoundSAMLObject*>(_1), now))
            );
        if (r)
            role = dynamic_cast<const RoleDescriptor*>(r);
    }

    annotateException(e, role, status, rethrow);
}

void opensaml::annotateException(XMLToolingException* e, const RoleDescriptor* role, const Status* status, bool rethrow)
{
    if (role) {
        auto_ptr_char id(dynamic_cast<EntityDescriptor*>(role->getParent())->getEntityID());
        e->addProperty("entityID",id.get());

        const ContactPerson* cp = SAMLConfig::getConfig().getContactPerson(*role);
        if (cp) {
            GivenName* fname = cp->getGivenName();
            SurName* lname = cp->getSurName();
            auto_ptr_char first(fname ? fname->getName() : nullptr);
            auto_ptr_char last(lname ? lname->getName() : nullptr);
            if (first.get() && last.get()) {
                string contact=string(first.get()) + ' ' + last.get();
                e->addProperty("contactName", contact.c_str());
            }
            else if (first.get())
                e->addProperty("contactName", first.get());
            else if (last.get())
                e->addProperty("contactName", last.get());
            const vector<EmailAddress*>& emails=cp->getEmailAddresss();
            if (!emails.empty()) {
                auto_ptr_char email(emails.front()->getAddress());
                if (email.get()) {
                    if (strstr(email.get(), "mailto:") == email.get()) {
                        e->addProperty("contactEmail", email.get());
                    }
                    else {
                        string addr = string("mailto:") + email.get();
                        e->addProperty("contactEmail", addr.c_str());
                    }
                }
            }
        }

        auto_ptr_char eurl(role->getErrorURL());
        if (eurl.get()) {
            e->addProperty("errorURL",eurl.get());
        }
    }

    if (status) {
        auto_ptr_char sc(status->getTopStatus());
        if (sc.get() && *sc.get())
            e->addProperty("statusCode", sc.get());
        if (status->getSubStatus()) {
            auto_ptr_char sc2(status->getSubStatus());
            if (sc2.get() && *sc.get())
                e->addProperty("statusCode2", sc2.get());
        }
        if (status->getMessage()) {
            auto_ptr_char msg(status->getMessage());
            if (msg.get() && *msg.get())
                e->addProperty("statusMessage", msg.get());
        }
    }
    
    if (rethrow)
        e->raise();
}
