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
 * MetadataProvider.cpp
 *
 * Supplies an individual source of metadata.
 */

#include "internal.h"
#include "saml2/metadata/MetadataFilter.h"
#include "saml2/metadata/MetadataProvider.h"

#include <algorithm>
#include <boost/lambda/lambda.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/unicode.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/XMLHelper.h>

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace boost::lambda;
using namespace boost;
using namespace std;

namespace opensaml {
    namespace saml2md {
        SAML_DLLLOCAL PluginManager<MetadataProvider,string,const DOMElement*>::Factory XMLMetadataProviderFactory;
        SAML_DLLLOCAL PluginManager<MetadataProvider,string,const DOMElement*>::Factory DynamicMetadataProviderFactory;
        SAML_DLLLOCAL PluginManager<MetadataProvider,string,const DOMElement*>::Factory ChainingMetadataProviderFactory;
        SAML_DLLLOCAL PluginManager<MetadataProvider,string,const DOMElement*>::Factory FolderMetadataProviderFactory;
        SAML_DLLLOCAL PluginManager<MetadataProvider,string,const DOMElement*>::Factory NullMetadataProviderFactory;
        SAML_DLLLOCAL PluginManager<MetadataFilter,string,const DOMElement*>::Factory BlacklistMetadataFilterFactory;
        SAML_DLLLOCAL PluginManager<MetadataFilter,string,const DOMElement*>::Factory WhitelistMetadataFilterFactory;
        SAML_DLLLOCAL PluginManager<MetadataFilter,string,const DOMElement*>::Factory SignatureMetadataFilterFactory;
        SAML_DLLLOCAL PluginManager<MetadataFilter,string,const DOMElement*>::Factory RequireValidUntilMetadataFilterFactory;
        SAML_DLLLOCAL PluginManager<MetadataFilter,string,const DOMElement*>::Factory EntityRoleMetadataFilterFactory;
        SAML_DLLLOCAL PluginManager<MetadataFilter,string,const DOMElement*>::Factory EntityAttributesMetadataFilterFactory;
    };
};

void SAML_API opensaml::saml2md::registerMetadataProviders()
{
    SAMLConfig& conf=SAMLConfig::getConfig();
    conf.MetadataProviderManager.registerFactory(XML_METADATA_PROVIDER, XMLMetadataProviderFactory);
    conf.MetadataProviderManager.registerFactory(DYNAMIC_METADATA_PROVIDER, DynamicMetadataProviderFactory);
    conf.MetadataProviderManager.registerFactory(CHAINING_METADATA_PROVIDER, ChainingMetadataProviderFactory);
    conf.MetadataProviderManager.registerFactory(FOLDER_METADATA_PROVIDER, FolderMetadataProviderFactory);
    conf.MetadataProviderManager.registerFactory(NULL_METADATA_PROVIDER, NullMetadataProviderFactory);
}

void SAML_API opensaml::saml2md::registerMetadataFilters()
{
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(BLACKLIST_METADATA_FILTER, BlacklistMetadataFilterFactory);
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(WHITELIST_METADATA_FILTER, WhitelistMetadataFilterFactory);
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(SIGNATURE_METADATA_FILTER, SignatureMetadataFilterFactory);
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(REQUIREVALIDUNTIL_METADATA_FILTER, RequireValidUntilMetadataFilterFactory);
    // additional name matching Java code
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory("RequiredValidUntil", RequireValidUntilMetadataFilterFactory);
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(ENTITYROLE_METADATA_FILTER, EntityRoleMetadataFilterFactory);
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(ENTITYATTR_METADATA_FILTER, EntityAttributesMetadataFilterFactory);

}

static const XMLCh _MetadataFilter[] =  UNICODE_LITERAL_14(M,e,t,a,d,a,t,a,F,i,l,t,e,r);
static const XMLCh Blacklist[] =        UNICODE_LITERAL_23(B,l,a,c,k,l,i,s,t,M,e,t,a,d,a,t,a,F,i,l,t,e,r);
static const XMLCh Whitelist[] =        UNICODE_LITERAL_23(W,h,i,t,e,l,i,s,t,M,e,t,a,d,a,t,a,F,i,l,t,e,r);
static const XMLCh SigFilter[] =        UNICODE_LITERAL_23(S,i,g,n,a,t,u,r,e,M,e,t,a,d,a,t,a,F,i,l,t,e,r);
static const XMLCh Exclude[] =          UNICODE_LITERAL_7(E,x,c,l,u,d,e);
static const XMLCh Include[] =          UNICODE_LITERAL_7(I,n,c,l,u,d,e);
static const XMLCh _type[] =            UNICODE_LITERAL_4(t,y,p,e);

MetadataProvider::MetadataProvider(const DOMElement* e) : m_filterContext(nullptr)
{
#ifdef _DEBUG
    NDC ndc("MetadataProvider");
#endif
    Category& log = Category::getInstance(SAML_LOGCAT".Metadata");
    SAMLConfig& conf = SAMLConfig::getConfig();

    // Locate any default recognized filters and plugins.
    try {
        DOMElement* child = XMLHelper::getFirstChildElement(e);
        while (child) {
            if (XMLString::equals(child->getLocalName(), _MetadataFilter)) {
                string t = XMLHelper::getAttrString(child, nullptr, _type);
                if (!t.empty()) {
                    log.info("building MetadataFilter of type %s", t.c_str());
                    auto_ptr<MetadataFilter> np(conf.MetadataFilterManager.newPlugin(t.c_str(), child));
                    m_filters.push_back(np.get());
                    np.release();
                }
                else {
                    log.error("MetadataFilter element missing type attribute");
                }
            }
            else if (XMLString::equals(child->getLocalName(), SigFilter)) {
                log.info("building MetadataFilter of type %s", SIGNATURE_METADATA_FILTER);
                m_filters.push_back(conf.MetadataFilterManager.newPlugin(SIGNATURE_METADATA_FILTER, child));
            }
            else if (XMLString::equals(child->getLocalName(), Whitelist)) {
                log.info("building MetadataFilter of type %s", WHITELIST_METADATA_FILTER);
                m_filters.push_back(conf.MetadataFilterManager.newPlugin(WHITELIST_METADATA_FILTER, child));
            }
            else if (XMLString::equals(child->getLocalName(), Blacklist)) {
                log.info("building MetadataFilter of type %s", BLACKLIST_METADATA_FILTER);
                m_filters.push_back(conf.MetadataFilterManager.newPlugin(BLACKLIST_METADATA_FILTER, child));
            }
            else if (XMLString::equals(child->getLocalName(), Include)) {
                log.info("building MetadataFilter of type %s", WHITELIST_METADATA_FILTER);
                m_filters.push_back(conf.MetadataFilterManager.newPlugin(WHITELIST_METADATA_FILTER, e));
            }
            else if (XMLString::equals(child->getLocalName(), Exclude)) {
                log.info("building MetadataFilter of type %s", BLACKLIST_METADATA_FILTER);
                m_filters.push_back(conf.MetadataFilterManager.newPlugin(BLACKLIST_METADATA_FILTER, e));
            }
            child = XMLHelper::getNextSiblingElement(child);
        }
    }
    catch (XMLToolingException& ex) {
        log.error("caught exception while installing filters: %s", ex.what());
        throw;
    }
}

MetadataProvider::~MetadataProvider()
{
}

const char* MetadataProvider::getId() const
{
    return nullptr;
}

void MetadataProvider::addMetadataFilter(MetadataFilter* newFilter)
{
    m_filters.push_back(newFilter);
}

MetadataFilter* MetadataProvider::removeMetadataFilter(MetadataFilter* oldFilter)
{
    ptr_vector<MetadataFilter>::iterator i = find_if(m_filters.begin(), m_filters.end(), (&_1 == oldFilter));
    if (i != m_filters.end()) {
        return m_filters.release(i).release();
    }
    return nullptr;
}

void MetadataProvider::setContext(const MetadataFilterContext* ctx)
{
    m_filterContext = ctx;
}

void MetadataProvider::doFilters(XMLObject& xmlObject) const
{
    Category& log = Category::getInstance(SAML_LOGCAT".Metadata");
    for (ptr_vector<MetadataFilter>::const_iterator i = m_filters.begin(); i != m_filters.end(); i++) {
        log.info("applying metadata filter (%s)", i->getId());
        i->doFilter(m_filterContext, xmlObject);
    }
}

void MetadataProvider::outputStatus(ostream& os) const
{
}

const EntitiesDescriptor* MetadataProvider::getEntitiesDescriptor(const XMLCh* name, bool strict) const
{
    auto_ptr_char temp(name);
    return getEntitiesDescriptor(temp.get(),strict);
}

MetadataProvider::Criteria::Criteria()
    : entityID_unicode(nullptr), entityID_ascii(nullptr), artifact(nullptr), role(nullptr), protocol(nullptr), protocol2(nullptr), validOnly(true)
{
}

MetadataProvider::Criteria::Criteria(const XMLCh* id, const xmltooling::QName* q, const XMLCh* prot, bool valid)
    : entityID_unicode(id), entityID_ascii(nullptr), artifact(nullptr), role(q), protocol(prot), protocol2(nullptr), validOnly(valid)
{
}

MetadataProvider::Criteria::Criteria(const char* id, const xmltooling::QName* q, const XMLCh* prot, bool valid)
    : entityID_unicode(nullptr), entityID_ascii(id), artifact(nullptr), role(q), protocol(prot), protocol2(nullptr), validOnly(valid)
{
}

MetadataProvider::Criteria::Criteria(const SAMLArtifact* a, const xmltooling::QName* q, const XMLCh* prot, bool valid)
    : entityID_unicode(nullptr), entityID_ascii(nullptr), artifact(a), role(q), protocol(prot), protocol2(nullptr), validOnly(valid)
{
}

MetadataProvider::Criteria::~Criteria()
{
}

void MetadataProvider::Criteria::reset()
{
    entityID_unicode = nullptr;
    entityID_ascii = nullptr;
    artifact = nullptr;
    role = nullptr;
    protocol = nullptr;
    protocol2 = nullptr;
    validOnly = true;
}

MetadataFilter::MetadataFilter()
{
}

MetadataFilter::~MetadataFilter()
{
}

void MetadataFilter::doFilter(const MetadataFilterContext* ctx, xmltooling::XMLObject& xmlObject) const
{
    // Default call into deprecated method.
    doFilter(xmlObject);
}

void MetadataFilter::doFilter(xmltooling::XMLObject& xmlObject) const
{
    // Empty default for deprecated method.
}

MetadataFilterContext::MetadataFilterContext()
{
}

MetadataFilterContext::~MetadataFilterContext()
{
}
