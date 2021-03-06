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

#include <errno.h>
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
        SAML_DLLLOCAL PluginManager<MetadataProvider,string,const DOMElement*>::Factory LocalDynamicMetadataProviderFactory;
        SAML_DLLLOCAL PluginManager<MetadataProvider,string,const DOMElement*>::Factory ChainingMetadataProviderFactory;
        SAML_DLLLOCAL PluginManager<MetadataProvider,string,const DOMElement*>::Factory FolderMetadataProviderFactory;
        SAML_DLLLOCAL PluginManager<MetadataProvider,string,const DOMElement*>::Factory NullMetadataProviderFactory;
        SAML_DLLLOCAL PluginManager<MetadataFilter,string,const DOMElement*>::Factory ExcludeMetadataFilterFactory;
        SAML_DLLLOCAL PluginManager<MetadataFilter,string,const DOMElement*>::Factory IncludeMetadataFilterFactory;
        SAML_DLLLOCAL PluginManager<MetadataFilter,string,const DOMElement*>::Factory InlineLogoMetadataFilterFactory;
        SAML_DLLLOCAL PluginManager<MetadataFilter,string,const DOMElement*>::Factory SignatureMetadataFilterFactory;
        SAML_DLLLOCAL PluginManager<MetadataFilter,string,const DOMElement*>::Factory RequireValidUntilMetadataFilterFactory;
        SAML_DLLLOCAL PluginManager<MetadataFilter,string,const DOMElement*>::Factory EntityRoleMetadataFilterFactory;
        SAML_DLLLOCAL PluginManager<MetadataFilter,string,const DOMElement*>::Factory EntityAttributesMetadataFilterFactory;
        SAML_DLLLOCAL PluginManager<MetadataFilter,string,const DOMElement*>::Factory UIInfoMetadataFilterFactory;
    };
};

void SAML_API opensaml::saml2md::registerMetadataProviders()
{
    SAMLConfig& conf=SAMLConfig::getConfig();
    conf.MetadataProviderManager.registerFactory(XML_METADATA_PROVIDER, XMLMetadataProviderFactory);
    conf.MetadataProviderManager.registerFactory(LOCAL_DYNAMIC_METADATA_PROVIDER, LocalDynamicMetadataProviderFactory);
    conf.MetadataProviderManager.registerFactory(CHAINING_METADATA_PROVIDER, ChainingMetadataProviderFactory);
    conf.MetadataProviderManager.registerFactory(FOLDER_METADATA_PROVIDER, FolderMetadataProviderFactory);
    conf.MetadataProviderManager.registerFactory(NULL_METADATA_PROVIDER, NullMetadataProviderFactory);
}

void SAML_API opensaml::saml2md::registerMetadataFilters()
{
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(EXCLUDE_METADATA_FILTER, ExcludeMetadataFilterFactory);
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(INCLUDE_METADATA_FILTER, IncludeMetadataFilterFactory);
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(INLINELOGO_METADATA_FILTER, InlineLogoMetadataFilterFactory);
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(SIGNATURE_METADATA_FILTER, SignatureMetadataFilterFactory);
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(ENTITYROLE_METADATA_FILTER, EntityRoleMetadataFilterFactory);
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(ENTITYATTR_METADATA_FILTER, EntityAttributesMetadataFilterFactory);
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(UIINFO_METADATA_FILTER, UIInfoMetadataFilterFactory);

    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(REQUIREVALIDUNTIL_METADATA_FILTER, RequireValidUntilMetadataFilterFactory);
    // additional name matching Java code
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory("RequiredValidUntil", RequireValidUntilMetadataFilterFactory);
    
    // Deprecated names.
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(BLACKLIST_METADATA_FILTER, ExcludeMetadataFilterFactory);
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(WHITELIST_METADATA_FILTER, IncludeMetadataFilterFactory);
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory("EntityRoleWhiteList", EntityRoleMetadataFilterFactory);
}

static const XMLCh _MetadataFilter[] =      UNICODE_LITERAL_14(M,e,t,a,d,a,t,a,F,i,l,t,e,r);
static const XMLCh BlacklistMF[] =          UNICODE_LITERAL_23(B,l,a,c,k,l,i,s,t,M,e,t,a,d,a,t,a,F,i,l,t,e,r);
static const XMLCh WhitelistMF[] =          UNICODE_LITERAL_23(W,h,i,t,e,l,i,s,t,M,e,t,a,d,a,t,a,F,i,l,t,e,r);
static const XMLCh SigFilter[] =            UNICODE_LITERAL_23(S,i,g,n,a,t,u,r,e,M,e,t,a,d,a,t,a,F,i,l,t,e,r);
static const XMLCh Exclude[] =              UNICODE_LITERAL_7(E,x,c,l,u,d,e);
static const XMLCh Include[] =              UNICODE_LITERAL_7(I,n,c,l,u,d,e);
static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);

MetadataProvider::MetadataProvider() { throw MetadataException("Illegal constructor call"); }

MetadataProvider::MetadataProvider(const DOMElement* e, bool deprecationSupport) : m_filterContext(nullptr)
{
#ifdef _DEBUG
    NDC ndc("MetadataProvider");
#endif
    Category& log = Category::getInstance(SAML_LOGCAT ".MetadataProvider");
    const SAMLConfig& conf = SAMLConfig::getConfig();

    // Locate any default recognized filters and plugins.
    DOMElement* child = XMLHelper::getFirstChildElement(e);
    while (child) {
        if (XMLString::equals(child->getLocalName(), _MetadataFilter)) {
            string t = XMLHelper::getAttrString(child, nullptr, _type);
            if (!t.empty()) {
                if (t == WHITELIST_METADATA_FILTER) {
                    log.warn("DEPRECATED: type=\"%s\" replaced by type=\"%s\"", WHITELIST_METADATA_FILTER, INCLUDE_METADATA_FILTER);
                    t = INCLUDE_METADATA_FILTER;
                }
                else if (t == BLACKLIST_METADATA_FILTER) {
                    log.warn("DEPRECATED: type=\"%s\" replaced by type=\"%s\"", BLACKLIST_METADATA_FILTER, EXCLUDE_METADATA_FILTER);
                    t = EXCLUDE_METADATA_FILTER;
                }
                else if (t == "EntityRoleWhiteList") {
                    log.warn("DEPRECATED: type=\"EntityRoleWhiteList\" replaced by type=\"%s\"", ENTITYROLE_METADATA_FILTER);
                    t = ENTITYROLE_METADATA_FILTER;
                }

                log.info("building MetadataFilter of type %s", t.c_str());
                auto_ptr<MetadataFilter> np(conf.MetadataFilterManager.newPlugin(t.c_str(), child, deprecationSupport));
                m_filters.push_back(np.get());
                np.release();
            }
            else {
                log.error("MetadataFilter element missing type attribute");
            }
        }
        else if (deprecationSupport && XMLString::equals(child->getLocalName(), SigFilter)) {
            log.warn("DEPRECATED: <SignatureMetadataFilter> replaced by type=\"%s\"", SIGNATURE_METADATA_FILTER);
            log.info("building MetadataFilter of type %s", SIGNATURE_METADATA_FILTER);
            m_filters.push_back(conf.MetadataFilterManager.newPlugin(SIGNATURE_METADATA_FILTER, child, deprecationSupport));
        }
        else if (deprecationSupport && XMLString::equals(child->getLocalName(), WhitelistMF)) {
            log.warn("DEPRECATED: <WhitelistMetadataFilter> replaced by type=\"%s\"", INCLUDE_METADATA_FILTER);
            log.info("building MetadataFilter of type %s", INCLUDE_METADATA_FILTER);
            m_filters.push_back(conf.MetadataFilterManager.newPlugin(INCLUDE_METADATA_FILTER, child, deprecationSupport));
        }
        else if (deprecationSupport && XMLString::equals(child->getLocalName(), BlacklistMF)) {
            log.warn("DEPRECATED: <BlacklistMetadataFilter> replaced by type=\"%s\"", EXCLUDE_METADATA_FILTER);
            log.info("building MetadataFilter of type %s", EXCLUDE_METADATA_FILTER);
            m_filters.push_back(conf.MetadataFilterManager.newPlugin(EXCLUDE_METADATA_FILTER, child, deprecationSupport));
        }
        else if (deprecationSupport && XMLString::equals(child->getLocalName(), Include)) {
            log.warn("DEPRECATED: <Include> replaced by type=\"%s\"", INCLUDE_METADATA_FILTER);
            log.info("building MetadataFilter of type %s", INCLUDE_METADATA_FILTER);
            m_filters.push_back(conf.MetadataFilterManager.newPlugin(INCLUDE_METADATA_FILTER, e, deprecationSupport));
        }
        else if (deprecationSupport && XMLString::equals(child->getLocalName(), Exclude)) {
            log.warn("DEPRECATED: <Exclude> replaced by type=\"%s\"", EXCLUDE_METADATA_FILTER);
            log.info("building MetadataFilter of type %s", EXCLUDE_METADATA_FILTER);
            m_filters.push_back(conf.MetadataFilterManager.newPlugin(EXCLUDE_METADATA_FILTER, e, deprecationSupport));
        }
        else if (!deprecationSupport && XMLString::endsWith(child->getLocalName(), _MetadataFilter)) {
            throw UnknownExtensionException("Unsupported metadata filter syntax detected.");
        }
        child = XMLHelper::getNextSiblingElement(child);
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

void MetadataProvider::doFilters(const MetadataFilterContext* ctx, XMLObject& xmlObject) const
{
    Category& log = Category::getInstance(SAML_LOGCAT ".MetadataProvider");
    for (ptr_vector<MetadataFilter>::const_iterator i = m_filters.begin(); i != m_filters.end(); i++) {
        log.info("applying metadata filter (%s)", i->getId());
        i->doFilter(ctx ? ctx : m_filterContext, xmlObject);
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

MetadataFilterContext::MetadataFilterContext()
{
}

MetadataFilterContext::~MetadataFilterContext()
{
}

BatchLoadMetadataFilterContext::BatchLoadMetadataFilterContext(bool isBackingFile)
    : MetadataFilterContext(), m_isBackingFile(isBackingFile)
{
}

BatchLoadMetadataFilterContext::~BatchLoadMetadataFilterContext()
{
}

bool BatchLoadMetadataFilterContext::isBackingFile() const
{
    return m_isBackingFile;
}

void BatchLoadMetadataFilterContext::setBackingFile(bool flag)
{
    m_isBackingFile = flag;
}
