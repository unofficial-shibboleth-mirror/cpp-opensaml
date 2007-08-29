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
 * MetadataProvider.cpp
 * 
 * Registration of factories for built-in providers
 */

#include "internal.h"
#include "saml2/metadata/MetadataFilter.h"
#include "saml2/metadata/MetadataProvider.h"

#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/XMLHelper.h>

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml2md {
        SAML_DLLLOCAL PluginManager<MetadataProvider,string,const DOMElement*>::Factory XMLMetadataProviderFactory;
        SAML_DLLLOCAL PluginManager<MetadataProvider,string,const DOMElement*>::Factory DynamicMetadataProviderFactory;
        SAML_DLLLOCAL PluginManager<MetadataProvider,string,const DOMElement*>::Factory ChainingMetadataProviderFactory;
        SAML_DLLLOCAL PluginManager<MetadataFilter,string,const DOMElement*>::Factory BlacklistMetadataFilterFactory;
        SAML_DLLLOCAL PluginManager<MetadataFilter,string,const DOMElement*>::Factory WhitelistMetadataFilterFactory;
        SAML_DLLLOCAL PluginManager<MetadataFilter,string,const DOMElement*>::Factory SignatureMetadataFilterFactory;
    };
};

void SAML_API opensaml::saml2md::registerMetadataProviders()
{
    SAMLConfig& conf=SAMLConfig::getConfig();
    conf.MetadataProviderManager.registerFactory(XML_METADATA_PROVIDER, XMLMetadataProviderFactory);
    conf.MetadataProviderManager.registerFactory(DYNAMIC_METADATA_PROVIDER, DynamicMetadataProviderFactory);
    conf.MetadataProviderManager.registerFactory(CHAINING_METADATA_PROVIDER, ChainingMetadataProviderFactory);
}

void SAML_API opensaml::saml2md::registerMetadataFilters()
{
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(BLACKLIST_METADATA_FILTER, BlacklistMetadataFilterFactory);
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(WHITELIST_METADATA_FILTER, WhitelistMetadataFilterFactory);
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(SIGNATURE_METADATA_FILTER, SignatureMetadataFilterFactory);
}

static const XMLCh _MetadataFilter[] =  UNICODE_LITERAL_14(M,e,t,a,d,a,t,a,F,i,l,t,e,r);
static const XMLCh Blacklist[] =        UNICODE_LITERAL_23(B,l,a,c,k,l,i,s,t,M,e,t,a,d,a,t,a,F,i,l,t,e,r);
static const XMLCh Whitelist[] =        UNICODE_LITERAL_23(W,h,i,t,e,l,i,s,t,M,e,t,a,d,a,t,a,F,i,l,t,e,r);
static const XMLCh SigFilter[] =        UNICODE_LITERAL_23(S,i,g,n,a,t,u,r,e,M,e,t,a,d,a,t,a,F,i,l,t,e,r);
static const XMLCh Exclude[] =          UNICODE_LITERAL_7(E,x,c,l,u,d,e);
static const XMLCh Include[] =          UNICODE_LITERAL_7(I,n,c,l,u,d,e);
static const XMLCh type[] =             UNICODE_LITERAL_4(t,y,p,e);

MetadataProvider::MetadataProvider(const DOMElement* e)
{
#ifdef _DEBUG
    NDC ndc("MetadataProvider");
#endif
    Category& log = Category::getInstance(SAML_LOGCAT".Metadata");
    SAMLConfig& conf=SAMLConfig::getConfig();
    
    // Locate any default recognized filters and plugins.
    try {
        DOMElement* child = e ? XMLHelper::getFirstChildElement(e) : NULL;
        while (child) {
            if (XMLString::equals(child->getLocalName(),_MetadataFilter)) {
                auto_ptr_char t(child->getAttributeNS(NULL,type));
                if (t.get() && *t.get()) {
                    log.info("building MetadataFilter of type %s", t.get());
                    m_filters.push_back(conf.MetadataFilterManager.newPlugin(t.get(),child));
                }
            }
            else if (XMLString::equals(child->getLocalName(),SigFilter)) {
                log.info("building MetadataFilter of type %s", SIGNATURE_METADATA_FILTER);
                m_filters.push_back(conf.MetadataFilterManager.newPlugin(SIGNATURE_METADATA_FILTER,child));
            }
            else if (XMLString::equals(child->getLocalName(),Whitelist)) {
                log.info("building MetadataFilter of type %s", WHITELIST_METADATA_FILTER);
                m_filters.push_back(conf.MetadataFilterManager.newPlugin(WHITELIST_METADATA_FILTER,child));
            }
            else if (XMLString::equals(child->getLocalName(),Blacklist)) {
                log.info("building MetadataFilter of type %s", BLACKLIST_METADATA_FILTER);
                m_filters.push_back(conf.MetadataFilterManager.newPlugin(BLACKLIST_METADATA_FILTER,child));
            }
            else if (XMLString::equals(child->getLocalName(),Include)) {
                log.info("building MetadataFilter of type %s", WHITELIST_METADATA_FILTER);
                m_filters.push_back(conf.MetadataFilterManager.newPlugin(WHITELIST_METADATA_FILTER,e));
            }
            else if (XMLString::equals(child->getLocalName(),Exclude)) {
                log.info("building MetadataFilter of type %s", BLACKLIST_METADATA_FILTER);
                m_filters.push_back(conf.MetadataFilterManager.newPlugin(BLACKLIST_METADATA_FILTER,e));
            }
            child = XMLHelper::getNextSiblingElement(child);
        }
    }
    catch (XMLToolingException& ex) {
        log.error("caught exception while installing filters: %s", ex.what());
        for_each(m_filters.begin(),m_filters.end(),xmltooling::cleanup<MetadataFilter>());
        throw;
    }
}

MetadataProvider::~MetadataProvider()
{
    for_each(m_filters.begin(),m_filters.end(),xmltooling::cleanup<MetadataFilter>());
}

void MetadataProvider::doFilters(XMLObject& xmlObject) const
{
#ifdef _DEBUG
    NDC ndc("doFilters");
#endif
    Category& log=Category::getInstance(SAML_LOGCAT".Metadata");
    for (std::vector<MetadataFilter*>::const_iterator i=m_filters.begin(); i!=m_filters.end(); i++) {
        log.info("applying metadata filter (%s)", (*i)->getId());
        (*i)->doFilter(xmlObject);
    }
}

const EntitiesDescriptor* MetadataProvider::getEntitiesDescriptor(const XMLCh* name, bool strict) const
{
    auto_ptr_char temp(name);
    return getEntitiesDescriptor(temp.get(),strict);
}

const EntityDescriptor* MetadataProvider::getEntityDescriptor(const XMLCh* name, bool strict) const
{
    auto_ptr_char temp(name);
    return getEntityDescriptor(temp.get(),strict);
}
