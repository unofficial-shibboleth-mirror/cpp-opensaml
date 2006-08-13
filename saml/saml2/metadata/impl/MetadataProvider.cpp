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
 * MetadataProvider.cpp
 * 
 * Registration of factories for built-in providers
 */

#include "internal.h"
#include "SAMLArtifact.h"
#include "saml2/metadata/MetadataProvider.h"

#include <log4cpp/Category.hh>
#include <xmltooling/util/NDC.h>

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    namespace saml2md {
        SAML_DLLLOCAL PluginManager<MetadataProvider,const DOMElement*>::Factory FilesystemMetadataProviderFactory; 
        SAML_DLLLOCAL PluginManager<MetadataFilter,const DOMElement*>::Factory BlacklistMetadataFilterFactory; 
        SAML_DLLLOCAL PluginManager<MetadataFilter,const DOMElement*>::Factory WhitelistMetadataFilterFactory; 
    };
};

void SAML_API opensaml::saml2md::registerMetadataProviders()
{
    SAMLConfig& conf=SAMLConfig::getConfig();
    conf.MetadataProviderManager.registerFactory(FILESYSTEM_METADATA_PROVIDER, FilesystemMetadataProviderFactory);
    conf.MetadataProviderManager.registerFactory("edu.internet2.middleware.shibboleth.metadata.provider.XMLMetadata", FilesystemMetadataProviderFactory);
    conf.MetadataProviderManager.registerFactory("edu.internet2.middleware.shibboleth.common.provider.XMLMetadata", FilesystemMetadataProviderFactory);
}

void SAML_API opensaml::saml2md::registerMetadataFilters()
{
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(BLACKLIST_METADATA_FILTER, BlacklistMetadataFilterFactory);
    SAMLConfig::getConfig().MetadataFilterManager.registerFactory(WHITELIST_METADATA_FILTER, WhitelistMetadataFilterFactory);
}

static const XMLCh Blacklist[] =                    UNICODE_LITERAL_23(B,l,a,c,k,l,i,s,t,M,e,t,a,d,a,t,a,F,i,l,t,e,r);
static const XMLCh Whitelist[] =                    UNICODE_LITERAL_23(W,h,i,t,e,l,i,s,t,M,e,t,a,d,a,t,a,F,i,l,t,e,r);
static const XMLCh Exclude[] =                      UNICODE_LITERAL_7(E,x,c,l,u,d,e);
static const XMLCh Include[] =                      UNICODE_LITERAL_7(I,n,c,l,u,d,e);
static const XMLCh GenericKeyResolver[] =           UNICODE_LITERAL_11(K,e,y,R,e,s,o,l,v,e,r);
static const XMLCh GenericMetadataFilter[] =        UNICODE_LITERAL_14(M,e,t,a,d,a,t,a,F,i,l,t,e,r);
static const XMLCh type[] =                         UNICODE_LITERAL_4(t,y,p,e);

MetadataProvider::MetadataProvider(const DOMElement* e) : m_resolver(NULL)
{
#ifdef _DEBUG
    NDC ndc("MetadataProvider");
#endif
    SAMLConfig& conf=SAMLConfig::getConfig();
    
    // Locate any default recognized filters and plugins.
    try {
        DOMElement* child = e ? XMLHelper::getFirstChildElement(e) : NULL;
        while (child) {
            if (!m_resolver && XMLString::equals(child->getLocalName(),GenericKeyResolver)) {
                auto_ptr_char t(child->getAttributeNS(NULL,type));
                if (t.get())
                    m_resolver = XMLToolingConfig::getConfig().KeyResolverManager.newPlugin(t.get(),child);
            }
            else if (XMLString::equals(child->getLocalName(),GenericMetadataFilter)) {
                auto_ptr_char t(child->getAttributeNS(NULL,type));
                if (t.get())
                    m_filters.push_back(conf.MetadataFilterManager.newPlugin(t.get(),child));
            }
            else if (XMLString::equals(child->getLocalName(),Whitelist)) {
                m_filters.push_back(conf.MetadataFilterManager.newPlugin(WHITELIST_METADATA_FILTER,child));
            }
            else if (XMLString::equals(child->getLocalName(),Blacklist)) {
                m_filters.push_back(conf.MetadataFilterManager.newPlugin(BLACKLIST_METADATA_FILTER,child));
            }
            else if (XMLString::equals(child->getLocalName(),Include)) {
                m_filters.push_back(conf.MetadataFilterManager.newPlugin(WHITELIST_METADATA_FILTER,e));
            }
            else if (XMLString::equals(child->getLocalName(),Exclude)) {
                m_filters.push_back(conf.MetadataFilterManager.newPlugin(BLACKLIST_METADATA_FILTER,e));
            }
            child = XMLHelper::getNextSiblingElement(child);
        }
        
        if (!m_resolver) {
            m_resolver = XMLToolingConfig::getConfig().KeyResolverManager.newPlugin(INLINE_KEY_RESOLVER, child);
        }
    }
    catch (XMLToolingException& ex) {
        Category::getInstance(SAML_LOGCAT".Metadata").error("caught exception while installing plugins and filters: %s", ex.what());
        delete m_resolver;
        for_each(m_filters.begin(),m_filters.end(),xmltooling::cleanup<MetadataFilter>());
        throw;
    }
}

MetadataProvider::~MetadataProvider()
{
    delete m_resolver;
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

void MetadataProvider::index(EntityDescriptor* site, time_t validUntil)
{
    if (validUntil < site->getValidUntilEpoch())
        site->setValidUntil(validUntil);

    auto_ptr_char id(site->getEntityID());
    if (id.get()) {
        m_sites.insert(make_pair(id.get(),site));
    }
    
    // Process each IdP role.
    const vector<IDPSSODescriptor*>& roles=const_cast<const EntityDescriptor*>(site)->getIDPSSODescriptors();
    for (vector<IDPSSODescriptor*>::const_iterator i=roles.begin(); i!=roles.end(); i++) {
        // SAML 1.x?
        if ((*i)->hasSupport(SAMLConstants::SAML10_PROTOCOL_ENUM) || (*i)->hasSupport(SAMLConstants::SAML11_PROTOCOL_ENUM)) {
            // Check for SourceID extension element.
            const Extensions* exts=(*i)->getExtensions();
            if (exts) {
                const list<XMLObject*>& children=exts->getXMLObjects();
                for (list<XMLObject*>::const_iterator ext=children.begin(); ext!=children.end(); ext++) {
                    SourceID* sid=dynamic_cast<SourceID*>(*ext);
                    if (sid) {
                        auto_ptr_char sourceid(sid->getID());
                        if (sourceid.get()) {
                            m_sources.insert(pair<string,const EntityDescriptor*>(sourceid.get(),site));
                            break;
                        }
                    }
                }
            }
            
            // Hash the ID.
            m_sources.insert(
                pair<string,const EntityDescriptor*>(SAMLConfig::getConfig().hashSHA1(id.get(), true),site)
                );
                
            // Load endpoints for type 0x0002 artifacts.
            const vector<ArtifactResolutionService*>& locs=const_cast<const IDPSSODescriptor*>(*i)->getArtifactResolutionServices();
            for (vector<ArtifactResolutionService*>::const_iterator loc=locs.begin(); loc!=locs.end(); loc++) {
                auto_ptr_char location((*loc)->getLocation());
                if (location.get())
                    m_sources.insert(pair<string,const EntityDescriptor*>(location.get(),site));
            }
        }
        
        // SAML 2.0?
        if ((*i)->hasSupport(SAMLConstants::SAML20P_NS)) {
            // Hash the ID.
            m_sources.insert(
                pair<string,const EntityDescriptor*>(SAMLConfig::getConfig().hashSHA1(id.get(), true),site)
                );
        }
    }
}

void MetadataProvider::index(EntitiesDescriptor* group, time_t validUntil)
{
    if (validUntil < group->getValidUntilEpoch())
        group->setValidUntil(validUntil);

    auto_ptr_char name(group->getName());
    if (name.get()) {
        m_groups.insert(make_pair(name.get(),group));
    }
    
    const vector<EntitiesDescriptor*>& groups=const_cast<const EntitiesDescriptor*>(group)->getEntitiesDescriptors();
    for (vector<EntitiesDescriptor*>::const_iterator i=groups.begin(); i!=groups.end(); i++)
        index(*i,group->getValidUntilEpoch());

    const vector<EntityDescriptor*>& sites=const_cast<const EntitiesDescriptor*>(group)->getEntityDescriptors();
    for (vector<EntityDescriptor*>::const_iterator j=sites.begin(); j!=sites.end(); j++)
        index(*j,group->getValidUntilEpoch());
}

void MetadataProvider::clearDescriptorIndex()
{
    m_sources.clear();
    m_sites.clear();
    m_groups.clear();
}

const EntitiesDescriptor* MetadataProvider::getEntitiesDescriptor(const char* name, bool strict) const
{
    pair<groupmap_t::const_iterator,groupmap_t::const_iterator> range=m_groups.equal_range(name);

    time_t now=time(NULL);
    for (groupmap_t::const_iterator i=range.first; i!=range.second; i++)
        if (now < i->second->getValidUntilEpoch())
            return i->second;
    
    if (!strict && range.first!=range.second)
        return range.first->second;
        
    return NULL;
}

const EntitiesDescriptor* MetadataProvider::getEntitiesDescriptor(const XMLCh* name, bool strict) const
{
    auto_ptr_char temp(name);
    return getEntitiesDescriptor(temp.get(),strict);
}

const EntityDescriptor* MetadataProvider::getEntityDescriptor(const char* name, bool strict) const
{
    pair<sitemap_t::const_iterator,sitemap_t::const_iterator> range=m_sites.equal_range(name);

    time_t now=time(NULL);
    for (sitemap_t::const_iterator i=range.first; i!=range.second; i++)
        if (now < i->second->getValidUntilEpoch())
            return i->second;
    
    if (!strict && range.first!=range.second)
        return range.first->second;
        
    return NULL;
}

const EntityDescriptor* MetadataProvider::getEntityDescriptor(const XMLCh* name, bool strict) const
{
    auto_ptr_char temp(name);
    return getEntityDescriptor(temp.get(),strict);
}

const EntityDescriptor* MetadataProvider::getEntityDescriptor(const SAMLArtifact* artifact) const
{
    pair<sitemap_t::const_iterator,sitemap_t::const_iterator> range=m_sources.equal_range(artifact->getSource());

    time_t now=time(NULL);
    for (sitemap_t::const_iterator i=range.first; i!=range.second; i++)
        if (now < i->second->getValidUntilEpoch())
            return i->second;

    return NULL;
}
