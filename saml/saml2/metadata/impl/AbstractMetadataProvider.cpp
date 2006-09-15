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
 * AbstractMetadataProvider.cpp
 * 
 * Base class for caching metadata providers.
 */

#include "internal.h"
#include "binding/SAMLArtifact.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/AbstractMetadataProvider.h"

#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/signature/CachingKeyResolver.h>
#include <xmltooling/util/XMLHelper.h>

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

static const XMLCh GenericKeyResolver[] =           UNICODE_LITERAL_11(K,e,y,R,e,s,o,l,v,e,r);
static const XMLCh type[] =                         UNICODE_LITERAL_4(t,y,p,e);

AbstractMetadataProvider::AbstractMetadataProvider(const DOMElement* e) : ObservableMetadataProvider(e), m_resolver(NULL)
{
    e = e ? XMLHelper::getFirstChildElement(e, GenericKeyResolver) : NULL;
    if (e) {
        auto_ptr_char t(e->getAttributeNS(NULL,type));
        if (t.get())
            m_resolver = XMLToolingConfig::getConfig().KeyResolverManager.newPlugin(t.get(),e);
        else
            throw UnknownExtensionException("<KeyResolver> element found with no type attribute");
    }
    
    if (!m_resolver) {
        m_resolver = XMLToolingConfig::getConfig().KeyResolverManager.newPlugin(INLINE_KEY_RESOLVER, NULL);
    }
}

AbstractMetadataProvider::~AbstractMetadataProvider()
{
    delete m_resolver;
}

void AbstractMetadataProvider::emitChangeEvent()
{
    xmlsignature::CachingKeyResolver* ckr=dynamic_cast<xmlsignature::CachingKeyResolver*>(m_resolver);
    if (ckr)
        ckr->clearCache();
    ObservableMetadataProvider::emitChangeEvent();    
}

void AbstractMetadataProvider::index(EntityDescriptor* site, time_t validUntil)
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

void AbstractMetadataProvider::index(EntitiesDescriptor* group, time_t validUntil)
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

void AbstractMetadataProvider::clearDescriptorIndex()
{
    m_sources.clear();
    m_sites.clear();
    m_groups.clear();
}

const EntitiesDescriptor* AbstractMetadataProvider::getEntitiesDescriptor(const char* name, bool strict) const
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

const EntityDescriptor* AbstractMetadataProvider::getEntityDescriptor(const char* name, bool strict) const
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

const EntityDescriptor* AbstractMetadataProvider::getEntityDescriptor(const SAMLArtifact* artifact) const
{
    pair<sitemap_t::const_iterator,sitemap_t::const_iterator> range=m_sources.equal_range(artifact->getSource());

    time_t now=time(NULL);
    for (sitemap_t::const_iterator i=range.first; i!=range.second; i++)
        if (now < i->second->getValidUntilEpoch())
            return i->second;

    return NULL;
}
