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
 * AbstractMetadataProvider.cpp
 * 
 * Base class for caching metadata providers.
 */

#include "internal.h"
#include "binding/SAMLArtifact.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/AbstractMetadataProvider.h"
#include "saml2/metadata/MetadataCredentialContext.h"
#include "saml2/metadata/MetadataCredentialCriteria.h"

#include <boost/iterator/indirect_iterator.hpp>
#include <boost/lambda/bind.hpp>
#include <boost/lambda/if.hpp>
#include <boost/lambda/lambda.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/security/Credential.h>
#include <xmltooling/security/KeyInfoResolver.h>
#include <xmltooling/security/SecurityHelper.h>
#include <xmltooling/util/DateTime.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLHelper.h>

using namespace opensaml::saml2md;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace boost::lambda;
using namespace boost;
using namespace std;
using opensaml::SAMLArtifact;

static const XMLCh _KeyInfoResolver[] = UNICODE_LITERAL_15(K,e,y,I,n,f,o,R,e,s,o,l,v,e,r);
static const XMLCh _type[] =            UNICODE_LITERAL_4(t,y,p,e);

AbstractMetadataProvider::AbstractMetadataProvider(const DOMElement* e)
    : ObservableMetadataProvider(e), m_lastUpdate(0),  m_resolver(nullptr), m_credentialLock(Mutex::create())
{
    e = XMLHelper::getFirstChildElement(e, _KeyInfoResolver);
    if (e) {
        string t = XMLHelper::getAttrString(e, nullptr, _type);
        if (!t.empty()) {
            m_resolverWrapper.reset(XMLToolingConfig::getConfig().KeyInfoResolverManager.newPlugin(t.c_str(), e));
            m_resolver = m_resolverWrapper.get();
        }
        else {
            throw UnknownExtensionException("<KeyInfoResolver> element found with no type attribute");
        }
    }
}

AbstractMetadataProvider::~AbstractMetadataProvider()
{
    for (credmap_t::iterator c = m_credentialMap.begin(); c!=m_credentialMap.end(); ++c)
        for_each(c->second.begin(), c->second.end(), xmltooling::cleanup<Credential>());
}

void AbstractMetadataProvider::outputStatus(ostream& os) const
{
    os << "<MetadataProvider";

    if (getId() && *getId()) {
        os << " id='" << getId() << "'";
    }

    if (m_lastUpdate > 0) {
        DateTime ts(m_lastUpdate);
        ts.parseDateTime();
        auto_ptr_char timestamp(ts.getFormattedString());
        os << " lastUpdate='" << timestamp.get() << "'";
    }

    os << "/>";
}

void AbstractMetadataProvider::emitChangeEvent() const
{
    for (credmap_t::iterator c = m_credentialMap.begin(); c!=m_credentialMap.end(); ++c)
        for_each(c->second.begin(), c->second.end(), xmltooling::cleanup<Credential>());
    m_credentialMap.clear();
    ObservableMetadataProvider::emitChangeEvent();
}

void AbstractMetadataProvider::emitChangeEvent(const EntityDescriptor& entity) const
{
    for (credmap_t::iterator c = m_credentialMap.begin(); c!=m_credentialMap.end(); ++c)
        for_each(c->second.begin(), c->second.end(), xmltooling::cleanup<Credential>());
    m_credentialMap.clear();
    ObservableMetadataProvider::emitChangeEvent(entity);
}

void AbstractMetadataProvider::indexEntity(EntityDescriptor* site, time_t& validUntil, bool replace) const
{
    // If child expires later than input, reset child, otherwise lower input to match.
    if (validUntil < site->getValidUntilEpoch())
        site->setValidUntil(validUntil);
    else
        validUntil = site->getValidUntilEpoch();

    auto_ptr_char id(site->getEntityID());
    if (id.get()) {
        if (replace) {
            // The data structure here needs work.
            // We have to find all the sites stored against the replaced ID. Then we have to
            // search for those sites in the entire set of sites tracked by the sources map and
            // remove them from both places.
            set<const EntityDescriptor*> existingSites;
            pair<sitemap_t::iterator,sitemap_t::iterator> existingRange = m_sites.equal_range(id.get());
            static pair<set<const EntityDescriptor*>::iterator,bool> (set<const EntityDescriptor*>::* ins)(const EntityDescriptor* const &) =
                &set<const EntityDescriptor*>::insert;
            for_each(
                existingRange.first, existingRange.second,
                lambda::bind(ins, boost::ref(existingSites), lambda::bind(&sitemap_t::value_type::second, _1))
                );
            m_sites.erase(existingRange.first, existingRange.second);
            for (sitemap_t::iterator s = m_sources.begin(); s != m_sources.end();) {
                if (existingSites.count(s->second) > 0) {
                    sitemap_t::iterator temp = s;
                    ++s;
                    m_sources.erase(temp);
                }
                else {
                    ++s;
                }
            }
        }
        m_sites.insert(sitemap_t::value_type(id.get(),site));
    }
    
    // Process each IdP role.
    const vector<IDPSSODescriptor*>& roles = const_cast<const EntityDescriptor*>(site)->getIDPSSODescriptors();
    for (vector<IDPSSODescriptor*>::const_iterator i = roles.begin(); i != roles.end(); i++) {
        // SAML 1.x?
        if ((*i)->hasSupport(samlconstants::SAML10_PROTOCOL_ENUM) || (*i)->hasSupport(samlconstants::SAML11_PROTOCOL_ENUM)) {
            // Check for SourceID extension element.
            const Extensions* exts = (*i)->getExtensions();
            if (exts && exts->hasChildren()) {
                const vector<XMLObject*>& children = exts->getUnknownXMLObjects();
                for (vector<XMLObject*>::const_iterator ext = children.begin(); ext != children.end(); ++ext) {
                    SourceID* sid = dynamic_cast<SourceID*>(*ext);
                    if (sid) {
                        auto_ptr_char sourceid(sid->getID());
                        if (sourceid.get()) {
                            m_sources.insert(sitemap_t::value_type(sourceid.get(),site));
                            break;
                        }
                    }
                }
            }
            
            // Hash the ID.
            m_sources.insert(sitemap_t::value_type(SecurityHelper::doHash("SHA1", id.get(), strlen(id.get())),site));
                
            // Load endpoints for type 0x0002 artifacts.
            const vector<ArtifactResolutionService*>& locs = const_cast<const IDPSSODescriptor*>(*i)->getArtifactResolutionServices();
            for (vector<ArtifactResolutionService*>::const_iterator loc = locs.begin(); loc != locs.end(); loc++) {
                auto_ptr_char location((*loc)->getLocation());
                if (location.get())
                    m_sources.insert(sitemap_t::value_type(location.get(),site));
            }
        }
        
        // SAML 2.0?
        if ((*i)->hasSupport(samlconstants::SAML20P_NS)) {
            // Hash the ID.
            m_sources.insert(sitemap_t::value_type(SecurityHelper::doHash("SHA1", id.get(), strlen(id.get())),site));
        }
    }
}

void AbstractMetadataProvider::indexGroup(EntitiesDescriptor* group, time_t& validUntil) const
{
    // If child expires later than input, reset child, otherwise lower input to match.
    if (validUntil < group->getValidUntilEpoch())
        group->setValidUntil(validUntil);
    else
        validUntil = group->getValidUntilEpoch();

    auto_ptr_char name(group->getName());
    if (name.get()) {
        m_groups.insert(groupmap_t::value_type(name.get(),group));
    }
    
    // Track the smallest validUntil amongst the children.
    time_t minValidUntil = validUntil;

    const vector<EntitiesDescriptor*>& groups = const_cast<const EntitiesDescriptor*>(group)->getEntitiesDescriptors();
    for (vector<EntitiesDescriptor*>::const_iterator i = groups.begin(); i != groups.end(); i++) {
        // Use the current validUntil fence for each child, but track the smallest we find.
        time_t subValidUntil = validUntil;
        indexGroup(*i, subValidUntil);
        if (subValidUntil < minValidUntil)
            minValidUntil = subValidUntil;
    }

    const vector<EntityDescriptor*>& sites = const_cast<const EntitiesDescriptor*>(group)->getEntityDescriptors();
    for (vector<EntityDescriptor*>::const_iterator j = sites.begin(); j != sites.end(); j++) {
        // Use the current validUntil fence for each child, but track the smallest we find.
        time_t subValidUntil = validUntil;
        indexEntity(*j, subValidUntil);
        if (subValidUntil < minValidUntil)
            minValidUntil = subValidUntil;
    }

    // Pass back up the smallest child we found.
    if (minValidUntil < validUntil)
        validUntil = minValidUntil;
}

void AbstractMetadataProvider::index(EntityDescriptor* site, time_t validUntil, bool replace) const
{
    indexEntity(site, validUntil, replace);
}

void AbstractMetadataProvider::index(EntitiesDescriptor* group, time_t validUntil) const
{
    indexGroup(group, validUntil);
}

void AbstractMetadataProvider::clearDescriptorIndex(bool freeSites)
{
    if (freeSites)
        for_each(m_sites.begin(), m_sites.end(), cleanup_const_pair<string,EntityDescriptor>());
    m_sites.clear();
    m_groups.clear();
    m_sources.clear();
}

const EntitiesDescriptor* AbstractMetadataProvider::getEntitiesDescriptor(const char* name, bool strict) const
{
    pair<groupmap_t::const_iterator,groupmap_t::const_iterator> range=const_cast<const groupmap_t&>(m_groups).equal_range(name);

    time_t now=time(nullptr);
    for (groupmap_t::const_iterator i=range.first; i!=range.second; i++)
        if (now < i->second->getValidUntilEpoch())
            return i->second;
    
    if (range.first != range.second) {
        Category& log = Category::getInstance(SAML_LOGCAT".MetadataProvider");
        if (strict) {
            log.warn("ignored expired metadata group (%s)", range.first->first.c_str());
        }
        else {
            log.info("no valid metadata found, returning expired metadata group (%s)", range.first->first.c_str());
            return range.first->second;
        }
    }

    return nullptr;
}

pair<const EntityDescriptor*,const RoleDescriptor*> AbstractMetadataProvider::getEntityDescriptor(const Criteria& criteria) const
{
    pair<sitemap_t::const_iterator,sitemap_t::const_iterator> range;
    if (criteria.entityID_ascii)
        range = const_cast<const sitemap_t&>(m_sites).equal_range(criteria.entityID_ascii);
    else if (criteria.entityID_unicode) {
        auto_ptr_char id(criteria.entityID_unicode);
        range = const_cast<const sitemap_t&>(m_sites).equal_range(id.get());
    }
    else if (criteria.artifact)
        range = const_cast<const sitemap_t&>(m_sources).equal_range(criteria.artifact->getSource());
    else
        return pair<const EntityDescriptor*,const RoleDescriptor*>(nullptr,nullptr);
    
    pair<const EntityDescriptor*,const RoleDescriptor*> result;
    result.first = nullptr;
    result.second = nullptr;
    
    time_t now=time(nullptr);
    for (sitemap_t::const_iterator i=range.first; i!=range.second; i++) {
        if (now < i->second->getValidUntilEpoch()) {
            result.first = i->second;
            break;
        }
    }
    
    if (!result.first && range.first!=range.second) {
        Category& log = Category::getInstance(SAML_LOGCAT".MetadataProvider");
        if (criteria.validOnly) {
            log.warn("ignored expired metadata instance for (%s)", range.first->first.c_str());
        }
        else {
            log.info("no valid metadata found, returning expired instance for (%s)", range.first->first.c_str());
            result.first = range.first->second;
        }
    }

    if (result.first && criteria.role) {
        result.second = result.first->getRoleDescriptor(*criteria.role, criteria.protocol);
        if (!result.second && criteria.protocol2)
            result.second = result.first->getRoleDescriptor(*criteria.role, criteria.protocol2);
    }
    
    return result;
}

const Credential* AbstractMetadataProvider::resolve(const CredentialCriteria* criteria) const
{
    const MetadataCredentialCriteria* metacrit = dynamic_cast<const MetadataCredentialCriteria*>(criteria);
    if (!metacrit)
        throw MetadataException("Cannot resolve credentials without a MetadataCredentialCriteria object.");

    Lock lock(m_credentialLock);
    const credmap_t::mapped_type& creds = resolveCredentials(metacrit->getRole());

    for (credmap_t::mapped_type::const_iterator c = creds.begin(); c!=creds.end(); ++c)
	if (metacrit->matches(*(*c)))
	return *c;
return nullptr;
}

vector<const Credential*>::size_type AbstractMetadataProvider::resolve(
    vector<const Credential*>& results, const CredentialCriteria* criteria
    ) const
{
    const MetadataCredentialCriteria* metacrit = dynamic_cast<const MetadataCredentialCriteria*>(criteria);
    if (!metacrit)
        throw MetadataException("Cannot resolve credentials without a MetadataCredentialCriteria object.");

    Lock lock(m_credentialLock);
    const credmap_t::mapped_type& creds = resolveCredentials(metacrit->getRole());

   for (credmap_t::mapped_type::const_iterator c = creds.begin(); c!=creds.end(); ++c)
	if (metacrit->matches(*(*c)))
	    results.push_back(*c); 
    return results.size();
}

const AbstractMetadataProvider::credmap_t::mapped_type& AbstractMetadataProvider::resolveCredentials(const RoleDescriptor& role) const
{
    credmap_t::const_iterator i = m_credentialMap.find(&role);
    if (i != m_credentialMap.end())
        return i->second;

    const KeyInfoResolver* resolver = m_resolver ? m_resolver : XMLToolingConfig::getConfig().getKeyInfoResolver();
    const vector<KeyDescriptor*>& keys = role.getKeyDescriptors();
    AbstractMetadataProvider::credmap_t::mapped_type& resolved = m_credentialMap[&role];
    for (indirect_iterator<vector<KeyDescriptor*>::const_iterator> k = make_indirect_iterator(keys.begin());
            k != make_indirect_iterator(keys.end()); ++k) {
        if (k->getKeyInfo()) {
            auto_ptr<MetadataCredentialContext> mcc(new MetadataCredentialContext(*k));
            auto_ptr<Credential> c(resolver->resolve(mcc.get()));
            if (c.get()) {
                mcc.release();  // this API sucks, the object is now owned by the Credential
                resolved.push_back(c.get());
                c.release();
            }
        }
    }
    return resolved;
}
