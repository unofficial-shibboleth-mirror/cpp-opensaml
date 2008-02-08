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
 * ChainingMetadataProvider.cpp
 * 
 * MetadataProvider that uses multiple providers in sequence.
 */

#include "internal.h"
#include "exceptions.h"
#include "saml/binding/SAMLArtifact.h"
#include "saml2/metadata/ChainingMetadataProvider.h"

#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/util/XMLHelper.h>


using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml2md {
        MetadataProvider* SAML_DLLLOCAL ChainingMetadataProviderFactory(const DOMElement* const & e)
        {
            return new ChainingMetadataProvider(e);
        }
    };
};

static const XMLCh _MetadataProvider[] =    UNICODE_LITERAL_16(M,e,t,a,d,a,t,a,P,r,o,v,i,d,e,r);
static const XMLCh precedence[] =           UNICODE_LITERAL_10(p,r,e,c,e,d,e,n,c,e);
static const XMLCh last[] =                 UNICODE_LITERAL_4(l,a,s,t);
static const XMLCh type[] =                 UNICODE_LITERAL_4(t,y,p,e);

ChainingMetadataProvider::ChainingMetadataProvider(const DOMElement* e)
    : ObservableMetadataProvider(e), m_firstMatch(true), m_tlsKey(NULL), m_log(Category::getInstance(SAML_LOGCAT".Metadata.Chaining"))
{
    if (XMLString::equals(e ? e->getAttributeNS(NULL, precedence) : NULL, last))
        m_firstMatch = false;

    e = e ? XMLHelper::getFirstChildElement(e, _MetadataProvider) : NULL;
    while (e) {
        auto_ptr_char temp(e->getAttributeNS(NULL,type));
        if (temp.get() && *temp.get()) {
            try {
                m_log.info("building MetadataProvider of type %s", temp.get());
                auto_ptr<MetadataProvider> provider(
                    SAMLConfig::getConfig().MetadataProviderManager.newPlugin(temp.get(), e)
                    );
                ObservableMetadataProvider* obs = dynamic_cast<ObservableMetadataProvider*>(provider.get());
                if (obs)
                    obs->addObserver(this);
                m_providers.push_back(provider.get());
                provider.release();
            }
            catch (exception& ex) {
                m_log.error("error building MetadataProvider: %s", ex.what());
            }
        }
        e = XMLHelper::getNextSiblingElement(e, _MetadataProvider);
    }
    m_tlsKey = ThreadKey::create(NULL);
}

ChainingMetadataProvider::~ChainingMetadataProvider()
{
    delete m_tlsKey;
    for_each(m_providers.begin(), m_providers.end(), xmltooling::cleanup<MetadataProvider>());
}

void ChainingMetadataProvider::onEvent(const ObservableMetadataProvider& provider) const
{
    emitChangeEvent();
}

void ChainingMetadataProvider::init()
{
    for (vector<MetadataProvider*>::const_iterator i=m_providers.begin(); i!=m_providers.end(); ++i) {
        try {
            (*i)->init();
        }
        catch (exception& ex) {
            m_log.error("failure initializing MetadataProvider: %s", ex.what());
        }
    }
}

Lockable* ChainingMetadataProvider::lock()
{
    return this;   // we're not lockable ourselves...
}

void ChainingMetadataProvider::unlock()
{
    // Check for a locked provider.
    void* ptr=m_tlsKey->getData();
    if (ptr) {
        m_tlsKey->setData(NULL);
        reinterpret_cast<MetadataProvider*>(ptr)->unlock();
    }
}

const XMLObject* ChainingMetadataProvider::getMetadata() const
{
    throw MetadataException("getMetadata operation not implemented on this provider.");
}

const EntitiesDescriptor* ChainingMetadataProvider::getEntitiesDescriptor(const char* name, bool requireValidMetadata) const
{
    // Clear any existing lock.
    const_cast<ChainingMetadataProvider*>(this)->unlock();

    // Do a search.
    MetadataProvider* held = NULL;
    const EntitiesDescriptor* ret=NULL;
    const EntitiesDescriptor* cur=NULL;
    for (vector<MetadataProvider*>::const_iterator i=m_providers.begin(); i!=m_providers.end(); ++i) {
        (*i)->lock();
        if (cur=(*i)->getEntitiesDescriptor(name,requireValidMetadata)) {
            // Are we using a first match policy?
            if (m_firstMatch) {
                // Save locked provider.
                m_tlsKey->setData(*i);
                return cur;
            }

            // Using last match wins. Did we already have one?
            if (held) {
                m_log.warn("found duplicate EntitiesDescriptor (%s), using last matching copy", name);
                held->unlock();
            }

            // Save off the latest match.
            held = *i;
            ret = cur;
        }
        else {
            // No match, so just unlock this one and move on.
            (*i)->unlock();
        }
    }

    // Preserve any lock we're holding.
    if (held)
        m_tlsKey->setData(held);
    return ret;
}

pair<const EntityDescriptor*,const RoleDescriptor*> ChainingMetadataProvider::getEntityDescriptor(const Criteria& criteria) const
{
    // Clear any existing lock.
    const_cast<ChainingMetadataProvider*>(this)->unlock();

    // Do a search.
    MetadataProvider* held = NULL;
    pair<const EntityDescriptor*,const RoleDescriptor*> ret = pair<const EntityDescriptor*,const RoleDescriptor*>(NULL,NULL);
    pair<const EntityDescriptor*,const RoleDescriptor*> cur = ret;
    for (vector<MetadataProvider*>::const_iterator i=m_providers.begin(); i!=m_providers.end(); ++i) {
        (*i)->lock();
        cur = (*i)->getEntityDescriptor(criteria);
        if (cur.first) {
            if (criteria.role) {
                // We want a role also. Did we find one?
                if (cur.second) {
                    // Are we using a first match policy?
                    if (m_firstMatch) {
                        // We could have an entity-only match from earlier, so unlock it.
                        if (held)
                            held->unlock();
                        // Save locked provider.
                        m_tlsKey->setData(*i);
                        return cur;
                    }

                    // Using last match wins. Did we already have one?
                    if (held) {
                        if (ret.second) {
                            // We had a "complete" match, so log it.
                            if (criteria.entityID_ascii) {
                                m_log.warn("found duplicate EntityDescriptor (%s) with role (%s), using last matching copy",
                                    criteria.entityID_ascii, criteria.role->toString().c_str());
                            }
                            else if (criteria.entityID_unicode) {
                                auto_ptr_char temp(criteria.entityID_unicode);
                                m_log.warn("found duplicate EntityDescriptor (%s) with role (%s), using last matching copy",
                                    temp.get(), criteria.role->toString().c_str());
                            }
                            else if (criteria.artifact) {
                                m_log.warn("found duplicate EntityDescriptor for artifact source (%s) with role (%s), using last matching copy",
                                    criteria.artifact->getSource().c_str(), criteria.role->toString().c_str());
                            }
                        }
                        held->unlock();
                    }

                    // Save off the latest match.
                    held = *i;
                    ret = cur;
                }
                else {
                    // We didn't find the role, so we're going to keep looking,
                    // but save this one if we didn't have the role yet.
                    if (ret.second) {
                        // We already had a role, so let's stick with that.
                        (*i)->unlock();
                    }
                    else {
                        // This is at least as good, so toss anything we had and keep it.
                        if (held)
                            held->unlock();
                        held = *i;
                        ret = cur;
                    }
                }
            }
            else {
                // Are we using a first match policy?
                if (m_firstMatch) {
                    // I don't think this can happen, but who cares, check anyway.
                    if (held)
                        held->unlock();
                    
                    // Save locked provider.
                    m_tlsKey->setData(*i);
                    return cur;
                }

                // Using last match wins. Did we already have one?
                if (held) {
                    if (criteria.entityID_ascii) {
                        m_log.warn("found duplicate EntityDescriptor (%s), using last matching copy", criteria.entityID_ascii);
                    }
                    else if (criteria.entityID_unicode) {
                        auto_ptr_char temp(criteria.entityID_unicode);
                        m_log.warn("found duplicate EntityDescriptor (%s), using last matching copy", temp.get());
                    }
                    else if (criteria.artifact) {
                        m_log.warn("found duplicate EntityDescriptor for artifact source (%s), using last matching copy",
                            criteria.artifact->getSource().c_str());
                    }
                    held->unlock();
                }

                // Save off the latest match.
                held = *i;
                ret = cur;
            }
        }
        else {
            // No match, so just unlock this one and move on.
            (*i)->unlock();
        }
    }

    // Preserve any lock we're holding.
    if (held)
        m_tlsKey->setData(held);
    return ret;
}

const Credential* ChainingMetadataProvider::resolve(const CredentialCriteria* criteria) const
{
    // Check for a locked provider.
    void* ptr=m_tlsKey->getData();
    if (!ptr)
        throw MetadataException("No locked MetadataProvider, where did the role object come from?");

    return reinterpret_cast<MetadataProvider*>(ptr)->resolve(criteria);
}

vector<const Credential*>::size_type ChainingMetadataProvider::resolve(
    vector<const Credential*>& results, const CredentialCriteria* criteria
    ) const
{
    // Check for a locked provider.
    void* ptr=m_tlsKey->getData();
    if (!ptr)
        throw MetadataException("No locked MetadataProvider, where did the role object come from?");

    return reinterpret_cast<MetadataProvider*>(ptr)->resolve(results, criteria);
}
