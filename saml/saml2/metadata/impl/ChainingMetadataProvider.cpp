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
 * ChainingMetadataProvider.cpp
 * 
 * MetadataProvider that uses multiple providers in sequence.
 */

#include "internal.h"
#include "exceptions.h"
#include "saml/binding/SAMLArtifact.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/DiscoverableMetadataProvider.h"
#include "saml2/metadata/ObservableMetadataProvider.h"
#include "saml2/metadata/MetadataCredentialCriteria.h"

#include <memory>
#include <functional>
#include <boost/bind.hpp>
#include <boost/ptr_container/ptr_vector.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLHelper.h>


using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace opensaml {
    namespace saml2md {

        // per-thread structure allocated to track locks and role->provider mappings
        struct SAML_DLLLOCAL tracker_t;
        
        class SAML_DLLLOCAL ChainingMetadataProvider
            : public DiscoverableMetadataProvider, public ObservableMetadataProvider, public ObservableMetadataProvider::Observer {
        public:
            ChainingMetadataProvider(const xercesc::DOMElement* e=nullptr);
            virtual ~ChainingMetadataProvider();
    
            using MetadataProvider::getEntityDescriptor;
            using MetadataProvider::getEntitiesDescriptor;

            Lockable* lock();
            void unlock();
            void init();
            void outputStatus(ostream& os) const;
            const XMLObject* getMetadata() const;
            const EntitiesDescriptor* getEntitiesDescriptor(const char* name, bool requireValidMetadata=true) const;
            pair<const EntityDescriptor*,const RoleDescriptor*> getEntityDescriptor(const Criteria& criteria) const;
    
            const Credential* resolve(const CredentialCriteria* criteria=nullptr) const;
            vector<const Credential*>::size_type resolve(vector<const Credential*>& results, const CredentialCriteria* criteria=nullptr) const;

            string getCacheTag() const {
                Lock lock(m_trackerLock);
                return m_feedTag;
            }

            void outputFeed(ostream& os, bool& first, bool wrapArray=true) const {
                if (wrapArray)
                    os << '[';
                // Lock each provider in turn and suck in its feed.
                for (ptr_vector<MetadataProvider>::iterator m = m_providers.begin(); m != m_providers.end(); ++m) {
                    DiscoverableMetadataProvider* d = dynamic_cast<DiscoverableMetadataProvider*>(&(*m));
                    if (d) {
                        Locker locker(d);
                        d->outputFeed(os, first, false);
                    }
                }
                if (wrapArray)
                    os << "\n]";
            }

            void onEvent(const ObservableMetadataProvider& provider) const {
                // Reset the cache tag for the feed.
                Lock lock(m_trackerLock);
                SAMLConfig::getConfig().generateRandomBytes(m_feedTag, 4);
                m_feedTag = SAMLArtifact::toHex(m_feedTag);
                emitChangeEvent();
            }

        protected:
            void generateFeed() {
                // No-op.
            }

        private:
            bool m_firstMatch;
            mutable auto_ptr<Mutex> m_trackerLock;
            auto_ptr<ThreadKey> m_tlsKey;
            mutable ptr_vector<MetadataProvider> m_providers;
            mutable set<tracker_t*> m_trackers;
            static void tracker_cleanup(void*);
            Category& m_log;
            friend struct tracker_t;
        };

        struct SAML_DLLLOCAL tracker_t {
            tracker_t(const ChainingMetadataProvider* m) : m_metadata(m) {
                Lock lock(m_metadata->m_trackerLock);
                m_metadata->m_trackers.insert(this);
            }

            void lock_if(MetadataProvider* m) {
                if (m_locked.count(m) == 0)
                    m->lock();
            }

            void unlock_if(MetadataProvider* m) {
                if (m_locked.count(m) == 0)
                    m->unlock();
            }

            void remember(MetadataProvider* m, const EntityDescriptor* entity=nullptr) {
                m_locked.insert(m);
                if (entity)
                    m_objectMap.insert(pair<const XMLObject*,const MetadataProvider*>(entity,m));
            }

            const MetadataProvider* getProvider(const RoleDescriptor& role) {
                map<const XMLObject*,const MetadataProvider*>::const_iterator i = m_objectMap.find(role.getParent());
                return (i != m_objectMap.end()) ? i->second : nullptr;
            }

            const ChainingMetadataProvider* m_metadata;
            set<MetadataProvider*> m_locked;
            map<const XMLObject*,const MetadataProvider*> m_objectMap;
        };

        MetadataProvider* SAML_DLLLOCAL ChainingMetadataProviderFactory(const DOMElement* const & e)
        {
            return new ChainingMetadataProvider(e);
        }

        static const XMLCh _MetadataProvider[] =    UNICODE_LITERAL_16(M,e,t,a,d,a,t,a,P,r,o,v,i,d,e,r);
        static const XMLCh precedence[] =           UNICODE_LITERAL_10(p,r,e,c,e,d,e,n,c,e);
        static const XMLCh last[] =                 UNICODE_LITERAL_4(l,a,s,t);
        static const XMLCh _type[] =                 UNICODE_LITERAL_4(t,y,p,e);
    };
};

void ChainingMetadataProvider::tracker_cleanup(void* ptr)
{
    if (ptr) {
        // free the tracker after removing it from the parent plugin's tracker set
        tracker_t* t = reinterpret_cast<tracker_t*>(ptr);
        Lock lock(t->m_metadata->m_trackerLock);
        t->m_metadata->m_trackers.erase(t);
        delete t;
    }
}

ChainingMetadataProvider::ChainingMetadataProvider(const DOMElement* e)
    : ObservableMetadataProvider(e), m_firstMatch(true), m_trackerLock(Mutex::create()), m_tlsKey(ThreadKey::create(tracker_cleanup)),
        m_log(Category::getInstance(SAML_LOGCAT".Metadata.Chaining"))
{
    if (XMLString::equals(e ? e->getAttributeNS(nullptr, precedence) : nullptr, last))
        m_firstMatch = false;

    e = XMLHelper::getFirstChildElement(e, _MetadataProvider);
    while (e) {
        string t = XMLHelper::getAttrString(e, nullptr, _type);
        if (!t.empty()) {
            try {
                m_log.info("building MetadataProvider of type %s", t.c_str());
                auto_ptr<MetadataProvider> provider(SAMLConfig::getConfig().MetadataProviderManager.newPlugin(t.c_str(), e));
                ObservableMetadataProvider* obs = dynamic_cast<ObservableMetadataProvider*>(provider.get());
                if (obs)
                    obs->addObserver(this);
                m_providers.push_back(provider.get());
                provider.release();
            }
            catch (std::exception& ex) {
                m_log.error("error building MetadataProvider: %s", ex.what());
            }
        }
        e = XMLHelper::getNextSiblingElement(e, _MetadataProvider);
    }
}

ChainingMetadataProvider::~ChainingMetadataProvider()
{
    for_each(m_trackers.begin(), m_trackers.end(), xmltooling::cleanup<tracker_t>());
}

void ChainingMetadataProvider::init()
{
    for (ptr_vector<MetadataProvider>::iterator i = m_providers.begin(); i != m_providers.end(); ++i) {
        try {
            i->init();
        }
        catch (std::exception& ex) {
            m_log.crit("failure initializing MetadataProvider: %s", ex.what());
        }
    }

    // Set an initial cache tag for the state of the plugins.
    SAMLConfig::getConfig().generateRandomBytes(m_feedTag, 4);
    m_feedTag = SAMLArtifact::toHex(m_feedTag);
}

void ChainingMetadataProvider::outputStatus(ostream& os) const
{
    for_each(m_providers.begin(), m_providers.end(), boost::bind(&MetadataProvider::outputStatus, _1, boost::ref(os)));
}

Lockable* ChainingMetadataProvider::lock()
{
    return this;   // we're not lockable ourselves...
}

void ChainingMetadataProvider::unlock()
{
    // Check for locked providers and remove role mappings.
    void* ptr=m_tlsKey->getData();
    if (ptr) {
        tracker_t* t = reinterpret_cast<tracker_t*>(ptr);
        for_each(t->m_locked.begin(), t->m_locked.end(), mem_fun(&Lockable::unlock));
        t->m_locked.clear();
        t->m_objectMap.clear();
    }
}

const XMLObject* ChainingMetadataProvider::getMetadata() const
{
    throw MetadataException("getMetadata operation not implemented on this provider.");
}

const EntitiesDescriptor* ChainingMetadataProvider::getEntitiesDescriptor(const char* name, bool requireValidMetadata) const
{
    // Ensure we have a tracker to use.
    tracker_t* tracker = nullptr;
    void* ptr=m_tlsKey->getData();
    if (ptr) {
        tracker = reinterpret_cast<tracker_t*>(ptr);
    }
    else {
        tracker = new tracker_t(this);
        m_tlsKey->setData(tracker);
    }

    MetadataProvider* held = nullptr;
    const EntitiesDescriptor* ret = nullptr;
    const EntitiesDescriptor* cur = nullptr;
    for (ptr_vector<MetadataProvider>::iterator i = m_providers.begin(); i != m_providers.end(); ++i) {
        tracker->lock_if(&(*i));
        if (cur=i->getEntitiesDescriptor(name,requireValidMetadata)) {
            // Are we using a first match policy?
            if (m_firstMatch) {
                // Save locked provider.
                tracker->remember(&(*i));
                return cur;
            }

            // Using last match wins. Did we already have one?
            if (held) {
                m_log.warn("found duplicate EntitiesDescriptor (%s), using last matching copy", name);
                tracker->unlock_if(held);
            }

            // Save off the latest match.
            held = &(*i);
            ret = cur;
        }
        else {
            // No match, so just unlock this one and move on.
            tracker->unlock_if(&(*i));
        }
    }

    // Preserve any lock we're holding.
    if (held)
        tracker->remember(held);
    return ret;
}

pair<const EntityDescriptor*,const RoleDescriptor*> ChainingMetadataProvider::getEntityDescriptor(const Criteria& criteria) const
{
    // Ensure we have a tracker to use.
    tracker_t* tracker = nullptr;
    void* ptr=m_tlsKey->getData();
    if (ptr) {
        tracker = reinterpret_cast<tracker_t*>(ptr);
    }
    else {
        tracker = new tracker_t(this);
        m_tlsKey->setData(tracker);
    }

    // Do a search.
    MetadataProvider* held = nullptr;
    pair<const EntityDescriptor*,const RoleDescriptor*> ret = pair<const EntityDescriptor*,const RoleDescriptor*>(nullptr,nullptr);
    pair<const EntityDescriptor*,const RoleDescriptor*> cur = ret;
    for (ptr_vector<MetadataProvider>::iterator i = m_providers.begin(); i != m_providers.end(); ++i) {
        tracker->lock_if(&(*i));
        cur = i->getEntityDescriptor(criteria);
        if (cur.first) {
            if (criteria.role) {
                // We want a role also. Did we find one?
                if (cur.second) {
                    // Are we using a first match policy?
                    if (m_firstMatch) {
                        // We could have an entity-only match from earlier, so unlock it.
                        if (held)
                            tracker->unlock_if(held);
                        // Save locked provider and role mapping.
                        tracker->remember(&(*i), cur.first);
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
                        tracker->unlock_if(held);
                    }

                    // Save off the latest match.
                    held = &(*i);
                    ret = cur;
                }
                else {
                    // We didn't find the role, so we're going to keep looking,
                    // but save this one if we didn't have the role yet.
                    if (ret.second) {
                        // We already had a role, so let's stick with that.
                        tracker->unlock_if(&(*i));
                    }
                    else {
                        // This is at least as good, so toss anything we had and keep it.
                        if (held)
                            tracker->unlock_if(held);
                        held = &(*i);
                        ret = cur;
                    }
                }
            }
            else {
                // Are we using a first match policy?
                if (m_firstMatch) {
                    // I don't think this can happen, but who cares, check anyway.
                    if (held)
                        tracker->unlock_if(held);
                    
                    // Save locked provider.
                    tracker->remember(&(*i), cur.first);
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
                    tracker->unlock_if(held);
                }

                // Save off the latest match.
                held = &(*i);
                ret = cur;
            }
        }
        else {
            // No match, so just unlock this one and move on.
            tracker->unlock_if(&(*i));
        }
    }

    // Preserve any lock we're holding.
    if (held)
        tracker->remember(held, ret.first);
    return ret;
}

const Credential* ChainingMetadataProvider::resolve(const CredentialCriteria* criteria) const
{
    void* ptr=m_tlsKey->getData();
    if (!ptr)
        throw MetadataException("No locked MetadataProvider, where did the role object come from?");
    tracker_t* tracker=reinterpret_cast<tracker_t*>(ptr);

    const MetadataCredentialCriteria* mcc = dynamic_cast<const MetadataCredentialCriteria*>(criteria);
    if (!mcc)
        throw MetadataException("Cannot resolve credentials without a MetadataCredentialCriteria object.");
    const MetadataProvider* m = tracker->getProvider(mcc->getRole());
    if (!m)
        throw MetadataException("No record of corresponding MetadataProvider, where did the role object come from?");
    return m->resolve(mcc);
}

vector<const Credential*>::size_type ChainingMetadataProvider::resolve(
    vector<const Credential*>& results, const CredentialCriteria* criteria
    ) const
{
    void* ptr=m_tlsKey->getData();
    if (!ptr)
        throw MetadataException("No locked MetadataProvider, where did the role object come from?");
    tracker_t* tracker=reinterpret_cast<tracker_t*>(ptr);

    const MetadataCredentialCriteria* mcc = dynamic_cast<const MetadataCredentialCriteria*>(criteria);
    if (!mcc)
        throw MetadataException("Cannot resolve credentials without a MetadataCredentialCriteria object.");
    const MetadataProvider* m = tracker->getProvider(mcc->getRole());
    if (!m)
        throw MetadataException("No record of corresponding MetadataProvider, where did the role object come from?");
    return m->resolve(results, mcc);
}
