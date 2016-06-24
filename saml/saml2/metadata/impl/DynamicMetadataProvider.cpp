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
 * DynamicMetadataProvider.cpp
 *
 * Simple implementation of a dynamic caching MetadataProvider.
 */

#include "internal.h"
#include "binding/SAMLArtifact.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/DynamicMetadataProvider.h"

#include <xercesc/framework/Wrapper4InputSource.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ParserPool.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLHelper.h>
#include <xmltooling/validation/ValidatorSuite.h>

#if defined(XMLTOOLING_LOG4SHIB)
# include <log4shib/NDC.hh>
#elif defined(XMLTOOLING_LOG4CPP)
# include <log4cpp/NDC.hh>
#endif

using namespace opensaml::saml2md;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

# ifndef min
#  define min(a,b)            (((a) < (b)) ? (a) : (b))
# endif

static const XMLCh id[] =                   UNICODE_LITERAL_2(i,d);
static const XMLCh cleanupInterval[] =      UNICODE_LITERAL_15(c,l,e,a,n,u,p,I,n,t,e,r,v,a,l);
static const XMLCh cleanupTimeout[] =       UNICODE_LITERAL_14(c,l,e,a,n,u,p,T,i,m,e,o,u,t);
static const XMLCh maxCacheDuration[] =     UNICODE_LITERAL_16(m,a,x,C,a,c,h,e,D,u,r,a,t,i,o,n);
static const XMLCh minCacheDuration[] =     UNICODE_LITERAL_16(m,i,n,C,a,c,h,e,D,u,r,a,t,i,o,n);
static const XMLCh refreshDelayFactor[] =   UNICODE_LITERAL_18(r,e,f,r,e,s,h,D,e,l,a,y,F,a,c,t,o,r);
static const XMLCh validate[] =             UNICODE_LITERAL_8(v,a,l,i,d,a,t,e);

namespace opensaml {
    namespace saml2md {
        MetadataProvider* SAML_DLLLOCAL DynamicMetadataProviderFactory(const DOMElement* const & e)
        {
            return new DynamicMetadataProvider(e);
        }
    };
};

DynamicMetadataProvider::DynamicMetadataProvider(const DOMElement* e)
    : AbstractMetadataProvider(e),
      m_validate(XMLHelper::getAttrBool(e, false, validate)),
        m_id(XMLHelper::getAttrString(e, "Dynamic", id)),
        m_lock(RWLock::create()),
        m_refreshDelayFactor(0.75),
        m_minCacheDuration(XMLHelper::getAttrInt(e, 600, minCacheDuration)),
        m_maxCacheDuration(XMLHelper::getAttrInt(e, 28800, maxCacheDuration)),
        m_shutdown(false),
        m_cleanupInterval(XMLHelper::getAttrInt(e, 1800, cleanupInterval)),
        m_cleanupTimeout(XMLHelper::getAttrInt(e, 1800, cleanupTimeout)),
        m_cleanup_wait(nullptr), m_cleanup_thread(nullptr)
{
    if (m_minCacheDuration > m_maxCacheDuration) {
        Category::getInstance(SAML_LOGCAT ".MetadataProvider.Dynamic").error(
            "minCacheDuration setting exceeds maxCacheDuration setting, lowering to match it"
            );
        m_minCacheDuration = m_maxCacheDuration;
    }

    const XMLCh* delay = e ? e->getAttributeNS(nullptr, refreshDelayFactor) : nullptr;
    if (delay && *delay) {
        auto_ptr_char temp(delay);
        m_refreshDelayFactor = atof(temp.get());
        if (m_refreshDelayFactor <= 0.0 || m_refreshDelayFactor >= 1.0) {
            Category::getInstance(SAML_LOGCAT ".MetadataProvider.Dynamic").error(
                "invalid refreshDelayFactor setting, using default"
                );
            m_refreshDelayFactor = 0.75;
        }
    }

    if (m_cleanupInterval > 0) {
        if (m_cleanupTimeout < 0)
            m_cleanupTimeout = 0;
        m_cleanup_wait = CondWait::create();
        m_cleanup_thread = Thread::create(&cleanup_fn, this);
    }
}

DynamicMetadataProvider::~DynamicMetadataProvider()
{
    // Each entity in the map is unique (no multimap semantics), so this is safe.
    clearDescriptorIndex(true);

    if (m_cleanup_thread) {
        // Shut down the cleanup thread and let it know.
        m_shutdown = true;
        m_cleanup_wait->signal();
        m_cleanup_thread->join(nullptr);
        delete m_cleanup_thread;
        delete m_cleanup_wait;
        m_cleanup_thread = nullptr;
        m_cleanup_wait = nullptr;
    }
}

void* DynamicMetadataProvider::cleanup_fn(void* pv)
{
    DynamicMetadataProvider* provider = reinterpret_cast<DynamicMetadataProvider*>(pv);

#ifndef WIN32
    // First, let's block all signals
    Thread::mask_all_signals();
#endif

    if (!provider->m_id.empty()) {
        string threadid("[");
        threadid += provider->m_id + ']';
        logging::NDC::push(threadid);
    }

#ifdef _DEBUG
    xmltooling::NDC ndc("cleanup");
#endif

    auto_ptr<Mutex> mutex(Mutex::create());
    mutex->lock();

    Category& log = Category::getInstance(SAML_LOGCAT ".MetadataProvider.Dynamic");

    log.info("cleanup thread started...running every %d seconds", provider->m_cleanupInterval);

    while (!provider->m_shutdown) {
        provider->m_cleanup_wait->timedwait(mutex.get(), provider->m_cleanupInterval);
        if (provider->m_shutdown)
            break;

        log.info("cleaning dynamic metadata cache...");

        // Get a write lock.
        provider->m_lock->wrlock();
        SharedLock locker(provider->m_lock, false);

        time_t now = time(nullptr);
        // Dual iterator loop so we can remove entries while walking the map.
        for (map<xstring, time_t>::iterator i = provider->m_cacheMap.begin(), i2 = i; i != provider->m_cacheMap.end(); i = i2) {
            ++i2;
            if (now > i->second + provider->m_cleanupTimeout) {
                if (log.isDebugEnabled()) {
                    auto_ptr_char id(i->first.c_str());
                    log.debug("removing cache entry for (%s)", id.get());
                }
                provider->unindex(i->first.c_str(), true);
                provider->m_cacheMap.erase(i);
            }
        }
    }

    log.info("cleanup thread finished");

    mutex->unlock();

    if (!provider->m_id.empty()) {
        logging::NDC::pop();
    }

    return nullptr;
}

const XMLObject* DynamicMetadataProvider::getMetadata() const
{
    throw MetadataException("getMetadata operation not implemented on this provider.");
}

Lockable* DynamicMetadataProvider::lock()
{
    m_lock->rdlock();
    return this;
}

void DynamicMetadataProvider::unlock()
{
    m_lock->unlock();
}

void DynamicMetadataProvider::init()
{
}

const char* DynamicMetadataProvider::getId() const
{
    return m_id.c_str();
}

pair<const EntityDescriptor*,const RoleDescriptor*> DynamicMetadataProvider::getEntityDescriptor(const Criteria& criteria) const
{
    Category& log = Category::getInstance(SAML_LOGCAT ".MetadataProvider.Dynamic");

    bool writeLocked = false;

    // First we check the underlying cache.
    pair<const EntityDescriptor*,const RoleDescriptor*> entity = AbstractMetadataProvider::getEntityDescriptor(criteria);

    // Check to see if we're within the caching interval for a lookup of this entity.
    // This applies *even if we didn't get a hit* because the cache map tracks failed
    // lookups also, to prevent constant reload attempts.
    cachemap_t::iterator cit;
    if (entity.first) {
        cit = m_cacheMap.find(entity.first->getEntityID());
    }
    else if (criteria.entityID_ascii) {
        auto_ptr_XMLCh widetemp(criteria.entityID_ascii);
        cit = m_cacheMap.find(widetemp.get());
    }
    else if (criteria.entityID_unicode) {
        cit = m_cacheMap.find(criteria.entityID_unicode);
    }
    else if (criteria.artifact) {
        auto_ptr_XMLCh widetemp(criteria.artifact->getSource().c_str());
        cit = m_cacheMap.find(widetemp.get());
    }
    else {
        cit = m_cacheMap.end();
    }
    if (cit != m_cacheMap.end()) {
        if (time(nullptr) <= cit->second)
            return entity;
    }

    string name;
    if (criteria.entityID_ascii) {
        name = criteria.entityID_ascii;
    }
    else if (criteria.entityID_unicode) {
        auto_ptr_char temp(criteria.entityID_unicode);
        name = temp.get();
    }
    else if (criteria.artifact) {
        name = criteria.artifact->getSource();
    }
    else {
        return entity;
    }

    if (entity.first)
        log.info("metadata for (%s) is beyond caching interval, attempting to refresh", name.c_str());
    else
        log.info("resolving metadata for (%s)", name.c_str());

    try {
        // Try resolving it.
        auto_ptr<EntityDescriptor> entity2(resolve(criteria));

        // Verify the entityID.
        if (criteria.entityID_unicode && !XMLString::equals(criteria.entityID_unicode, entity2->getEntityID())) {
            log.error("metadata instance did not match expected entityID");
            return entity;
        }
        else {
            auto_ptr_XMLCh temp2(name.c_str());
            if (!XMLString::equals(temp2.get(), entity2->getEntityID())) {
                log.error("metadata instance did not match expected entityID");
                return entity;
            }
        }

        // Preprocess the metadata (even if we schema-validated).
        try {
            SchemaValidators.validate(entity2.get());
        }
        catch (exception& ex) {
            log.error("metadata instance failed manual validation checking: %s", ex.what());
            throw MetadataException("Metadata instance failed manual validation checking.");
        }

        // Filter it, which may throw.
        doFilters(*entity2);

        time_t now = time(nullptr);
        if (entity2->getValidUntil() && entity2->getValidUntilEpoch() < now + 60)
            throw MetadataException("Metadata was already invalid at the time of retrieval.");

        log.info("caching resolved metadata for (%s)", name.c_str());

        // Compute the smaller of the validUntil / cacheDuration constraints.
        time_t cacheExp = (entity2->getValidUntil() ? entity2->getValidUntilEpoch() : SAMLTIME_MAX) - now;
        if (entity2->getCacheDuration())
            cacheExp = min(cacheExp, entity2->getCacheDurationEpoch());
            
        // Adjust for the delay factor.
        cacheExp *= m_refreshDelayFactor;

        // Bound by max and min.
        if (cacheExp > m_maxCacheDuration)
            cacheExp = m_maxCacheDuration;
        else if (cacheExp < m_minCacheDuration)
            cacheExp = m_minCacheDuration;

        log.info("next refresh of metadata for (%s) no sooner than %u seconds", name.c_str(), cacheExp);

        // Upgrade our lock so we can cache the new metadata.
        m_lock->unlock();
        m_lock->wrlock();
        writeLocked = true;

        // Notify observers.
        emitChangeEvent(*entity2);

        // Record the proper refresh time.
        m_cacheMap[entity2->getEntityID()] = now + cacheExp;

        // Make sure we clear out any existing copies, including stale metadata or if somebody snuck in.
        cacheExp = SAMLTIME_MAX;
        unindex(entity2->getEntityID(), true);  // actually frees the old instance with this ID
        indexEntity(entity2.get(), cacheExp);
        entity2.release();

        m_lastUpdate = now;
    }
    catch (exception& e) {
        log.error("error while resolving entityID (%s): %s", name.c_str(), e.what());
        // This will return entries that are beyond their cache period,
        // but not beyond their validity unless that criteria option was set.
        // Bump the cache period to prevent retries, making sure we have a write lock
        if (!writeLocked) {
            m_lock->unlock();
            m_lock->wrlock();
            writeLocked = true;
        }
        if (entity.first)
            m_cacheMap[entity.first->getEntityID()] = time(nullptr) + m_minCacheDuration;
        else if (criteria.entityID_unicode)
            m_cacheMap[criteria.entityID_unicode] = time(nullptr) + m_minCacheDuration;
        else {
            auto_ptr_XMLCh widetemp(name.c_str());
            m_cacheMap[widetemp.get()] = time(nullptr) + m_minCacheDuration;
        }
        log.warn("next refresh of metadata for (%s) no sooner than %u seconds", name.c_str(), m_minCacheDuration);
        return entity;
    }

    // Downgrade back to a read lock.
    if (writeLocked) {
        m_lock->unlock();
        m_lock->rdlock();
    }

    // Rinse and repeat.
    return getEntityDescriptor(criteria);
}

EntityDescriptor* DynamicMetadataProvider::resolve(const Criteria& criteria) const
{
    string name;
    if (criteria.entityID_ascii) {
        name = criteria.entityID_ascii;
    }
    else if (criteria.entityID_unicode) {
        auto_ptr_char temp(criteria.entityID_unicode);
        name = temp.get();
    }
    else if (criteria.artifact) {
        throw MetadataException("Unable to resolve metadata dynamically from an artifact.");
    }

    try {
        DOMDocument* doc=nullptr;
        auto_ptr_XMLCh widenit(name.c_str());
        URLInputSource src(widenit.get());
        Wrapper4InputSource dsrc(&src,false);
        if (m_validate)
            doc=XMLToolingConfig::getConfig().getValidatingParser().parse(dsrc);
        else
            doc=XMLToolingConfig::getConfig().getParser().parse(dsrc);

        // Wrap the document for now.
        XercesJanitor<DOMDocument> docjanitor(doc);

        // Unmarshall objects, binding the document.
        auto_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
        docjanitor.release();

        // Make sure it's metadata.
        EntityDescriptor* entity = dynamic_cast<EntityDescriptor*>(xmlObject.get());
        if (!entity) {
            throw MetadataException(
                "Root of metadata instance not recognized: $1", params(1,xmlObject->getElementQName().toString().c_str())
                );
        }
        xmlObject.release();
        return entity;
    }
    catch (XMLException& e) {
        auto_ptr_char msg(e.getMessage());
        Category::getInstance(SAML_LOGCAT ".MetadataProvider.Dynamic").error(
            "Xerces error while resolving entityID (%s): %s", name.c_str(), msg.get()
            );
        throw MetadataException(msg.get());
    }
}
