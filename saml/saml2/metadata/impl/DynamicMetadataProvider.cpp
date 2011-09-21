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
#include <xmltooling/util/ParserPool.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLHelper.h>
#include <xmltooling/validation/ValidatorSuite.h>

using namespace opensaml::saml2md;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

# ifndef min
#  define min(a,b)            (((a) < (b)) ? (a) : (b))
# endif

static const XMLCh id[] =                   UNICODE_LITERAL_2(i,d);
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
        m_maxCacheDuration(XMLHelper::getAttrInt(e, 28800, maxCacheDuration))
{
    if (m_minCacheDuration > m_maxCacheDuration) {
        Category::getInstance(SAML_LOGCAT".MetadataProvider.Dynamic").error(
            "minCacheDuration setting exceeds maxCacheDuration setting, lowering to match it"
            );
        m_minCacheDuration = m_maxCacheDuration;
    }

    const XMLCh* delay = e ? e->getAttributeNS(nullptr, refreshDelayFactor) : nullptr;
    if (delay && *delay) {
        auto_ptr_char temp(delay);
        m_refreshDelayFactor = atof(temp.get());
        if (m_refreshDelayFactor <= 0.0 || m_refreshDelayFactor >= 1.0) {
            Category::getInstance(SAML_LOGCAT".MetadataProvider.Dynamic").error(
                "invalid refreshDelayFactor setting, using default"
                );
            m_refreshDelayFactor = 0.75;
        }
    }
}

DynamicMetadataProvider::~DynamicMetadataProvider()
{
    // Each entity in the map is unique (no multimap semantics), so this is safe.
    clearDescriptorIndex(true);
    delete m_lock;
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
    Category& log = Category::getInstance(SAML_LOGCAT".MetadataProvider.Dynamic");

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
        m_cacheMap.erase(cit);
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
            log.error("metadata intance failed manual validation checking: %s", ex.what());
            throw MetadataException("Metadata instance failed manual validation checking.");
        }

        // Filter it, which may throw.
        doFilters(*entity2.get());

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

        // Notify observers.
        emitChangeEvent();

        // Record the proper refresh time.
        m_cacheMap[entity2->getEntityID()] = now + cacheExp;

        // Make sure we clear out any existing copies, including stale metadata or if somebody snuck in.
        cacheExp = SAMLTIME_MAX;
        indexEntity(entity2.release(), cacheExp, true);

        m_lastUpdate = now;

        // Downgrade back to a read lock.
        m_lock->unlock();
        m_lock->rdlock();
    }
    catch (exception& e) {
        log.error("error while resolving entityID (%s): %s", name.c_str(), e.what());
        // This will return entries that are beyond their cache period,
        // but not beyond their validity unless that criteria option was set.
        // If it is a cache-expired entry, bump the cache period to prevent retries.
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
        Category::getInstance(SAML_LOGCAT".MetadataProvider.Dynamic").error(
            "Xerces error while resolving entityID (%s): %s", name.c_str(), msg.get()
            );
        throw MetadataException(msg.get());
    }
}
