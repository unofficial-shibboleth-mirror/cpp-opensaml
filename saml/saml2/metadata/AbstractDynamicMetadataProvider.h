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
 * @file saml/saml2/metadata/AbstractDynamicMetadataProvider.h
 *
 * Simple base implementation of a dynamic caching MetadataProvider.
 */

#ifndef __saml2_absdynmetadataprov_h__
#define __saml2_absdynmetadataprov_h__

#include <saml/saml2/metadata/AbstractMetadataProvider.h>
#include <xmltooling/Lockable.h>

namespace xmltooling {
    class XMLTOOL_API CondWait;
    class XMLTOOL_API RWLock;
    class XMLTOOL_API Thread;
};

namespace opensaml {
    namespace saml2md {

        /**
         * Simple implementation of a dynamic, caching MetadataProvider.
         */
        class SAML_API AbstractDynamicMetadataProvider : public AbstractMetadataProvider
        {
        public:
            /**
             * Constructor.
             *
             * @param defaultNegativeCache - if not specified in the element, do we cache lookup failures?
             * @param e DOM to supply configuration for provider
             */
            AbstractDynamicMetadataProvider(bool defaultNegativeCache, const xercesc::DOMElement* e=nullptr);

            virtual ~AbstractDynamicMetadataProvider();

            xmltooling::Lockable* lock();
            void unlock();
            const char* getId() const;
            const xmltooling::XMLObject* getMetadata() const;
            std::pair<const EntityDescriptor*,const RoleDescriptor*> getEntityDescriptor(const Criteria& criteria) const;

        protected:
            /** Controls XML schema validation. */
            bool m_validate;

            /**
             * Resolves a metadata instance using the supplied criteria.
             *
             * <p>A null return value indicates the instance hasn't changed since the prevous request
             * for the same instance.</p>
             *
             * <p>The cache tag may be modified on output to update it for future calls.</p>
             *
             * @param criteria  lookup criteria
             * @param cacheTag implementation specific cache tag
             *
             * @return  a valid metadata instance or null
             * @throws an exception if resolution failed
             */
            virtual EntityDescriptor* resolve(const Criteria& criteria, std::string& cacheTag) const=0;

            /**
             * Index an entity and cache the fact of it being indexed.
             *
             * @param entity what to cache
             * @param cacheTag cache tag
             * @param locked have we locked ourselves exclusively first?
             *
             * @return the cache ttl (for logging purposes)
             */
            virtual time_t cacheEntity(EntityDescriptor* entity, const std::string& cacheTag, bool locked=false) const;

            /**
             * Compute the number of seconds until the next refresh attempt.
             *
             * @param entity entity to evaluate
             * @param currentTime baseline for calculation
             *
             * @return the cache ttl
             */
            time_t computeNextRefresh(const EntityDescriptor& entity, time_t currentTime) const;

            /**
             * Parse and unmarshal the provided stream, returning the EntityDescriptor if there is one.
             *
             * @param stream the stream to parse
             *
             * @return the entity, or nullptr if there isn't one
             */
            EntityDescriptor* entityFromStream(std::istream& stream) const;


        private:
            std::string m_id;
            boost::scoped_ptr<xmltooling::RWLock> m_lock;
            double m_refreshDelayFactor;
            time_t m_minCacheDuration, m_maxCacheDuration;
            typedef std::map< xmltooling::xstring, std::pair<time_t,std::string> > cachemap_t;
            mutable cachemap_t m_cacheMap;
            bool m_negativeCache;

            // Used to manage background maintenance of cache.
            bool m_shutdown;
            long m_cleanupInterval;
            long m_cleanupTimeout;
            boost::scoped_ptr<xmltooling::CondWait> m_cleanup_wait;
            boost::scoped_ptr<xmltooling::Thread> m_cleanup_thread;
            static void* cleanup_fn(void*);
        };

    };
};

#endif /* __saml2_dynmetadataprov_h__ */
