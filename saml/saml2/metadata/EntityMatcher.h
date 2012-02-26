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
 * @file saml/saml2/metadata/EntityMatcher.h
 *
 * Applies a set of matching rules to an entity.
 */

#include <saml/base.h>

#ifndef __saml2_entitymatcher_h__
#define __saml2_entitymatcher_h__

namespace opensaml {
    namespace saml2md {

        class SAML_API EntityDescriptor;

        /**
         * An entity matcher is a predicate that evaluates an entity against a set of matching rules.
         */
        class SAML_API EntityMatcher
        {
            MAKE_NONCOPYABLE(EntityMatcher);
        protected:
            EntityMatcher();
        public:
            virtual ~EntityMatcher();

            /**
             * Applies the instance's matching rule(s) against an entity.
             *
             * @param entity the entity to evaluate
             * @return  true iff the entity is matched
             */
            virtual bool matches(const EntityDescriptor& entity) const=0;
        };

        /**
         * Registers EntityMatcher classes into the runtime.
         */
        void SAML_API registerEntityMatchers();

        /** EntityMatcher that matches based on name. */
        #define NAME_ENTITY_MATCHER "Name"

        /** EntityMatcher that applies a set of input attributes. */
        #define ENTITYATTR_ENTITY_MATCHER "EntityAttributes"
    };
};

#endif /* __saml2_entitymatcher_h__ */
