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
 * @file saml/RootObject.h
 * 
 * Base class for SAML objects at the root of core schemas 
 */

#ifndef __saml_root_h__
#define __saml_root_h__

#include <saml/signature/SignableObject.h>
#include <xmltooling/util/DateTime.h>

namespace opensaml {

    /**
     * Base class for SAML objects at the root of core schemas.
     * Root objects are signable, and have message identifiers and timestamps.
     */
    class SAML_API RootObject : public virtual SignableObject
    {
    public:
        virtual ~RootObject() {}

        /**
         * Returns the unique SAML ID of the object.
         *
         * @return the unique SAML ID
         */
        virtual const XMLCh* getID() const=0;

        /**
         * Returns the timestamp of the object
         *
         * @return the timestamp
         */
        virtual const xmltooling::DateTime* getIssueInstant() const=0;

        /**
         * Returns the timestamp of the object as an epoch
         *
         * @return the timestamp
         */
        virtual time_t getIssueInstantEpoch() const=0;

    protected:
        RootObject() {}
    };

};

#endif /* __saml_root_h__ */
