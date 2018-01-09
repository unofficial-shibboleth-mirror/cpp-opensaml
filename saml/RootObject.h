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
 * @file saml/RootObject.h
 * 
 * Base class for SAML objects at the root of core schemas.
 */

#ifndef __saml_root_h__
#define __saml_root_h__

#include <saml/signature/SignableObject.h>

#include <xercesc/util/XMLDateTime.hpp>

namespace opensaml {

    /**
     * Base class for SAML objects at the root of core schemas.
     * Root objects are signable, and have message identifiers and timestamps.
     */
    class SAML_API RootObject : public SignableObject
    {
    public:
        virtual ~RootObject();

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
        virtual const xercesc::XMLDateTime* getIssueInstant() const=0;

        /**
         * Returns the timestamp of the object as an epoch
         *
         * @return the timestamp
         */
        virtual time_t getIssueInstantEpoch() const=0;

    protected:
        RootObject();
    };

    /**
     * Base class for SAML assertions.
     * Currently just a marker interface.
     */
    class SAML_API Assertion : public virtual RootObject
    {
    public:
        virtual ~Assertion();
    protected:
        Assertion();
    };

    /**
     * Base class for SAML status codes.
     */
    class SAML_API Status : public virtual xmltooling::XMLObject
    {
    public:
        virtual ~Status();

        /**
         * Returns a string representation of the top-level status code.
         *
         * @return string representation of top-level status code
         */
        virtual const XMLCh* getTopStatus() const=0;

        /**
         * Returns a string representation of the second-level status code, if any.
         *
         * @return string representation of second-level status code, or nullptr
         */
        virtual const XMLCh* getSubStatus() const=0;

        /**
         * Returns true iff status information beyond the second level exists.
         *
         * @return indicator of three or more status codes
         */
        virtual bool hasAdditionalStatus() const=0;

        /**
         * Returns the message contained in the status, if any.
         *
         * @return status message, or nullptr
         */
        virtual const XMLCh* getMessage() const=0;

    protected:
        Status();
    };

};

#endif /* __saml_root_h__ */
