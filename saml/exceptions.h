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
 * @file saml/exceptions.h
 * 
 * Exception classes
 */
 
#ifndef __saml_exceptions_h__
#define __saml_exceptions_h__

#include <saml/base.h>
#include <xmltooling/exceptions.h>

namespace opensaml {
    
    namespace saml2p {
        class SAML_API Status;
    };
    namespace saml2md {
        class SAML_API EntityDescriptor;
        class SAML_API RoleDescriptor;
    };
    
    DECL_XMLTOOLING_EXCEPTION(SecurityPolicyException,SAML_EXCEPTIONAPI(SAML_API),opensaml,xmltooling::XMLToolingException,Exceptions in security policy processing);
    DECL_XMLTOOLING_EXCEPTION(BindingException,SAML_EXCEPTIONAPI(SAML_API),opensaml,xmltooling::XMLToolingException,Exceptions in SAML binding processing);
    DECL_XMLTOOLING_EXCEPTION(ProfileException,SAML_EXCEPTIONAPI(SAML_API),opensaml,xmltooling::ValidationException,Exceptions in SAML profile processing);
    DECL_XMLTOOLING_EXCEPTION(FatalProfileException,SAML_EXCEPTIONAPI(SAML_API),opensaml,ProfileException,Fatal exceptions in SAML profile processing);
    DECL_XMLTOOLING_EXCEPTION(RetryableProfileException,SAML_EXCEPTIONAPI(SAML_API),opensaml,ProfileException,Non-fatal exceptions in SAML profile processing);

    /**
     * Attaches metadata-derived information as exception properties and optionally
     * rethrows the object. The following named properties are attached, when possible:
     * 
     *  <dl>
     *  <dt>entityID</dt>       <dd>The unique ID of the entity</dd>
     *  <dt>errorURL</dt>       <dd>The error support URL of a random role</dd>
     *  <dt>contactName</dt>    <dd>A formatted support or technical contact name</dd>
     *  <dt>contactEmail</dt>   <dd>A contact email address</dd>
     *  <dt>statusCode</dt>     <dd>Top-level status code from Status object</dd>
     *  <dt>statusCode2</dt>    <dd>Second-level status code from Status object</dd>
     *  <dt>statusMessage</dt>  <dd>StatusMessage from Status object</dd>
     *  </dl>
     * 
     * @param e         pointer to exception object
     * @param entity    pointer to entity
     * @param status    pointer to Status from message 
     * @param rethrow   true iff the exception should be rethrown
     */
    void SAML_API annotateException(
        xmltooling::XMLToolingException* e,
        const saml2md::EntityDescriptor* entity,
        const saml2p::Status* status=NULL,
        bool rethrow=true
        );
    
    /**
     * Attaches metadata-derived information as exception properties and optionally
     * rethrows the object. The following named properties are attached, when possible:
     * 
     *  <dl>
     *  <dt>entityID</dt>       <dd>The unique ID of the entity</dd>
     *  <dt>errorURL</dt>       <dd>The error support URL of the role</dd>
     *  <dt>contactName</dt>    <dd>A formatted support or technical contact name</dd>
     *  <dt>contactEmail</dt>   <dd>A contact email address</dd>
     *  <dt>statusCode</dt>     <dd>Top-level status code from Status object</dd>
     *  <dt>statusCode2</dt>    <dd>Second-level status code from Status object</dd>
     *  </dl>
     * 
     * @param e         pointer to exception object
     * @param entity    pointer to role
     * @param status    pointer to Status from message 
     * @param rethrow   true iff the exception should be rethrown
     */
    void SAML_API annotateException(
        xmltooling::XMLToolingException* e,
        const saml2md::RoleDescriptor* role,
        const saml2p::Status* status=NULL,
        bool rethrow=true
        );
};

#endif /* __saml_exceptions_h__ */
