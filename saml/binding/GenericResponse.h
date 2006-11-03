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
 * @file saml/binding/GenericResponse.h
 * 
 * Interface to generic protocol responses that transport SAML messages. 
 */

#ifndef __saml_genres_h__
#define __saml_genres_h__

#include <saml/base.h>
#include <iostream>

namespace opensaml {
    
    /**
     * Interface to caller-supplied shim for accessing generic transport
     * request context.
     * 
     * <p>This interface need not be threadsafe.
     */
    class SAML_API GenericResponse {
        MAKE_NONCOPYABLE(GenericResponse);
    protected:
        GenericResponse() {}
    public:
        virtual ~GenericResponse() {}        

        /**
         * Sets or clears the MIME type of the response.
         * 
         * @param type the MIME type, or NULL to clear
         */
        virtual void setContentType(const char* type=NULL)=0;

        /**
         * Sends a completed response to the client.
         * 
         * @param inputStream   reference to source of response data
         * @param status        transport-specific status to return
         * @return a result code to return from the calling MessageEncoder
         */
        virtual long sendResponse(std::istream& inputStream, long status)=0;
    };
};

#endif /* __saml_genres_h__ */
