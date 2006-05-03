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
 * @file SAMLConfig.h
 * 
 * Library configuration 
 */

#ifndef __saml_config_h__
#define __saml_config_h__

#include <saml/base.h>

namespace opensaml {

    /**
     * Singleton object that manages library startup/shutdown.configuration.
     */
    class SAML_API SAMLConfig
    {
    MAKE_NONCOPYABLE(SAMLConfig);
    public:
        virtual ~SAMLConfig() {}

        /**
         * Returns the global configuration object for the library.
         * 
         * @return reference to the global library configuration object
         */
        static SAMLConfig& getConfig();
        
        /**
         * Initializes library
         * 
         * Each process using the library MUST call this function exactly once
         * before using any library classes.
         * 
         * @return true iff initialization was successful 
         */
        virtual bool init()=0;
        
        /**
         * Shuts down library
         * 
         * Each process using the library SHOULD call this function exactly once
         * before terminating itself
         */
        virtual void term()=0;

    protected:
        SAMLConfig() {}
    };

};

#endif /* __saml_config_h__ */
