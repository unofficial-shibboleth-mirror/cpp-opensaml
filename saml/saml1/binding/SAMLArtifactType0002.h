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
 * @file saml/saml1/binding/SAMLArtifactType0002.h
 * 
 * Type 0x0002 SAML 1.x artifact class
 */

#ifndef __saml_artifacttype0002_h__
#define __saml_artifacttype0002_h__

#include <saml/binding/SAMLArtifact.h>

namespace opensaml {
    namespace saml1p {
        
        /**
         * Type 0x0002 SAML 1.x artifact class
         */
        class SAML_API SAMLArtifactType0002 : public SAMLArtifact
        {
            SAMLArtifactType0002& operator=(const SAMLArtifactType0002& src);
        public:
            /**
             * Decodes a base64-encoded type 0x0002 artifact
             * 
             * @param s NULL-terminated base64-encoded string 
             */        
            SAMLArtifactType0002(const char* s);

            /**
             * Constructs an artifact with the specified source URL, but a random assertion handle.
             * 
             * @param sourceLocation source URL
             */        
            SAMLArtifactType0002(const std::string& sourceLocation);

            /**
             * Constructs an artifact with the specified source URL and assertion handle.
             * 
             * @param sourceLocation    source URL
             * @param handle            HANDLE_LENGTH bytes of binary data 
             */        
            SAMLArtifactType0002(const std::string& sourceLocation, const std::string& handle);
    
            virtual ~SAMLArtifactType0002() {}
            
            virtual SAMLArtifactType0002* clone() const {
                return new SAMLArtifactType0002(*this);
            }
            
            virtual std::string getMessageHandle() const {
                return m_raw.substr(TYPECODE_LENGTH, HANDLE_LENGTH);    // bytes 3-22
            }

            virtual std::string getSource() const {
                return m_raw.c_str() + TYPECODE_LENGTH + HANDLE_LENGTH; // bytes 23-terminating null
            }
            
            /** Length of assertion handle */
            static const unsigned int HANDLE_LENGTH;
    
        protected:
            SAMLArtifactType0002(const SAMLArtifactType0002& src) : SAMLArtifact(src) {}
        };
        
    };
};

#endif /* __saml_artifacttype0002_h__ */
