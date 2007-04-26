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
 * @file saml/saml1/binding/SAMLArtifactType0001.h
 * 
 * Type 0x0001 SAML 1.x artifact class
 */

#ifndef __saml_artifacttype0001_h__
#define __saml_artifacttype0001_h__

#include <saml/binding/SAMLArtifact.h>

namespace opensaml {
    namespace saml1p {
        
        /**
         * Type 0x0001 SAML 1.x artifact class
         */
        class SAML_API SAMLArtifactType0001 : public SAMLArtifact
        {
            SAMLArtifactType0001& operator=(const SAMLArtifactType0001& src);
        public:
            /**
             * Decodes a base64-encoded type 0x0001 artifact
             * 
             * @param s NULL-terminated base64-encoded string 
             */        
            SAMLArtifactType0001(const char* s);

            /**
             * Constructs an artifact with the specified source ID, but a random assertion handle.
             * 
             * @param sourceid SOURCEID_LENGTH bytes of binary data 
             */        
            SAMLArtifactType0001(const std::string& sourceid);

            /**
             * Constructs an artifact with the specified source ID and assertion handle.
             * 
             * @param sourceid  SOURCEID_LENGTH bytes of binary data
             * @param handle    HANDLE_LENGTH bytes of binary data 
             */        
            SAMLArtifactType0001(const std::string& sourceid, const std::string& handle);
    
            virtual ~SAMLArtifactType0001() {}
            
            virtual SAMLArtifactType0001* clone() const {
                return new SAMLArtifactType0001(*this);
            }
            
            virtual std::string getSource() const {
                return toHex(getSourceID());
            }

            /**
             * Returns the binary data that identifies the source.
             * The result MAY contain embedded null characters.
             * 
             * @return the binary source ID
             */
            virtual std::string getSourceID() const {
                return m_raw.substr(TYPECODE_LENGTH,SOURCEID_LENGTH);                   // bytes 3-22
            }
            
            virtual std::string getMessageHandle() const {
                return m_raw.substr(TYPECODE_LENGTH+SOURCEID_LENGTH, HANDLE_LENGTH);    // bytes 23-42
            }

            /** Length of source ID */            
            static const unsigned int SOURCEID_LENGTH;

            /** Length of assertion handle */            
            static const unsigned int HANDLE_LENGTH;
    
        protected:
            /**
             * Copy constructor.
             * 
             * @param src   object to copy
             */
            SAMLArtifactType0001(const SAMLArtifactType0001& src) : SAMLArtifact(src) {}
        };
        
    };
};

#endif /* __saml_artifacttype0001_h__ */
