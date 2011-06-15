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
 * @file saml/saml2/binding/SAML2Redirect.h
 * 
 * SAML 2.0 HTTP Redirect compression functionality
 */

#include <saml/base.h>
#include <iostream>

namespace opensaml {
    namespace saml2p {
        /**
         * Deflates data in accordance with RFC1951. The caller must free the
         * resulting buffer using delete[]
         * 
         * @param in        the data to compress
         * @param in_len    length of input data
         * @param out_len   will contain the length of the resulting data
         * @return  allocated buffer of out_len bytes containing deflated data
         */
        SAML_EXPORT char* deflate(char* in, unsigned int in_len, unsigned int* out_len);
        
        /**
         * Inflates data compressed in accordance with RFC1951 and sends the
         * results to an output stream.
         * 
         * @param in        the data to inflate
         * @param in_len    length of input data
         * @param out       reference to output stream to receive data
         * @return  number of bytes written to stream
         */
        SAML_EXPORT unsigned int inflate(char* in, unsigned int in_len, std::ostream& out);
    };
};
