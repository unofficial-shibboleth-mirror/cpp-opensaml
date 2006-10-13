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
 * EncryptedKeyResolver.cpp
 * 
 * SAML-specific encrypted key resolver 
 */
 
#include "internal.h"
#include "encryption/EncryptedKeyResolver.h"

using namespace xmlencryption;
using namespace std;

EncryptedKey* opensaml::EncryptedKeyResolver::resolveKey(EncryptedData* encryptedData)
{
    const vector<EncryptedKey*>& keys=m_ref.getEncryptedKeys();
    for (vector<EncryptedKey*>::const_iterator i=keys.begin(); i!=keys.end(); i++) {
        if (XMLString::equals(m_recipient,(*i)->getRecipient()))
            return (*i);
    }
    return NULL;
}
