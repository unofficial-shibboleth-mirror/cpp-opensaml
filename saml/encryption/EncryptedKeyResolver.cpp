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
 * EncryptedKeyResolver.cpp
 * 
 * SAML-specific encrypted key resolver 
 */
 
#include "internal.h"
#include "encryption/EncryptedKeyResolver.h"
#include "saml2/core/Assertions.h"

using namespace xmlencryption;
using namespace std;

const EncryptedKey* opensaml::EncryptedKeyResolver::resolveKey(const EncryptedData& encryptedData, const XMLCh* recipient) const
{
    const vector<EncryptedKey*>& keys=m_ref.getEncryptedKeys();
    for (vector<EncryptedKey*>::const_iterator i=keys.begin(); i!=keys.end(); i++) {
        if (XMLString::equals(recipient,(*i)->getRecipient()))
            return (*i);
    }
    return NULL;
}
