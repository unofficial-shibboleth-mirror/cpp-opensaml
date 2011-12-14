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
 * EncryptedKeyResolver.cpp
 * 
 * SAML-specific encrypted key resolver.
 */
 
#include "internal.h"
#include "encryption/EncryptedKeyResolver.h"
#include "saml2/core/Assertions.h"

#include <boost/lambda/bind.hpp>
#include <boost/lambda/lambda.hpp>

using namespace xmlencryption;
using opensaml::saml2::EncryptedElementType;
using namespace boost::lambda;
using namespace boost;
using namespace std;

opensaml::EncryptedKeyResolver::EncryptedKeyResolver(const EncryptedElementType& ref) : m_ref(ref)
{
}

opensaml::EncryptedKeyResolver::~EncryptedKeyResolver()
{
}

const EncryptedKey* opensaml::EncryptedKeyResolver::resolveKey(const EncryptedData& encryptedData, const XMLCh* recipient) const
{
    const EncryptedKey* base = xmlencryption::EncryptedKeyResolver::resolveKey(encryptedData, recipient);
    if (base)
        return base;

    static bool (*equal_fn)(const XMLCh*, const XMLCh*) = &XMLString::equals;

    // Look for first match that has no Recipient attribute, or matches the input recipient.
    // Using XMLString::equals allows for both to be NULL and still match.
    vector<EncryptedKey*>::const_iterator k = find_if(
        m_ref.getEncryptedKeys().begin(), m_ref.getEncryptedKeys().end(),
        (lambda::bind(&EncryptedKey::getRecipient, _1) == ((const XMLCh*)nullptr) ||
            lambda::bind(equal_fn, recipient, lambda::bind(&EncryptedKey::getRecipient, _1)))
        );
    return (k != m_ref.getEncryptedKeys().end()) ? (*k) : nullptr;
}
