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
 * MetadataCredentialCriteria.cpp
 * 
 * Metadata-based CredentialCriteria subclass.
 */

#include "internal.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataCredentialContext.h"
#include "saml2/metadata/MetadataCredentialCriteria.h"

#include <xmltooling/security/Credential.h>

using namespace opensaml::saml2md;
using namespace xmltooling;

MetadataCredentialCriteria::MetadataCredentialCriteria(const RoleDescriptor& role) : m_role(role)
{
    const EntityDescriptor* entity = dynamic_cast<const EntityDescriptor*>(role.getParent());
    if (entity) {
        auto_ptr_char name(entity->getEntityID());
        setPeerName(name.get());
    }
}

bool MetadataCredentialCriteria::matches(const Credential& credential) const
{
    const MetadataCredentialContext* context = dynamic_cast<const MetadataCredentialContext*>(credential.getCredentalContext());
    if (context) {
        // Check for a usage mismatch.
        if ((getUsage() & (xmltooling::Credential::SIGNING_CREDENTIAL | xmltooling::Credential::TLS_CREDENTIAL)) &&
                XMLString::equals(context->getKeyDescriptor().getUse(),KeyDescriptor::KEYTYPE_ENCRYPTION))
            return false;
        else if ((getUsage() & xmltooling::Credential::ENCRYPTION_CREDENTIAL) &&
                XMLString::equals(context->getKeyDescriptor().getUse(),KeyDescriptor::KEYTYPE_SIGNING))
            return false;
    }
    return CredentialCriteria::matches(credential);
}
