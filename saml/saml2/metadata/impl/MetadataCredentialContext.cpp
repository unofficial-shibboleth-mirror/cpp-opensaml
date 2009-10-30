/*
 *  Copyright 2001-2009 Internet2
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
 * MetadataCredentialContext.cpp
 * 
 * Metadata-based CredentialContext subclass.
 */

#include "internal.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataCredentialContext.h"

using namespace opensaml::saml2md;

MetadataCredentialContext::MetadataCredentialContext(const KeyDescriptor& descriptor)
    : KeyInfoCredentialContext(descriptor.getKeyInfo()), m_descriptor(descriptor)
{
}

MetadataCredentialContext::~MetadataCredentialContext()
{
}

const KeyDescriptor& MetadataCredentialContext::getKeyDescriptor() const
{
    return m_descriptor;
}
