/*
 *  Copyright 2009 Internet2
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
 * SAML2AssertionPolicy.cpp
 *
 * Policy subclass to track SAML 2.0 Assertion SubjectConfirmation.
 */

#include "internal.h"
#include "saml2/profile/SAML2AssertionPolicy.h"

using namespace opensaml::saml2;
using namespace opensaml;

void SAML2AssertionPolicy::reset(bool messageOnly)
{
    SecurityPolicy::reset(messageOnly);
    SAML2AssertionPolicy::_reset(messageOnly);
}
