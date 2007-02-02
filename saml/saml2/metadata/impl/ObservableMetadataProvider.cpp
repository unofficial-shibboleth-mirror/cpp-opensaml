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
 * ObservableMetadataProvider.cpp
 * 
 * A metadata provider that notifies interested parties of changes.
 */

#include "internal.h"
#include "saml2/metadata/ObservableMetadataProvider.h"

using namespace opensaml::saml2md;
using namespace std;

ObservableMetadataProvider::~ObservableMetadataProvider()
{
    for_each(m_observers.begin(),m_observers.end(),xmltooling::cleanup<Observer>());
}

void ObservableMetadataProvider::emitChangeEvent()
{
    for (std::vector<Observer*>::const_iterator i=m_observers.begin(); i!=m_observers.end(); i++) {
        (*i)->onEvent(*this);
    }
}
