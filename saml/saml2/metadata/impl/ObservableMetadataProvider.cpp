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
 * ObservableMetadataProvider.cpp
 * 
 * A metadata provider that notifies interested parties of changes.
 */

#include "internal.h"
#include "saml2/metadata/ObservableMetadataProvider.h"

#include <xmltooling/util/Threads.h>

using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace std;

ObservableMetadataProvider::ObservableMetadataProvider(const xercesc::DOMElement* e)
    : MetadataProvider(e), m_observerLock(Mutex::create())
{
}

ObservableMetadataProvider::~ObservableMetadataProvider()
{
    delete m_observerLock;
}

void ObservableMetadataProvider::emitChangeEvent() const
{
    Lock lock(m_observerLock);
    for (vector<const Observer*>::const_iterator i=m_observers.begin(); i!=m_observers.end(); i++) {
        (*i)->onEvent(*this);
    }
}

void ObservableMetadataProvider::addObserver(const Observer* newObserver) const
{
    Lock lock(m_observerLock);
    m_observers.push_back(newObserver);
}

const ObservableMetadataProvider::Observer* ObservableMetadataProvider::removeObserver(const Observer* oldObserver) const
{
    Lock lock(m_observerLock);
    for (vector<const Observer*>::iterator i=m_observers.begin(); i!=m_observers.end(); i++) {
        if (oldObserver==(*i)) {
            m_observers.erase(i);
            return oldObserver;
        }
    }
    return NULL;
}
