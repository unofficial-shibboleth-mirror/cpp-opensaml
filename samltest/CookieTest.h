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

#include "binding.h"

using namespace std;

class CookieTest : public CxxTest::TestSuite, public SAMLBindingBaseTestCase
{
public:
    void setUp() {
        m_headers["Cookie"] = "   foo=bar;foo2=bar2;;  foo3  = bar3 ;foo4 =  bar4;;";
    }
    void tearDown() {
    }
    void testCookie(void) {
        const char* val = getCookie("foo");
        TSM_ASSERT_SAME_DATA("cookie 'foo' with incorrect value", val, "bar", 3);

        val = getCookie("foo2");
        TSM_ASSERT_SAME_DATA("cookie 'foo2' with incorrect value", val, "bar2", 4);

        val = getCookie("foo3");
        TSM_ASSERT_SAME_DATA("cookie 'foo3' with incorrect value", val, " bar3 ", 6);

        val = getCookie("foo4");
        TSM_ASSERT_SAME_DATA("cookie 'foo4' with incorrect value", val, "  bar4", 6);

        val = getCookie("foo5");
        TSM_ASSERT("cookie 'foo5' had a value", val == nullptr);
    }
};
