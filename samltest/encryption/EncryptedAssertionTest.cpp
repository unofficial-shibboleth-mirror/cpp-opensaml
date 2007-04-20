/* Generated file, do not edit */

#ifndef CXXTEST_RUNNING
#define CXXTEST_RUNNING
#endif

#define _CXXTEST_HAVE_STD
#define _CXXTEST_HAVE_EH
#define _CXXTEST_ABORT_TEST_ON_FAIL
#include <cxxtest/TestListener.h>
#include <cxxtest/TestTracker.h>
#include <cxxtest/TestRunner.h>
#include <cxxtest/RealDescriptions.h>

#include "c:\cvs\cpp-opensaml2\samltest\encryption\EncryptedAssertionTest.h"

static EncryptedAssertionTest suite_EncryptedAssertionTest;

static CxxTest::List Tests_EncryptedAssertionTest = { 0, 0 };
CxxTest::StaticSuiteDescription suiteDescription_EncryptedAssertionTest( "c:\\cvs\\cpp-opensaml2\\samltest\\encryption\\EncryptedAssertionTest.h", 30, "EncryptedAssertionTest", suite_EncryptedAssertionTest, Tests_EncryptedAssertionTest );

static class TestDescription_EncryptedAssertionTest_testEncryptedAssertion : public CxxTest::RealTestDescription {
public:
 TestDescription_EncryptedAssertionTest_testEncryptedAssertion() : CxxTest::RealTestDescription( Tests_EncryptedAssertionTest, suiteDescription_EncryptedAssertionTest, 59, "testEncryptedAssertion" ) {}
 void runTest() { suite_EncryptedAssertionTest.testEncryptedAssertion(); }
} testDescription_EncryptedAssertionTest_testEncryptedAssertion;

