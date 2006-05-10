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

#include "c:\cvs\cpp-opensaml2\samltest\saml1\core\impl\ActionTest.h"

static ActionTest suite_ActionTest;

static CxxTest::List Tests_ActionTest = { 0, 0 };
CxxTest::StaticSuiteDescription suiteDescription_ActionTest( "c:\\cvs\\cpp-opensaml2\\samltest\\saml1\\core\\impl\\ActionTest.h", 22, "ActionTest", suite_ActionTest, Tests_ActionTest );

static class TestDescription_ActionTest_testSingleElementUnmarshall : public CxxTest::RealTestDescription {
public:
 TestDescription_ActionTest_testSingleElementUnmarshall() : CxxTest::RealTestDescription( Tests_ActionTest, suiteDescription_ActionTest, 44, "testSingleElementUnmarshall" ) {}
 void runTest() { suite_ActionTest.testSingleElementUnmarshall(); }
} testDescription_ActionTest_testSingleElementUnmarshall;

static class TestDescription_ActionTest_testSingleElementOptionalAttributesUnmarshall : public CxxTest::RealTestDescription {
public:
 TestDescription_ActionTest_testSingleElementOptionalAttributesUnmarshall() : CxxTest::RealTestDescription( Tests_ActionTest, suiteDescription_ActionTest, 52, "testSingleElementOptionalAttributesUnmarshall" ) {}
 void runTest() { suite_ActionTest.testSingleElementOptionalAttributesUnmarshall(); }
} testDescription_ActionTest_testSingleElementOptionalAttributesUnmarshall;

static class TestDescription_ActionTest_testSingleElementMarshall : public CxxTest::RealTestDescription {
public:
 TestDescription_ActionTest_testSingleElementMarshall() : CxxTest::RealTestDescription( Tests_ActionTest, suiteDescription_ActionTest, 59, "testSingleElementMarshall" ) {}
 void runTest() { suite_ActionTest.testSingleElementMarshall(); }
} testDescription_ActionTest_testSingleElementMarshall;

static class TestDescription_ActionTest_testSingleElementOptionalAttributesMarshall : public CxxTest::RealTestDescription {
public:
 TestDescription_ActionTest_testSingleElementOptionalAttributesMarshall() : CxxTest::RealTestDescription( Tests_ActionTest, suiteDescription_ActionTest, 64, "testSingleElementOptionalAttributesMarshall" ) {}
 void runTest() { suite_ActionTest.testSingleElementOptionalAttributesMarshall(); }
} testDescription_ActionTest_testSingleElementOptionalAttributesMarshall;

