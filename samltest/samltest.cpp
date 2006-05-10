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
#include <cxxtest/ErrorPrinter.h>

int main() {
 return CxxTest::ErrorPrinter().run();
}
#include "c:\cvs\cpp-opensaml2\samltest\samltest.h"

static GlobalTest suite_GlobalTest;

static CxxTest::List Tests_GlobalTest = { 0, 0 };
CxxTest::StaticSuiteDescription suiteDescription_GlobalTest( "c:\\cvs\\cpp-opensaml2\\samltest\\samltest.h", 59, "GlobalTest", suite_GlobalTest, Tests_GlobalTest );

static class TestDescription_GlobalTest_testGlobal : public CxxTest::RealTestDescription {
public:
 TestDescription_GlobalTest_testGlobal() : CxxTest::RealTestDescription( Tests_GlobalTest, suiteDescription_GlobalTest, 62, "testGlobal" ) {}
 void runTest() { suite_GlobalTest.testGlobal(); }
} testDescription_GlobalTest_testGlobal;

#include <cxxtest/Root.cpp>
