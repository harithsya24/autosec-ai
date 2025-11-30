#!/usr/bin/env python3
"""
Run All Week Tests
Run Week 1, 2, and 3 tests one by one
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))


def run_week1():
    """Run Week 1 tests"""
    print("\n" + "="*70)
    print(" " * 20 + "WEEK 1 TESTS")
    print("="*70)
    
    try:
        from tests.test_week1 import TestWeek1
        tester = TestWeek1()
        return tester.run_all_tests()
    except Exception as e:
        print(f"\nERROR: Error running Week 1 tests: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_week2():
    """Run Week 2 tests"""
    print("\n" + "="*70)
    print(" " * 20 + "WEEK 2 TESTS")
    print("="*70)
    
    try:
        from tests.test_week2 import TestWeek2
        tester = TestWeek2()
        return tester.run_all_tests()
    except Exception as e:
        print(f"\nERROR: Error running Week 2 tests: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_week3():
    """Run Week 3 tests"""
    print("\n" + "="*70)
    print(" " * 20 + "WEEK 3 TESTS")
    print("="*70)
    
    try:
        from tests.test_week3_integration import TestWeek3Integration
        tester = TestWeek3Integration()
        return tester.run_all_tests()
    except Exception as e:
        print(f"\nERROR: Error running Week 3 tests: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all week tests"""
    print("="*70)
    print(" " * 15 + "AUTOSEC AI - COMPLETE TEST SUITE")
    print("="*70)
    print("\nThis script will run tests for Week 1, 2, and 3 sequentially.")
    print("Each week's tests are independent and can be run separately.\n")
    
    results = {}
    
    # Run Week 1
    print("\n" + "="*35)
    results['week1'] = run_week1()
    
    # Ask before continuing
    if not results['week1']:
        response = input("\nWARNING: Week 1 tests failed. Continue to Week 2? (y/n): ")
        if response.lower() != 'y':
            print("\nStopping tests.")
            return False
    
    # Run Week 2
    print("\n" + "="*35)
    results['week2'] = run_week2()
    
    # Ask before continuing
    if not results['week2']:
        response = input("\nWARNING: Week 2 tests failed. Continue to Week 3? (y/n): ")
        if response.lower() != 'y':
            print("\nStopping tests.")
            return False
    
    # Run Week 3
    print("\n" + "="*35)
    results['week3'] = run_week3()
    
    # Final summary
    print("\n" + "="*70)
    print(" " * 20 + "FINAL SUMMARY")
    print("="*70)
    
    for week, passed in results.items():
        status = "PASS" if passed else "FAIL"
        print(f"  {status} - {week.upper()}")
    
    all_passed = all(results.values())
    passed_count = sum(1 for v in results.values() if v)
    
    print(f"\nResults: {passed_count}/3 weeks passed")
    
    if all_passed:
        print("\nAll tests passed across all weeks!")
    else:
        print(f"\nWARNING: {3 - passed_count} week(s) had failures")
    
    return all_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

