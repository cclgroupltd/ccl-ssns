# ccl-ssns

This module is now out of date and will not process data from recent versions of Chrome. An updated module can be found in this repo: https://github.com/cclgroupltd/ccl_chrome_indexeddb

A set of Python modules for performing off-line parsing of Chrome session files ("Current Session", "Last Session", "Current Tabs", "Last Tabs"). 

Three modules - 
 * `ccl_chrome_pickle.py` - a re-implementation of the PickleIterator for Python
 * `ccl_chrome_tab_state.py` - Reimplementation of the relevant classes in Chrome related to Tab and Session management for Python
 * `Chrome-SNSS-Parse-OS.py` - Command line utility for reading and reporting on the contents of the Last/Current Tabs/Session files

A (now outdated) blog explaining the file structure can be found here: http://www.cclgroupltd.com/chrome-session-and-tabs-files-and-the-puzzle-of-the-pickle/
