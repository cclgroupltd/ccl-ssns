A Python module for performing off-line parsing of Chrome session files ("Current Session", "Last Session", "Current Tabs", "Last Tabs").

The module contains a class structure representing the data in the files and functions for reading the files into these structures: `load(f, file_type)` and `load_iter(f, file_type)`.

There is also a command line interface which will read a file and output a simple HTML report.

A blog explaining the file structure can be found here: http://digitalinvestigation.wordpress.com/2012/09/03/chrome-session-and-tabs-files-and-the-puzzle-of-the-pickle/

_To download the scripts go to the "Source" tab and click "Browse"_


---


### Other projects ###
  * http://code.google.com/p/ccl-asl/ - ccl\_asl: Python module and command line interface for offline processing of iOS and OSX ASL (Apple System Log) files
  * http://code.google.com/p/ccl-bplist/ - ccl\_bplist: Python module for parsing Binary Property List files
  * http://code.google.com/p/ccl-ipd/ - ccl\_ipd: Python module for parsing BlackBerry IPD backup files