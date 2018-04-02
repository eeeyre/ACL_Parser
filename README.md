# ACL_Parser

##Application Layout
The parser is comprised of 4 files: <br />
    1. __main__py <br />
    2. parse.py <br />
    3. audit.py <br />
    4. utils.py <br />

###\_\_main__.py
This file was titled like this to allow the user to execute the software
by calling either the zipped file or the parent directory without calling
any python file directly.
<br />
<br />
This file is using the argparse library to handle commandline arguments.
It ensures that the proper arguments are passed, and that the input files
are properly opened.

###parse.py

Parse.py contains all of the logic for parsing the input files.  The logic
for extended lines is as follows: <br />
   1. Determine if the line is a remark line, an extended rule, or an error <br />
     -The line is reviewed in the following order: extended, remark, error. <br />
   2. The following regex is used to identify the ACL list name, the line number, the permit or deny status, 
        the protocol, and extracts the rest of the line following those items for future parsing 
        evaluation for extended rules.
        
    r"access-list (?P<list_name>[^\s]+) "
    r"line (?P<line_number>[^\s]+) "
    r"extended (?P<condition>[^\s]+) "
    r"(?P<protocol>[^\s]+) "
    r"(?P<remainder>.*$)"<br />
    
   3. The remainder of the line is passed to a method that parses out IP address information for source information.
        This method removes 1, 2 or 3 items from the remaining line based on the keywords and other information used.
   4. The remainder from the IP address parse method is then passed to the port parsing method for source information.
        This method removes 0, 2 or 3 items from the remainder based on what keywords are used.
   5. The remainder is passed through the IP parser and the Port parser methods one additional time to get the destination information.
   6. Finally the remainder from the above methods are checked with a final regex to get the hit count and the checksums of each line.
            
    ".*\(hitcnt=(?P<hitcount>[^)]+)\) (?P<checksum>.*) "
The logic for remarks is as follows:
   1. Use a single regex to extract the ACL Name, the line number, the remark keyword, and the remark text.
                
    r"access-list (?P<list_name>[^\s]+) line (?P<line_number>[^\s]+) remark (?P<remark>.*$)"
    
Any lines that do not match the syntax used for extended and remark lines are considered to be error lines, and are added to the errors table.
   
###audit.py

Audit.py contains the logic that comprises the audit checks for the ACL Parser.
2 audits can be performed, and one more has been included that is not fully implemented.
The implemented audits are promiscuous rules and redundant rules.

The logic for identifying promiscuous rules are as follows:
1. The use of the "any" keyword in the Destination or Source IP address fields.
2. Failing to specify a port in any extended Destination or Source Port field.
3. Using a classful IP address while using a subnet that encompasses more hosts 
than that traditional classful network would have allowed.
    - eg. 192.168.1.1/20
    - eg. 172.16.1.1/12
    - eg. 10.0.0.1/4

The logic for identifying redundant rules are as follows:
1. Check that the ACL Name matches
2. Check that the ACL Line Number is greater than the compared line number
3. Check that the traffic protocol matches
4. Check that the Source IP Address and Net Mask match
5. Check that the Source Port and conditions match
6. Check that the Destination IP Address and Net Mask match

###utils.py
The utilities file contains logic that isn't directly used for parsing or audits, but that is useful to facilitiate 
string manipulation and file formatting.

The functions included prepare and append the headers for the excel spreadsheet, and format the spreadsheet to prepare for export.
