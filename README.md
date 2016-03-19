__ODAT linux standalone__ version at [https://github.com/quentinhardy/odat/releases/](https://github.com/quentinhardy/odat/releases/)

ODAT 
====

__ODAT__ (Oracle Database Attacking Tool) is an open source __penetration testing__ tool that tests the security of __Oracle Databases remotely__.

Usage examples of ODAT:
* You have an Oracle database listening remotely and want to find valid __SIDs__ and __credentials__ in order to connect to the database
* You have a valid Oracle account on a database and want to __escalate your privileges__ to become DBA or SYSDBA
* You have a Oracle account and you want to __execute system commands__ (e.g. __reverse shell__) in order to move forward on the operating system hosting the database

Tested on Oracle Database __10g__,  __11g__ and __12c__(12.1.0.2.0).

Changelog
====
* Version __2.1__ (__2016/03/04__) :
   * A new module (_cve_) for exploiting some CVE (Common Vulnerabilities and Exposures). CVE-2012-3137 (perhaps this number, I'm not sure...) implemented at the moment: A user authenticated can modify all tables who can select even if he can't modify them normally (no ALTER privilege).
   * new option (__--accounts-files__) for remote authentication attack which uses 2 distinct files: a login list and password list.
   * Print 10g passwords for oclHashcat compatibility.
   * bug fixes (listening with __nc__).
* Version __2.0__ (__2016/02/21__) :
 * A new module (_privesc_) for using system privileges of an Oracle user (e.g. CREATE ANY PROCEDURE) in order to gain privileged access (i.e. DBA). System privileges that can be used by ODAT in this version:
    * CREATE ANY PROCEDURE: execution of arbitrary requests with APEX_040200's privileges (e.g. modification of Oracle users' passwords)
    * CREATE PROCEDURE and EXECUTE ANY PROCEDURE: execution of arbitrary requests as SYS (e.g. gives DBA role to a user)
    * CREATE ANY TRIGER (and CREATE PROCEDURE): execution of arbitrary requests as SYS (e.g. gives DBA role to a user)
    * ANALYZE ANY (and CREATE PROCEDURE): execution of arbitrary requests as SYS (e.g. gives DBA role to a user)
    * CREATE ANY INDEX (and CREATE PROCEDURE): execution of arbitrary requests as SYS (e.g. gives DBA role to a user)
 * The module _privesc_ can be used to get all system privileges and roles granted. It shows system privileges that can be used to gain privileged access.
 * new option (-vvv) for showing SQL requests sent by ODAT in debugs
 * standalone version moved to *releases* ([https://github.com/quentinhardy/odat/releases/](https://github.com/quentinhardy/odat/releases/))
* Version __1.6__ (__2015/07/14__) :
 * new feature to detect if a target is vulnerable to TNS poisoning (CVE-2012-1675)
 * new module named *unwrapper* to unwrap PL/SQL source code wrapped, from a file or a remote database
 * some improvements done
* Version __1.5__ (__2015/03/17__) :
 * new module named *search* in order to search in column names
 * some improvements done (ex: output of tables)
 * new option : output encoding
* Version __1.4__ (__2014/12/07__) :
 * fix some false positives
 * improve the CVE-2012-3137 module: check more easily if the vulnerability can be exploited
* Version __1.3__ (__2014/10/07__) : 
 * add the *-C* option in the *all* module. This module can be used to use file which contains credentials (disable the *-U* and *-P* option)
 * add the *tnscmd* module to get TNS *alias*, database *version* (thanks to VSNNUM) and TNS *status*
 * bug fix: name server can be given to the *-s* option
* Version __1.2__ (__2014/08/08__) : 
 * add the *SMB* module to capture a SMB authentication
 * add an option (*SHOW_SQL_REQUESTS_IN_VERBOSE_MODE*) in *Constants.py* to show SQL requests sent to the database server
* Version __1.1__ (__2014/07/28__) : 
 * add the *DBMS_LOB* module useful in order to download files stored on a remote server through Oracle Database.
 * bug fix: java source code: "getenv no longer supported, use properties and -D instead"
* Version __1.0__ (__2014/06/26__) : 
 * first ODAT version.

Features
====

Thanks to ODAT, you can:

* search __valid SID__ on a remote Oracle Database listener via:
 * a dictionary attack
 * a brute force attack
 * ALIAS of the listener
* search Oracle __accounts__ using:
 * a dictionary attack
 * each Oracle user like the password (need an account before to use this attack)
* __execute system commands__ on the database server using:
 * DBMS_SCHEDULER
 * JAVA
 * external tables
 * oradbg
* __download files__ stored on the database server using:
 * UTL_FILE
 * external tables
 * CTXSYS
 * DBMS_LOB
* __upload files__ on the database server using:
 * UTL_FILE
 * DBMS_XSLPROCESSOR
 * DBMS_ADVISOR
* __delete files__ using:
 * UTL_FILE
* __gain privileged access__ using these following system privileges combinations (see help for *privesc* module commands): (__NEW__ : 2016/02/21)
 * CREATE ANY PROCEDURE
 * CREATE PROCEDURE and EXECUTE ANY PROCEDURE
 * CREATE ANY TRIGER (and CREATE PROCEDURE)
 * ANALYZE ANY (and CREATE PROCEDURE)
 * CREATE ANY INDEX (and CREATE PROCEDURE)
* __send/reveive HTTP requests__ from the database server using:
 * UTL_HTTP
 * HttpUriType
* __scan ports__ of the local server or a remote server using:
 * UTL_HTTP
 * HttpUriType
 * UTL_TCP
* __capture a SMB authentication__ through:
 * an index in order trigger a SMB connection
* exploit some CVE: 
 * the __CVE-2012-313__ (http://cvedetails.com/cve/2012-3137)
      * pickup the session key and salt for arbitrary users
      * attack by dictionary on sessions
 * the __CVE-2012-3137__? (https://twitter.com/gokhanatil/status/595853921479991297): A user authenticated can modify all tables who can select even if he can't modify them normally (no ALTER privilege). 
* check __CVE-2012-1675__ (http://seclists.org/fulldisclosure/2012/Apr/204)
* __search in column names__ thanks to the *search* module:
 * search a pattern (ex: password) in column names
* __unwrap__ PL/SQL source code (10g/11g and 12c)
* get __system privileges__ and __roles granted__. It is possible to get privileges and roles of roles granted also (__NEW__ : 2016/02/21)

![Alt text](./pictures/ODAT_main_features_v2.0.jpg)

Supported Platforms and dependencies
====

ODAT is compatible with __Linux__ only.

__Standalone versions__ exist in order to don't have need to install dependencies and slqplus (see [https://github.com/quentinhardy/odat/releases/](https://github.com/quentinhardy/odat/releases/)).
The ODAT standalone has been generated thanks to *pyinstaller*.

If you want to have the __development version__ installed on your computer, these following tools and dependencies are needed:
* Langage: Python 2.7
* Oracle dependancies: 
 * Instant Oracle basic
 * Instant Oracle sdk
* Python libraries: 
 * cx_Oracle
 * colorlog (recommended)
 * termcolor (recommended)
 * argcomplete (recommended)
 * pyinstaller (recommended)

Installation (optional, for development version)
====

This part describes how to install instantclient, CX_Oracle and some others python libraries on __Ubuntu__ in order to have the ODAT development version. 
Don't forget that an ODAT standalone version exists at [https://github.com/quentinhardy/odat/releases/](https://github.com/quentinhardy/odat/releases/): __It is not required to install something for use the standalone version__

* Get instant client basic, sdk (devel) and sqlplus from the Oracle web site:
 * X64: http://www.oracle.com/technetwork/topics/linuxx86-64soft-092277.html
 * X86: http://www.oracle.com/technetwork/topics/linuxsoft-082809.html

* Install *python-dev*, *alien* and *libaio1* package (for sqlplus):
```bash
sudo apt-get install libaio1 python-dev alien python-pip
```

* Generate DEB files from RPM files thanks to :
```bash
sudo alien --to-deb oracle-instantclient11.2-basic-???.x???.rpm
sudo alien --to-deb oracle-instantclient11.2-sqlplus-???.x???.rpm
sudo alien --to-deb oracle-instantclient11.2-devel-???.x???.rpm
```

* Install instant client basic, sdk and sqlplus:
```bash
sudo dpkg -i oracle-instantclient11.2-basic-???.x???.deb
sudo dpkg -i oracle-instantclient11.2-sqlplus-???.x???.deb
sudo dpkg -i oracle-instantclient11.2-devel_???_???.deb
```

* Put these lines in your */etc/profile* file in order to define Oracle *env* variables:
```bash
export ORACLE_HOME=/usr/lib/oracle/11.2/client64/
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$ORACLE_HOME/lib
export PATH=$ORACLE_HOME/bin:$PATH
```

* Restart your session (to apply env variables)  and run *sqlplus*:
```bash
sqlplus
```

> If nor error: good job, Continue...

* Create a symlink to your so file.
```bash
cd $ORACLE_HOME/lib/
sudo ln -s libclntsh.so.11.1   libclntsh.so
```

* Create the */etc/ld.so.conf.d/oracle.conf* file and add the path to Oracle home:
```
/usr/lib/oracle/11.2/client64/lib/
```

* Update the ldpath using:
```bash
sudo ldconfig
```

* Install *CX_Oracle*
```bash
sudo -s
source /etc/profile
pip install cx_Oracle
```

* Test if all is good:
```bash
python -c 'import cx_Oracle' 
```
> This command should *just return* without errors.

* Install some python libraries:
```bash
sudo apt-get install python-scapy
sudo pip install colorlog termcolor pycrypto passlib
sudo pip install argcomplete && sudo activate-global-python-argcomplete
```

* Install the __development__ version of pyinstaller (http://www.pyinstaller.org/).
```bash
python setup.py install
```

* Run ODAT:
```bash
./odat.py -h
```

> __Good job if you have not errors:)__

Examples
====

Examples are on the wiki: [https://github.com/quentinhardy/odat/wiki/ODAT-Home](https://github.com/quentinhardy/odat/wiki/ODAT-Home) 

---
| __Quentin HARDY__    |
| ------------- |
| __quentin.hardy@bt.com__    |
| __qhardyfr@gmail.com__  |

