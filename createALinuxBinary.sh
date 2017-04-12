#/bin/bash
GLIBC_VERSION=`ldd --version | grep ldd | grep -o ')[^"]*' | sed "s/) //g"`
VERSION="libc$GLIBC_VERSION-`uname -m`"
PYINSTALLER="/usr/local/bin/pyinstaller" #or "/opt/python2.7.8/bin/pyinstaller"
#Creation
if which $PYINSTALLER >/dev/null; then
	echo "Pyinstaller has been found: good news :)"
else
	echo "Pyinstaller not found, stop!"
	exit 0
fi
mkdir -p ./build/linux/
$PYINSTALLER --clean --onedir --noconfirm --distpath="./build/linux/" --workpath="./build/" --name="odat-$VERSION" odat.py --strip
#Add a librarie manually
cp "$ORACLE_HOME"/lib/libociei.so ./build/linux/odat-$VERSION/libociei.so
cp "$ORACLE_HOME"/lib/libclntsh.so.12.1 ./build/linux/odat-$VERSION/libclntsh.so.12.1
cp "$ORACLE_HOME"/lib/libnnz12.so ./build/linux/odat-$VERSION/libnnz12.so
cp "$ORACLE_HOME"/lib/libons.so ./build/linux/odat-$VERSION/libons.so
#Required files
cp -R accounts/ ./build/linux/odat-$VERSION/accounts
cp sids.txt ./build/linux/odat-$VERSION/sids.txt
chmod a+x ./build/linux/odat-$VERSION/libociei.so
#Suppression des traces
rm -R build/odat-$VERSION/
#Compress directory
cd ./build/linux/
ls -l
export GZIP=-9
tar -cvzf "./odat-linux-$VERSION.tar.gz" ./odat-$VERSION/
read -p "Do you want delete no compressed data (Y or y for yes)? " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
rm -r ./odat-$VERSION/
fi
