FROM debian:latest
# Reduce output from debconf
ENV DEBIAN_FRONTEND noninteractive
# Install python-dev, alien and libaio1 package (for sqlplus) and some python libraries
# Removed apt-utils wget dpkg-dev 
RUN apt update && apt-get install -y --no-install-recommends git libaio1 alien build-essential python3-dev python3-pip python3-scapy ca-certificates &&\
    apt clean &&\
    rm -rf /var/lib/apt/lists/*
WORKDIR /tmp
# Generate DEB files from RPM files to install instant client basic, sdk and sqlplus
ADD oracle-* /tmp/
RUN alien --to-deb oracle-* &&\
    dpkg -i oracle-*.deb &&\
    bash -c 'rm *.{deb,rpm}'
# Define Oracle env variables & Create the /etc/ld.so.conf.d/oracle.conf file and add the path to Oracle home
RUN bash -c '\
	SQLPLUS_Lib=$(find / -name "libsqlplus.so") &&\
	SQLPLUS_Folder=${SQLPLUS_Lib%/lib/libsqlplus.so} &&\
	echo "export ORACLE_HOME=${SQLPLUS_Folder}" >> /etc/profile &&\
	echo "export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:\$ORACLE_HOME/lib" >> /etc/profile &&\
	echo "export PATH=\$ORACLE_HOME/bin:\$PATH" >> /etc/profile &&\
 	echo "$ORACLE_HOME/lib/" > /etc/ld.so.conf.d/oracle.conf &&\
	ldconfig'
# Install CX_Oracle, Python libraries and pyinstaller
RUN pip install cx_Oracle colorlog termcolor pycrypto argcomplete pyinstaller python-libnmap passlib -i https://pypi.python.org/simple/ &&\
    activate-global-python-argcomplete
# Change to /root et clone odat project
WORKDIR /root
RUN git clone --branch master-python3 --single-branch https://github.com/quentinhardy/odat.git
WORKDIR odat
ENTRYPOINT ["python3", "odat.py"]
