FROM debian:wheezy
# Reduce output from debconf
env DEBIAN_FRONTEND noninteractive

# Install python-dev, alien and libaio1 package (for sqlplus) and some python libraries
RUN apt-get update && apt-get install -y --no-install-recommends apt-utils git wget libaio1 alien build-essential dpkg-dev python-dev python-pip python-scapy ca-certificates
WORKDIR /tmp
# Generate DEB files from RPM files to install instant client basic, sdk and sqlplus
ADD oracle-instantclient12.1-basic-12.1.0.1.0-1.x86_64.rpm /tmp/oracle-instantclient12.1-basic-12.1.0.1.0-1.x86_64.rpm
ADD oracle-instantclient12.1-devel-12.1.0.1.0-1.x86_64.rpm /tmp/oracle-instantclient12.1-devel-12.1.0.1.0-1.x86_64.rpm
ADD oracle-instantclient12.1-sqlplus-12.1.0.1.0-1.x86_64.rpm /tmp/oracle-instantclient12.1-sqlplus-12.1.0.1.0-1.x86_64.rpm
RUN alien --to-deb oracle-instantclient12.1-basic-12.1.0.1.0-1.x86_64.rpm oracle-instantclient12.1-sqlplus-12.1.0.1.0-1.x86_64.rpm oracle-instantclient12.1-devel-12.1.0.1.0-1.x86_64.rpm
RUN dpkg -i oracle-instantclient12.1-basic_12.1.0.1.0-2_amd64.deb oracle-instantclient12.1-sqlplus_12.1.0.1.0-2_amd64.deb oracle-instantclient12.1-devel_12.1.0.1.0-2_amd64.deb
RUN bash -c 'rm *.{deb,rpm}'
# Define Oracle env variables
RUN bash -c 'echo "export ORACLE_HOME=/usr/lib/oracle/12.1/client64" >> /etc/profile'
RUN bash -c 'echo "export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:\$ORACLE_HOME/lib" >> /etc/profile'
RUN bash -c 'echo "export PATH=\$ORACLE_HOME/bin:\$PATH" >> /etc/profile'
# Create the /etc/ld.so.conf.d/oracle.conf file and add the path to Oracle home
RUN bash -c 'echo "/usr/lib/oracle/12.1/client64/lib/" > /etc/ld.so.conf.d/oracle.conf'
RUN bash -c 'ldconfig'
# Install CX_Oracle
RUN bash -cl 'pip install cx_Oracle -i https://pypi.python.org/simple/'
# Install some python libraries and pyinstaller
RUN pip install colorlog termcolor pycrypto argcomplete pyinstaller -i https://pypi.python.org/simple/
RUN activate-global-python-argcomplete
# Change to /root et clone odat project
WORKDIR /root
RUN git clone https://github.com/quentinhardy/odat.git
WORKDIR odat
