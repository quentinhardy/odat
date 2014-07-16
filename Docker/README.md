You can use docker to rapidly deploy and use odat !

You can build it with the Dockerfile provided. 

* First, get RPMs of instant client basic, sdk (devel) and sqlplus from the Oracle web site
*(use the same directory for Dockerfile and .rpm)*

http://www.oracle.com/technetwork/topics/linuxx86-64soft-092277.html *(user registration required)*

* Edit "Dockerfile" and adapt the version of downloaded RPMs *(line 9 to 13)*

* Then :
```bash
docker build -t="odat" .
docker run --name myodat_container -i -t odat bash
```
