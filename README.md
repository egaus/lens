
<div style="text-align:center"><img src ="https://github.com/egaus/lens/blob/master/img/lens_logo.PNG" /></div>

Lens Framework: Customizable Malware Detection
==============================================
Lens is a next generation open source malware analysis framework, built to get up and running quickly on a single system or to be deployed across a distributed environment.  Lens allows you to supplement and fully customize your organization's ability to detect malware with your own signatures, thresholds, and machine learning algorithms.  As defenders, having the ability to deploy our own custom malware detection before, during, or after a campaign can be invaluable.

Installation For Linux:
=======================
0. Yara-Python is a dependency and in order to make use of the most recent version of Yara, you may need to build from source.
0. First install build dependencies
```
sudo apt-get install autoconf
sudo apt-get install libtool
sudo apt-get install python-dev
```

0. Now install Yara and Yara-Python
```
wget https://github.com/plusvic/yara/archive/v3.4.0.tar.gz
tar -xvf v3.4.0.tar.gz
cd yara-3.4.0
./configure
make
sudo make install
cd yara-python
python setup.py build
python setup.py install
```

0. pefile - dependecy required to parse portable executable files.




