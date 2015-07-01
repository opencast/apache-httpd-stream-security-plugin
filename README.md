# Apache HTTPd Stream Security Plugin

This plugin brings Opencast Stream Security to the Apache HTTPd server. More information about Opencast Stream Security can be found in the [Opencast Administration Guide]().

## Installation

#### 1. Install Package Dependencies For Your Platform (Example is CentOS 6)

    sudo yum install httpd-devel libtool openssl-devel

#### 2. Install Jansson For Json Support

    cd /tmp
    wget http://www.digip.org/jansson/releases/jansson-2.7.tar.gz
    tar -xvf jansson-2.7.tar.gz
    cd jansson-2.7
    ./configure
    make
    make check
    sudo make install
    sudo ln -s /usr/local/lib/libjansson.so.4 /usr/lib/libjansson.so.4
    sudo ldconfig

#### 3. Download and Install Stream Security plugin
    sudo yum install git
    cd /tmp
    git clone http://bitbucket.org/entwinemedia/apache-httpd-stream-security-plugin.git
    cd apache-httpd-stream-security-plugin
    make
    sudo make install

## Configuration

To use the stream security plugin you will need to add it as a handler for a directory by adding "SetHandler stream-security". For example in the file "/etc/httpd/conf.d/matterhorn-downloads.conf" it would look like this:

    <Directory "/var/matterhorn/distribution/downloads">     
        SetHandler stream-security     
        Options FollowSymLinks MultiViews ExecCGI     
        Order allow,deny     
        Allow from all
    </Directory>


There are two directives available for configuring stream security. These are added to your server configuration for example Virtual host. So for example in the "/etc/httpd/conf.d/matterhorn-downloads.conf" file:

    <VirtualHost *:80>   
    # Principal server name   
    ServerName matterhorn.download.com
    ...
    # Configure Stream Security   
    StreamSecurityEnabled On   
    StreamSecurityKeysPath /etc/httpd/conf/stream-security-keys.json
    StreamSecurityDebug Off
    ...

Whether the plugin is enabled (by default On, can be set to Off):
    
    StreamSecurityEnabled On

Where the location of the id / key pairs for signing the policies is located: 

    StreamSecurityKeysPath /etc/httpd/conf/stream-security-keys.json

If there is no file in the right location it will warn you **Unable to open file stream security configuration file '/etc/httpd/conf/stream-security-keys.json' because 'No such file or directory'** when you first start up httpd.
    
If detailed debug information should be sent with the response (by default Off, can be set to On):

    StreamSecurityDebug On

The last configuration step is to configure the key id / secret pairs that need to have the same id and secret as on the matterhorn server. There is an example file in the downloaded plugin code called stream-security-keys.json. It is in json format so that when you create your own it should look like the example file.

    {
       "keys":[
          {
             "keyId":"demoKeyOne",
             "secret":"6EDB5EDDCF994B7432C371D7C274F"
          },
          {
             "keyId":"demoKeyTwo",
             "secret":"C843C21ECF59F2B38872A1BCAA774"
          }
       ]
    }

Just create the file at the location you specified with `StreamSecurityKeysPath`.

Now restart your httpd service and the stream security handler will prevent accesses of files without the proper policy, signature and key id.

    sudo service httpd restart