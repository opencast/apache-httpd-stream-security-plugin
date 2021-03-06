# Apache HTTPd Stream Security Plugin

This plugin brings Opencast Stream Security to the Apache HTTPd server. More information about Opencast Stream Security can be found in the [Opencast Administration Guide](https://docs.opencast.org).

Opencast installations can use Apache HTTPd to distribute files over HTTP or HTTPS, with the verification of signed URLs carried out by a custom component available from Bitbucket: http://bitbucket.org/opencast-community/apache-httpd-stream-security-plugin.

## Install Dependencies
In order to build the HTTPd component, some dependencies need to be installed first. The example routine is based on CentOS 6 and will work similarly using alternate platforms and/or package managers.

#### 1. Install Package Dependencies For Your Platform (Example is CentOS 6)

    sudo yum install httpd-devel libtool openssl-devel

#### 2. Install Jansson For Json Support

    cd /tmp
    wget http://www.digip.org/jansson/releases/jansson-2.10.tar.gz
    tar -xvf jansson-2.10.tar.gz
    cd jansson-2.10
    ./configure
    make
    make check
    sudo make install
    sudo ln -s /usr/local/lib/libjansson.so.4 /usr/lib/libjansson.so.4
    sudo ldconfig

## Install Stream Security HTTPd Component
Once the dependencies are in place, the HTTPd component can be built with the following commands:

    sudo yum install git
    cd /tmp
    git clone http://bitbucket.org/opencast-community/apache-httpd-stream-security-plugin.git
    cd apache-httpd-stream-security-plugin
    ./configure
    make
    sudo make install

## Configure

In order to use stream security load the module in the httpd config with

    LoadModule stream_security_module modules/mod_stream_security.so

The Stream Security component is implemented as an [Apache Handler](https://httpd.apache.org/docs/2.2/handler.html). To activate the component, the handler must be added to the HTTPd configuration:

```xml
<Directory "/var/matterhorn/distribution/downloads">
    ...
    SetHandler stream-security
    ...
</Directory>
```

Besides the handler, there are two directives which need to be defined:
* `StreamSecurityEnabled` - (`On/Off`, default `On`)
* `StreamSecurityKeysPath` - {path to the keys file}

Example:

```xml
<VirtualHost *:80>    
    ...
    StreamSecurityEnabled On
    StreamSecurityKeysPath /etc/httpd/conf/stream-security-keys.json
    ...
</VirtualHost>
```

Additionally, there are two optional directives which can be defined:
* `StreamSecurityDebug` - (`On/Off`, default `Off`) - Returns an html document of the result of the request for a resource instead of actually returning the resource / denying the source. Useful for trying to determine why a request for a resource failed.
* `StreamSecurityStrict` - (`On/Off`, default `On`) - If turned on, the entire URL will be considered when comparing the current request for a resource against the policy, including the scheme (http, https etc.), hostname  and optional port. If turned off, only the path to the resource will be considered. So if the request is for a resource at `http://download.matterhorn.com:8080/the/full/path/video.mp4`, and strict mode is disabled, only the `/the/full/path/video.mp4` will be checked against the policy. This flexibility is useful when using things like load balancers, where the Apache hostname may not match the requested hostname or if a video player is rewriting requests, e.g. by inserting the port number.

#### Keys File
The final configuration involves setting the parameters for id and key for each key. The entries here need to have the same values for `id` and `key` as used for the Signing Providers configuration, because the `id` is part of the policy and the `key` is used to sign and verify the request.

An example configuration file is contained in the component code called stream-security-keys.json and as below:

Example:

```json
{
  "keys":[
    {
      "id":"demoKeyOne",
      "key":"6EDB5EDDCF994B7432C371D7C274F"
    },
    {
      "id":"demoKeyTwo",
      "key":"C843C21ECF59F2B38872A1BCAA774"
    }
  ]
}
```

## Development

### Bump version of plugin

Bumping the version of the plugin is a manual task and involves two steps:

1. Change the version in the file `configure.ac` in the `AC_INIT` section.
2. Rebuild the `configure` file by running the `autoconf` tool without any further parameters.

Changes in both files, `configure.ac` and `configure` need to be committed to the version control system.


### Docker based build environment

The project comes with a `Dockerfile` which defines a Docker image useful for tasks during development. In order to build the image, execute this task: 

    docker build -t stream-security-build-env .

### Build distribution archive

The distribution archive can be created leveraging the Docker image created in the previous step by executing this command:

    docker run --rm -v $(pwd):/tmp -w /tmp stream-security-build-env ./configure && make dist distclean

As a result, you should find the archive in your working directory.
