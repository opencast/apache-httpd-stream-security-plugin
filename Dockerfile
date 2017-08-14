FROM httpd:2.4

ENV JANSSON_VERSION="2.10" \
    JANSSON_SHA="78215ad1e277b42681404c1d66870097a50eb084be9d771b1d15576575cf6447"

RUN \
  # Removing libssl1.0.0 to resolve dependency conflict with libssl-dev last version
  apt-get remove -y libssl1.0.0 \
  # Install some prerequisites to fetch and build software
  && apt-get update \
  && apt-get install -y libssl-dev \
  && apt-get install -y libaprutil1 libaprutil1-dev libaprutil1-ldap \
  && apt-get install -y build-essential \
  && apt-get install -y curl \
  && apt-get install -y make \
  # Compile and install Jansson JSON library
  && curl -L -o d.tgz http://www.digip.org/jansson/releases/jansson-$JANSSON_VERSION.tar.gz \
  && echo "${JANSSON_SHA}  d.tgz" >> jansson.sha \
  && sha256sum -c jansson.sha \
  && rm jansson.sha \
  && tar -xzvf d.tgz \
  && rm d.tgz \
  && cd jansson-$JANSSON_VERSION \
  && ./configure --prefix=/usr/ \
  && make \
  && make check \
  && make install \
  && ldconfig \
  && cd .. \
  && rm -rf jansson-$JANSSON_VERSION \
  # Remove unneeded tools
  && apt-get remove -y --purge make \
  && apt-get remove -y --purge curl \
  && apt-get clean
