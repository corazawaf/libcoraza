FROM ubuntu:18.04

# shell cannot be interactive
ARG DEBIAN_FRONTEND=noninteractive
RUN apt update && \
    apt install -y apache2 apache2-dev autoconf automake build-essential git wget

RUN apt install -y software-properties-common && \
    add-apt-repository ppa:longsleep/golang-backports && \
    apt update && \
    apt install -y golang-go

# install libinjection
RUN git clone https://github.com/libinjection/libinjection /tmp/li && \
    gcc -std=c99 -Wall -Werror -fpic -c /tmp/li/src/libinjection_sqli.c -o /tmp/li/libinjection_sqli.o  && \
    gcc -std=c99 -Wall -Werror -fpic -c /tmp/li/src/libinjection_xss.c -o /tmp/li/libinjection_xss.o && \
    gcc -std=c99 -Wall -Werror -fpic -c /tmp/li/src/libinjection_html5.c -o /tmp/li/libinjection_html5.o && \
    gcc -dynamiclib -shared -o /tmp/li/libinjection.so /tmp/li/libinjection_sqli.o /tmp/li/libinjection_xss.o /tmp/li/libinjection_html5.o && \
    cp /tmp/li/*.so /usr/local/lib && \
    cp /tmp/li/*.o /usr/local/lib && \
    cp /tmp/li/src/*.h /usr/local/include/ && \
    chmod 444 /usr/local/include/libinjection* && \
    rm -rf /tmp/libinjection && \
    ldconfig



RUN apt install -y libpcre++-dev
COPY vendor/ ./vendor/
COPY * .
RUN export GOPATH=/tmp/go && \
    mkdir -p $GOPATH/src/github.com/jptosso/coraza-cexport && \
    cp -r *.go *.sum *.mod vendor $GOPATH/src/github.com/jptosso/coraza-cexport 
RUN cd /tmp/go$GOPATH/src/github.com/jptosso/coraza-cexport && \
    go build -buildmode=c-shared -o /usr/local/lib/libcoraza.so export.go && \
    mv /usr/local/lib/libcoraza.h /usr/local/include/coraza.h && \
    ldconfig -v /usr/local/lib
RUN mkdir -p /usr/lib/apache2/modules /etc/apache2/mods-available
RUN make clean && \
    apxs -i -Wc,-fPIC -Wc,-O0 -a -L/usr/local/lib -c -lcoraza mod_coraza.c coraza_config.c coraza_filters.c coraza_utils.c

#RUN echo SecRule REQUEST_URI "/denied" "id:1,phase:1,deny,status:500" > /etc/apache2/coraza.conf
#COPY examples/apache-vhost.conf /etc/apache2/sites-enabled/000-default.conf
#RUN apache2ctl -k start
CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]