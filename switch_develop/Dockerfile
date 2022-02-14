FROM alpine:3.3

RUN apk add --update openvswitch nano tcpdump && rm -rf /var/cache/apk/*

VOLUME ["/etc/openvswitch/", "~/.ssh"]

ADD boot.sh /bin/boot.sh

CMD /bin/sh /bin/boot.sh