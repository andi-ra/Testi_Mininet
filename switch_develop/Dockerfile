FROM alpine:3.3

RUN apk update

RUN apk add openvswitch nano tcpdump openssh && rm -rf /var/cache/apk/*

RUN ssh-keygen -A \
    && mkdir /root/.ssh \
    && chmod 0700 /root/.ssh \
    && echo "root:root" | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
EXPOSE 22
VOLUME ["/etc/openvswitch/", "~/.ssh"]

ADD boot.sh /bin/boot.sh

CMD /bin/sh /bin/boot.sh