# Original credit: https://github.com/jpetazzo/dockvpn

# Smallest base image
FROM alpine:latest

LABEL maintainer="Kyle Manna <kyle@kylemanna.com>"

# Testing: pamtester
RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing/" >> /etc/apk/repositories && \
    apk add --update openvpn iptables bash easy-rsa openvpn-auth-pam google-authenticator pamtester libqrencode python3 py3-pip && \
    ln -s /usr/share/easy-rsa/easyrsa /usr/local/bin && \
    ln -sf python3 /usr/bin/python && \
    rm -rf /tmp/* /var/tmp/* /var/cache/apk/* /var/cache/distfiles/* && \
    python3 -m pip install --no-cache --upgrade pip setuptools Flask Flask-HTTPAuth gunicorn pyOpenSSL

# Needed by scripts
ENV OPENVPN=/etc/openvpn
ENV EASYRSA=/usr/share/easy-rsa \
    EASYRSA_CRL_DAYS=3650 \
    EASYRSA_PKI=$OPENVPN/pki
ENV WEB_SECRET_TOKEN=example_web_secret

VOLUME ["/etc/openvpn"]

# Internally uses port 1194/udp, remap using `docker run -p 443:1194/tcp`
EXPOSE 1194/udp
EXPOSE 8000

CMD ["ovpn_run_with_api"]

ADD ./bin /usr/local/bin
RUN chmod a+x /usr/local/bin/*

# Add support for OTP authentication using a PAM module
ADD ./otp/openvpn /etc/pam.d/
