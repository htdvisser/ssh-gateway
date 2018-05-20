FROM alpine:3.7
ADD ./dist/ssh-gateway-linux-amd64 /usr/local/bin/ssh-gateway
RUN chmod 755 /usr/local/bin/ssh-gateway
ENTRYPOINT ["/usr/local/bin/ssh-gateway"]
