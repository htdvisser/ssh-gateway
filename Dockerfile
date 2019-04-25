FROM alpine:3.9
RUN apk --update --no-cache add ca-certificates
ADD ./dist/ssh-gateway-linux-amd64 /usr/local/bin/ssh-gateway
RUN chmod 755 /usr/local/bin/ssh-gateway
ENTRYPOINT ["/usr/local/bin/ssh-gateway"]
