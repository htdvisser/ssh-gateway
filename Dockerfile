FROM alpine:3.12

ADD ./dist/ssh-gateway-linux-amd64 /usr/local/bin/ssh-gateway
RUN chmod 755 /usr/local/bin/ssh-gateway

FROM alpine:3.12
RUN apk --update --no-cache add ca-certificates
COPY --from=0 /usr/local/bin/ssh-gateway /usr/local/bin/ssh-gateway
ENTRYPOINT ["/usr/local/bin/ssh-gateway"]
