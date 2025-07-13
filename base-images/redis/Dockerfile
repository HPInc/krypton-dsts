FROM redis:8.0.2-alpine3.21
RUN apk update && apk upgrade

VOLUME /var/lib/redis/
EXPOSE 6379

# In production environments, the actual cache password and is fetched from
# secret manager.
ENV CACHE_PASSWORD=changeme

COPY . /krypton

# Copy a modified redis.conf file with the bind directive configured to
# allow us to connect to the container externally.
COPY redis.conf /usr/local/etc/redis/redis.conf

WORKDIR /krypton
RUN chmod +x /krypton/*.sh

CMD [ "/krypton/start_redis.sh"]
