#!/bin/sh
REDIS_CMD="/usr/local/bin/redis-server"
REDIS_CONFIG="/usr/local/etc/redis/redis.conf"

# Update the Redis password in its configuration file. The Redis password is
# sourced from the CACHE_PASSWORD environment variable. This variable
# may be set when launching the container or if the service launcher is used, it
# is set by the service launcher after getting the required secret.
sed -i s/REDIS_PASSWORD/"$CACHE_PASSWORD"/g /usr/local/etc/redis/redis.conf

# Launch the Redis cache.
"$REDIS_CMD" "$REDIS_CONFIG"
