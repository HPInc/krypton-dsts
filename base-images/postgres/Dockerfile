# Start with the common Postgres image as our base image.
FROM postgres:17.5-alpine3.22
RUN apk update && apk upgrade

# Add the datastore.
ENV POSTGRES_USER=krypton
ENV POSTGRES_DB=kryptondb

# Add the contents of the SQL scripts directory to the image.
# All scripts in the docker-entrypoint-initdb.d directory are automatically
# executed when the container starts up.
COPY ./sql-scripts/initdb.sql /docker-entrypoint-initdb.d/

# Expose the Postgres port for the database.
EXPOSE 5432 5432
