# Build a docker image for the Krypton PostgreSQL databases
The datastore is a PostgreSQL database used by Krypton services

## Build the docker image
To build the docker image, execute the following commands:

```
make all
```

This should create a docker image using PostgreSQL and will run the initialization scripts (SQL scripts) to create the required tables in the datastore. Optionally, the service that consumes the database can also initialize the required tables etc. in the database.

## Push image to ghcr
As pre-requisites, make sure that you have the following
- a PAT with package write permissions
- you are logged in to ghcr using `docker login https://ghcr.io` with username and PAT

To push image, do `make push`. This will tag the image appropriately and push to ghcr. Once a push is successful, you can check your images at the [docker registry in github](https://ghcr.io/hpinc/packages)


## Start the docker container
To startup the datastore, execute the following command:

```
docker run -d -p 5432:5432 --name dsts-db -e POSTGRES_PASSWORD=supersecret krypton-db
```

Replace `supersecret` above with the password you'd like to use for the datastore.


## Verify the datastore is initialized correctly
This section shows you how to verify the datastore was initialized correctly.

To start, use the following command to connect to container hosting the datastore:
```
docker exec -it dsts-db bash
```

This will start up a bash prompt within the container hosting the datastore. You can then connect to the datastore using the PostgreSQL client and verify that the datastore is correctly initialized.
```
psql dstsdb kryptonuser
```

When prompted, enter the PostgreSQL database password you've configured above while starting up the container. At the psql prompt, use the following commands to verify the datastore has been initialized as desired.

To see a list of tables in the datastore:
```
\d+
```

Eg. to see the schema of the devices table within the datastore:
```
\d devices;
select * from devices;
```
