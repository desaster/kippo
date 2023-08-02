FROM alpine:3.15

VOLUME /app/data /app/log /app/dl /app/kippo.cfg

# Create a non-root user and switch to it
RUN adduser -D -H -g '' app
USER app

# Set the working directory in the container to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Switch back to root to install dependencies
USER root

RUN apk --update-cache add \
        python2 \
        mariadb-connector-c \
    # build-dependencies can be removed at the end to save space
    && apk --update-cache add --virtual build-dependencies \
        git \
        python2-dev \
        musl-dev \
        gcc \
        mariadb-connector-c-dev \
    # hack to make the MySQL-python build succeed
    && wget -q https://raw.githubusercontent.com/paulfitz/mysql-connector-c/8c058fab669d61a14ec23c714e09c8dfd3ec08cd/include/my_config.h -O /usr/include/mysql/my_config.h \
    && sed '/st_mysql_options options;/a unsigned int reconnect;' /usr/include/mysql/mysql.h -i.bkp \
    # pip doesn't seem to be available via apk
    && python -m ensurepip --upgrade \
    # basic kippo dependencies, including optional MySQL-python
    && pip install --no-cache-dir \
        zope.interface==5.5.2 \
        Twisted==15.1.0 \
        pycrypto==2.6.1 \
        pyasn1==0.5.0 \
        MySQL-python==1.2.5 \
    # dependencies for XMPP support, needs this ancient custom branch
    && pip install --no-cache-dir \
        git+https://github.com/ralphm/wokkel/@e0a70e4b5d03a2c1c911bb2bdf5c3ef717049707 \
        python-dateutil==2.8.2 \
    # clean up
    && apk del build-dependencies

# Switch back to the non-root user
USER app

# Make port 2222 available to the world outside thiscontainer
EXPOSE 2222

# Run twistd command when the container launches
CMD ["twistd", "-n", "-y", "kippo.tac", "--pidfile", "kippo.pid"]
