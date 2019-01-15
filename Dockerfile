FROM php:5.6-cli

MAINTAINER Jack Skinner

RUN apt-get update
RUN apt-get install -y python-pip
RUN pip install -U pip
RUN pip install pywatch
RUN curl -sS https://getcomposer.org/installer | php \
  && chmod +x composer.phar && mv composer.phar /usr/local/bin/composer
RUN apt-get install -y git unzip

WORKDIR /opt

# ENTRYPOINT ["sh"]


