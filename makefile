################################################################################
## @Author:					Thomas Bouder <Tbouder>
## @Email:					Tbouder@protonmail.com
## @Date:					Sunday 05 January 2020 - 19:54:37
## @Filename:				makefile
##
## @Last modified by:		Tbouder
## @Last modified time:		Sunday 05 January 2020 - 19:55:03
################################################################################

SERVICE=Keys
SERVICE_PACKAGE=keys

all: build

build:
	docker build -t panghostlin__grpc__${SERVICE_PACKAGE} .

re: clear
	docker build -t panghostlin__grpc__${SERVICE_PACKAGE} .

run:
	docker run panghostlin__grpc__${SERVICE_PACKAGE}

clear:
	docker image remove --force panghostlin__grpc__${SERVICE_PACKAGE}

fullclear: clear
	rm -rf .env
