FROM golang:1.13.3

# get the actual repo
WORKDIR /go/src/github.com/panghostlin/Keys

ADD go.mod .
ADD go.sum .
RUN go mod download

ADD . /go/src/github.com/panghostlin/Keys

# build the project
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o panghostlin-keys

ENTRYPOINT ["./panghostlin-keys"]
EXPOSE 8011