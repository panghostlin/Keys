FROM golang:1.13.3

WORKDIR /go/src/github.com/panghostlin/Keys

ADD go.mod .
ADD go.sum .
RUN go mod download
ADD . /go/src/github.com/panghostlin/Keys

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o panghostlin-keys

ENTRYPOINT ["./panghostlin-keys"]
EXPOSE 8011