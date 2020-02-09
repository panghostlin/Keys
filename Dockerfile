FROM golang:1.13.3

# create ssh directory
RUN mkdir ~/.ssh
RUN touch ~/.ssh/known_hosts
RUN ssh-keyscan -t rsa github.com >> ~/.ssh/known_hosts && ssh-keyscan -t rsa gitlab.com >> ~/.ssh/known_hosts

# allow private repo pull
RUN git config --global url."https://oauth2:xWYT_NATskxdWtrzSy9E@gitlab.com/".insteadOf "https://gitlab.com/"

# get the actual repo
WORKDIR /go/src/gitlab.com/betterpiwigo/server/Keys/

ADD go.mod .
ADD go.sum .
RUN go mod download

ADD . /go/src/gitlab.com/betterpiwigo/server/Keys

# build the project
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o piwigo-keys

ENTRYPOINT ["./piwigo-keys"]
EXPOSE 8011 8090