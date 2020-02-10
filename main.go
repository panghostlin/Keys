/*******************************************************************************
** @Author:					Major Tom - Sacré Studio <Major>
** @Email:					sacrestudioparis@gmail.com
** @Date:					Monday 03 September 2018 - 18:13:51
** @Filename:				main.go
**
** @Last modified by:		Tbouder
** @Last modified time:		Monday 10 February 2020 - 11:22:52
*******************************************************************************/

package			main

import			"os"
import			"log"
import			"fmt"
import			"net"
import			"time"
import			"errors"
import			"runtime"
import			"io/ioutil"
import			"google.golang.org/grpc"
import			"google.golang.org/grpc/credentials"
import			"crypto/x509"
import			"crypto/tls"
import			"database/sql"
import			_ "github.com/lib/pq"
import			"github.com/shirou/gopsutil/mem"
import			"github.com/microgolang/logs"
import			"github.com/panghostlin/SDK/Keys"

var		crt = `/env/server.crt`
var		key = `/env/server.key`
var		caCert = `/env/ca.crt`
var		PGR *sql.DB

func	connectToPostgre() {
	username := os.Getenv("POSTGRE_USERNAME")
	password := os.Getenv("POSTGRE_PWD")
	host := os.Getenv("POSTGRE_URI")
	dbName := os.Getenv("POSTGRE_DB")
	connStr := "user=" + username + " password=" + password + " dbname=" + dbName + " host=" + host + " sslmode=disable"
	PGR, _ = sql.Open("postgres", connStr)

	PGR.Exec(`CREATE extension if not exists "uuid-ossp";`)
	PGR.Exec(`CREATE TABLE if not exists keys(
		ID uuid NOT NULL DEFAULT uuid_generate_v4(),
		MemberID uuid NOT NULL,
		
		PasswordArgon2Hash varchar NULL,
		PasswordArgon2IV varchar NULL,
		PasswordScryptHash varchar NULL,
		PasswordScryptIV varchar NULL,

		EncryptionSalt varchar NULL,

		PublicKey varchar NULL,
		PublicKeyIV varchar NULL,
		PrivateKey varchar NULL,
		PrivateKeyIV varchar NULL,
		PrivateKeySalt varchar NULL,

		CONSTRAINT keys_pk PRIMARY KEY (ID),
		CONSTRAINT keys_un UNIQUE (MemberID)
	);`)

	logs.Success(`Connected to DB - Localhost`)
}

type	server struct {keys.KeysServiceServer}
type	MemberSecure struct {
	Password			string //Symmetric encryption of the user password with the master key
	PasswordArgon2Hash	[]byte
	PasswordArgon2IV	[]byte
	PasswordScryptHash	[]byte
	PasswordScryptIV	[]byte
}
var (
	ErrInvalidBlockSize		= errors.New("invalid blocksize")
	ErrInvalidPKCS7Data		= errors.New("invalid PKCS7 data (empty or not padded)")
	ErrInvalidPKCS7Padding	= errors.New("invalid padding on input")
	ErrInvalidHash			= errors.New("the encoded hash is not in the correct format")
    ErrIncompatibleVersion	= errors.New("incompatible version of argon2")
)

func	ServeKeysInsecure() {
    lis, err := net.Listen(`tcp`, `:8011`)
    if err != nil {
		log.Fatalf("Failed to listen: %v", err)
    }

	srv := grpc.NewServer(grpc.MaxConcurrentStreams(16))
	keys.RegisterKeysServiceServer(srv, &server{})
	logs.Success(`Running on port: :8011`)
	if err := srv.Serve(lis); err != nil {
		logs.Error(err)
		log.Fatalf("failed to serve: %v", err)
	}
}
func	ServeKeys() {
	certificate, err := tls.LoadX509KeyPair(crt, key)
    if err != nil {
		//Invalid Keys, should load as insecure
		logs.Warning("could not load server key pair : " + err.Error())
		logs.Warning("Using insecure connection")
		ServeKeysInsecure()
    }

    // Create a certificate pool from the certificate authority
    certPool := x509.NewCertPool()
    ca, err := ioutil.ReadFile(caCert)
    if err != nil {
        log.Fatalf("could not read ca certificate: %s", err)
    }

    // Append the client certificates from the CA
    if ok := certPool.AppendCertsFromPEM(ca); !ok {
        log.Fatalf("failed to append client certs")
    }

    // Create the channel to listen on
    lis, err := net.Listen(`tcp`, `:8011`)
    if err != nil {
		log.Fatalf("Failed to listen: %v", err)
    }

    // Create the TLS credentials
    creds := credentials.NewTLS(&tls.Config{
    	ClientAuth:   tls.RequireAndVerifyClientCert,
    	Certificates: []tls.Certificate{certificate},
    	ClientCAs:    certPool,
	})

    // Create the gRPC server with the credentials
	srv := grpc.NewServer(
		grpc.Creds(creds),
		grpc.MaxConcurrentStreams(16),
	)
	keys.RegisterKeysServiceServer(srv, &server{})
	logs.Success(`Running on port: :8011`)
	if err := srv.Serve(lis); err != nil {
		logs.Error(err)
		log.Fatalf("failed to serve: %v", err)
	}
}

func PrintMemUsage() {
	v, _ := mem.VirtualMemory()
	fmt.Printf("Used: %v, Free:%v, UsedPercent:%f%%, GRoutines: %d\n",
		v.Used, v.Free, v.UsedPercent, runtime.NumGoroutine())
}

func loop() {
	for {
		time.Sleep(time.Second * 2)
		PrintMemUsage()
	}
}

func	main()	{
	go loop()
	connectToPostgre()
	ServeKeys()
}
