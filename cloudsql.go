package helper

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/go-sql-driver/mysql"
)

func ConnectCloudSQL(database string) *sql.DB {
	databaseSocket, err := connectTCPSocket(database)
	if err != nil {
		Logger(fmt.Sprint(" Something went wrong when trying to create a connection to the database: ", err), "critical")
		return nil
	}

	if databaseSocket == nil {
		Logger(" Something went wrong with the values that were passed to the database connection.", "critical")
		return nil
	}

	return databaseSocket
}

func connectTCPSocket(database string) (*sql.DB, error) {
	var (
		databaseUser     = MustGetenv("DATABASE_USER")
		databasePassword = MustGetenv("DATABASE_PASS")
		databaseIP       = MustGetenv("DATABASE_IP")
		databaseName     = MustGetenv("DATABASE_NAME")
		databaseProject  = MustGetenv("PROJECT_ID")
		databasePort     = "3306"
	)

	databaseURI := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true", databaseUser, databasePassword, databaseIP, databasePort, database)

	if databaseRootCert, ok := os.LookupEnv("DATABASE_ROOT_CERT"); ok {
		var (
			databaseCert    = MustGetenv("DATABASE_CERT")
			databaseCertKey = MustGetenv("DATABASE_CERT_KEY")
		)
		certificatePool := x509.NewCertPool()
		rootCertificate, err := os.ReadFile(databaseRootCert)
		if err != nil {
			Logger(fmt.Sprint(" Something went wrong when trying to read the root certificate: ", err), "critical")
			return nil, err
		}

		if ok := certificatePool.AppendCertsFromPEM(rootCertificate); !ok {
			Logger(fmt.Sprint(" Something went wrong when trying to append the root certificate to the pool: ", err), "critical")
			return nil, errors.New("unable to append root cert to pool")
		}

		clientCertificate, err := tls.LoadX509KeyPair(databaseCert, databaseCertKey)
		if err != nil {
			Logger(fmt.Sprint(" Something went wrong when trying to load the client certificate: ", err), "critical")
			return nil, err
		}

		// Issue with the connection and use the function in here:
		// https://github.com/golang/go/issues/40748
		mysql.RegisterTLSConfig("cloudsql", &tls.Config{
			RootCAs:            certificatePool,
			Certificates:       []tls.Certificate{clientCertificate},
			InsecureSkipVerify: true,
			ServerName:         databaseProject + ":" + databaseName,
			VerifyConnection: func(cs tls.ConnectionState) error {
				commonName := cs.PeerCertificates[0].Subject.CommonName
				if commonName != cs.ServerName {
					Logger(fmt.Sprintf(" Something went wrong when trying to verify the connection: invalid certificate name %q, expected %q", commonName, cs.ServerName), "critical")
					return fmt.Errorf(" Something went wrong when trying to verify the connection: invalid certificate name")
				}
				opts := x509.VerifyOptions{
					Roots:         certificatePool,
					Intermediates: x509.NewCertPool(),
				}
				for _, cert := range cs.PeerCertificates[1:] {
					opts.Intermediates.AddCert(cert)
				}
				_, err := cs.PeerCertificates[0].Verify(opts)
				return err
			},
		})
		databaseURI += "&tls=cloudsql"
	}

	databaseConnection, err := sql.Open("mysql", databaseURI)
	if err != nil {
		return nil, fmt.Errorf("sql.Open: %w", err)
	}

	configureConnectionPool(databaseConnection)

	return databaseConnection, nil
}

func configureConnectionPool(db *sql.DB) {
	db.SetMaxIdleConns(5)
	db.SetMaxOpenConns(7)
	db.SetConnMaxLifetime(1800 * time.Second)
}
