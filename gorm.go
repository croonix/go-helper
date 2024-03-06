package helper

import (
	"context"
	"fmt"
	"log"
	"os"
	"reflect"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// GormDatabase is a function that returns a GORM database connection
// - Use simple Structure to connect to the database
// - Use the following environment variables:
//   - DATABASE_USER
//   - DATABASE_PASS
//   - DATABASE_IP
//
// Works only with MySQL databases (for now)
func GormDatabase(databaseName string) *gorm.DB {
	var (
		databaseUser     = os.Getenv("DATABASE_USER")
		databasePassword = os.Getenv("DATABASE_PASS")
		databaseIP       = os.Getenv("DATABASE_IP")
		databasePort     = "3306"
		dsn              = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true", databaseUser, databasePassword, databaseIP, databasePort, databaseName)
	)

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Printf(" * ERROR: %v\n", err)
	}

	schema.RegisterSerializer("timestamp", TimestampSerializer{})
	schema.RegisterSerializer("json", schema.JSONSerializer{})
	return db
}

// TimestampSerializer is a custom serializer for GORM to handle timestamps values
type TimestampSerializer struct {
}

func (TimestampSerializer) Scan(ctx context.Context, field *schema.Field, dst reflect.Value, dbValue interface{}) (err error) {
	fieldValue := reflect.New(field.FieldType)
	if dbValue != nil {
		timestamppbValue := timestamppb.New(dbValue.(time.Time))
		fieldValue.Elem().Set(reflect.ValueOf(timestamppbValue))
	}

	field.ReflectValueOf(ctx, dst).Set(fieldValue.Elem())
	return
}

// Value implements serializer interface
func (TimestampSerializer) Value(ctx context.Context, field *schema.Field, dst reflect.Value, fieldValue interface{}) (interface{}, error) {
	return fieldValue.(*timestamppb.Timestamp).AsTime(), nil
}
