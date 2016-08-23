package db

import (
	"log"
	"time"

	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// Mongo for save scan result
type Mongo struct {
	URI        string
	DB         string
	Collection string
}

// NewMongo create a mongo db
func NewMongo(uri, db, collection string) *Mongo {
	return &Mongo{
		URI:        uri,
		DB:         db,
		Collection: collection,
	}
}

// Output save scan result in mongo db
func (m *Mongo) Output(result map[string]interface{}) {
	session, err := mgo.DialWithTimeout(m.URI, time.Second*10)
	if err != nil {
		log.Printf("Fail to connect mongo: %s", err.Error())
		return
	}
	defer session.Close()

	c := session.DB(m.DB).C(m.Collection)

	result["updateTime"] = time.Now().Format("2006-01-02 15:04:05")

	c.Upsert(bson.M{"domain": result["domain"]}, result)
}
