package database

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDB struct {
	options     *options.ClientOptions
	client      *mongo.Client
	database    *mongo.Database
	Collections map[string]*mongo.Collection
}

func InitDB(uri string) (db MongoDB) {
	db.options = options.Client().ApplyURI(uri)
	return db
}

func (db *MongoDB) Connect(ctx context.Context) (err error) {
	db.client, err = mongo.Connect(ctx, db.options)
	db.Collections = make(map[string]*mongo.Collection)
	return
}

func (db *MongoDB) OpenDB(d string) {
	db.database = db.client.Database(d)
}

func (db *MongoDB) OpenCollection(c string) {
	db.Collections[c] = db.database.Collection(c)
}

func (db *MongoDB) FindDoc(c string, ctx context.Context, filter interface{}) bool {
	return db.Collections[c].FindOne(ctx, filter).Err() == nil
}

func (db *MongoDB) ReadDoc(c string, ctx context.Context, filter interface{}, target interface{}) {
	singleResult := db.Collections[c].FindOne(ctx, filter)
	if singleResult.Err() == nil {
		singleResult.Decode(target)
	}
}

func (db *MongoDB) WriteDoc(c string, ctx context.Context, doc interface{}) {
	db.Collections[c].InsertOne(ctx, doc)
}

func (db *MongoDB) UpdateDoc(c string, ctx context.Context, filter interface{}, doc interface{}) bool {
	_, err := db.Collections[c].UpdateOne(ctx, filter, bson.M{"$set": doc})
	return err == nil
}
