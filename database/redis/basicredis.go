package basicredis

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/go-redis/redis"
	log "github.com/sirupsen/logrus"
)

// ConnectToDb use emtpy string for hardcoded port
func ConnectToDb(addr string, port string, db int) *redis.Client {
	// Empty addr and port for default connection
	if strings.Compare(addr, port) == 0 {
		addr = "localhost"
		port = "6379"
	}
	client := redis.NewClient(&redis.Options{
		Addr:     addr + ":" + port,
		Password: "", // no password set
		DB:       db,
	})
	log.Info("Connecting to -> ", client)
	err := client.Ping().Err()
	if err != nil {
		log.Error("Impossibile to connecto to DB ...| CLIENT: ", addr, ":", port, " | ERR: ", err)
		return nil
	}
	log.Info("Succesfully connected to -> ", client)
	return client
}

// GetValueFromDB is delegated to check if a key is alredy inserted and return the value in the dest variable in signature
func GetValueFromDB(client *redis.Client, key string, dest interface{}) error {
	tmp, err := client.Get(key).Result()
	if err == nil {
		if err = json.Unmarshal([]byte(tmp), dest); err != nil {
			log.Error("GetValueFromDB | Unable to unmarshal data from Redis: ", err)
			return err
		}
		log.Debug("GetValueFromDB | SUCCESS | Key: ", key, " | Value: ", dest)
		return nil
	} else if err == redis.Nil {
		log.Warn("GetValueFromDB | Key -> ", key, " does not exist")
		return err
	}
	log.Error("GetValueFromDB | Fatal exception during retrieving of data [", key, "] | Redis: ", client)
	log.Error(err)
	return err
}

// RemoveValueFromDB is delegated to check if a key is alredy inserted and return the value
func RemoveValueFromDB(client *redis.Client, key string) error {
	err := client.Del(key).Err()
	if err == nil {
		log.Debug("RemoveValueFromDB | SUCCESS | Key: ", key, " | Removed")
		return nil
	} else if err == redis.Nil {
		log.Warn("RemoveValueFromDB | Key -> ", key, " does not exist")
		return err
	}
	log.Error("RemoveValueFromDB | Fatal exception during retrieving of data [", key, "] | Redis: ", client)
	log.Error(err)
	return err
}

// InsertTokenFromDB set the two value into the Databased pointed from the client
func InsertTokenFromDB(client *redis.Client, key string, value string, expire int) error {
	key = key + "_token"
	log.Info("InsertIntoClient | Inserting -> (", key, ":", value, ")")
	err := client.Set(key, value, 0).Err() // Inserting the values into the DB
	if err != nil {
		log.Error(err)
		return err
	}
	duration := time.Second * time.Duration(expire)
	log.Debug("InsertIntoClient | Setting ", expire, " seconds as expire time | Duration: ", duration)
	err1 := client.Expire(key, duration)
	if err1.Err() != nil {
		log.Error("Unable to set expiration time ... | Err: ", err1)
		return err
	}
	log.Info("InsertIntoClient | INSERTED SUCCESFULLY!! | (", key, ":", value, ")")
	return nil
}

// GetTokenFromDB is delegated to retrieve the token from Redis
func GetTokenFromDB(client *redis.Client, key string) (string, error) {
	var err error
	var token string
	key = key + "_token"
	log.Info("InsertIntoClient | Retrieving -> (", key, ")")
	if token, err = client.Get(key).Result(); err != nil {
		log.Error("GetTokenFromDB | Unable to retrieve the token for the key: [", key, "] | Err:", err)
		return "", err
	}
	log.Debug("GetTokenFromDB | Token [", token, "] retrieved for the key [", key, "]")
	return token, nil

}

// InsertValueIntoDB is delegated to save a general structure into redis
func InsertValueIntoDB(client *redis.Client, key string, value interface{}) error {
	p, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return client.Set(key, p, 0).Err()
}
