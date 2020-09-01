package basicredis

import (
	"encoding/json"
	"errors"
	stringutils "github.com/alessiosavi/GoGPUtils/string"
	"github.com/alessiosavi/StreamingServer/datastructures"
	"strings"
	"time"

	"github.com/go-redis/redis"
	log "github.com/sirupsen/logrus"
)

// ConnectToDb use emtpy string for hardcoded port
func ConnectToDb(addr string, port string, db int) (*redis.Client, error) {
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
		log.Errorf("Impossibile to connecto to DB ...| CLIENT: [%+v] | Addr: [%s] | Port: [%s] | ERR: [%s]", client, addr, port, err.Error())
		return nil, err
	}
	log.Infof("Succesfully connected to -> [%+v]", client)
	return client, nil
}

// GetValueFromDB is delegated to check if a key is alredy inserted and return the value in the dest variable in signature
func GetValueFromDB(client *redis.Client, key string, dest interface{}) error {
	tmp, err := client.Get(key).Result()
	if err == nil {
		if err = json.Unmarshal([]byte(tmp), dest); err != nil {
			log.Error("GetValueFromDB | Unable to unmarshal data from Redis: ", err)
			return err
		}
		log.Debugf("GetValueFromDB | SUCCESS | Key: "+key+" | Value: %+v", dest)
		return nil
	} else if err == redis.Nil {
		log.Warn("GetValueFromDB | Key -> " + key + " does not exist")
		return err
	}
	log.Errorf("GetValueFromDB | Fatal exception during retrieving of data [%s] | Redis: [%+v]", key, client)
	log.Error(err)
	return err
}

// RemoveValueFromDB is delegated to check if a key is alredy inserted and return the value
func RemoveValueFromDB(client *redis.Client, key string) error {
	err := client.Del(key).Err()
	if err == nil {
		log.Debugf("RemoveValueFromDB | SUCCESS | Key: [%s] | Removed", key)
		return nil
	} else if err == redis.Nil {
		log.Warnf("RemoveValueFromDB | Key -> [%s] does not exist", key)
		return err
	}
	log.Error("RemoveValueFromDB | Fatal exception during retrieving of data [", key, "] | Redis: ", client)
	log.Error(err)
	return err
}

// InsertTokenIntoDB set the two value into the Databased pointed from the client
func InsertTokenIntoDB(client *redis.Client, key string, value string, expire time.Duration) error {
	key = key + "_token"
	log.Infof("InsertTokenIntoDB | Inserting -> (%s:%s)", key, value)
	err := client.Set(key, value, expire).Err() // Inserting the values into the DB
	if err != nil {
		log.Error(err)
		return err
	}
	//log.Debug("InsertTokenIntoDB | Setting ", expire, " seconds as expire time")
	//err1 := client.Expire(key, expire)
	//if err1.Err() != nil {
	//	log.Error("Unable to set expiration time ... | Err: ", err1)
	//	return err
	//}
	log.Infof("InsertTokenIntoDB | INSERTED SUCCESFULLY!! | (%s:%s)", key, value)
	return nil
}

// GetTokenFromDB is delegated to retrieve the token from Redis
func GetTokenFromDB(client *redis.Client, key string) (string, error) {
	var err error
	var token string
	key = key + "_token"
	log.Info("GetTokenFromDB | Retrieving -> (", key, ")")
	if token, err = client.Get(key).Result(); err != nil {
		log.Error("GetTokenFromDB | Unable to retrieve the token for the key: [", key, "] | Err:", err)
		return "", err
	}
	log.Debugf("GetTokenFromDB | Token [%s] retrieved for the key [%s]", token, key)
	return token, nil

}

// InsertValueIntoDB is delegated to save a general structure into redis
func InsertValueIntoDB(client *redis.Client, key string, value interface{}) error {
	var data []byte
	var err error
	if data, err = json.Marshal(value); err != nil {
		log.Errorf("InsertValueIntoDB | Unable to marshall user [%+v] | Err: %s", value, err.Error())
		return err
	}
	return client.Set(key, data, 0).Err()
}

// InsertValueIntoDB is delegated to save a general structure into redis
func InsertUserIntoDB(client *redis.Client, key string, user datastructures.User) error {
	var data []byte
	var err error
	if stringutils.IsBlank(user.Username) {
		err = errors.New("username is empty")
		log.Error("InsertUserIntoDB | ", err)
		return err
	}
	if stringutils.IsBlank(user.Password) {
		err = errors.New("password is empty")
		log.Error("InsertUserIntoDB | ", err)
		return err
	}
	if data, err = json.Marshal(user); err != nil {
		log.Errorf("InsertValueIntoDB | Unable to marshall user [%+v] | Err: %s", user, err.Error())
		return err
	}
	return client.Set(key, data, 0).Err()
}
