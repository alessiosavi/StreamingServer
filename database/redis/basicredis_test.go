package basicredis

import (
	"github.com/alessiosavi/StreamingServer/datastructures"
	"github.com/go-redis/redis"
	"testing"
	"time"
)

func TestConnectToDb(t *testing.T) {
	var err error
	var client *redis.Client
	if client, err = ConnectToDb("localhost", "6379", 0); err != nil {
		t.Error("Unable to connect to the localhost instance")
	}
	if client != nil {
		client.Close()
	}
	if client, err = ConnectToDb("localhost", "6378", 0); err == nil {
		t.Error("Expected an error!")
	}
	if client != nil {
		client.Close()
	}
}

func TestGetTokenFromDB(t *testing.T) {
	var client *redis.Client
	var err error

	if client, err = ConnectToDb("localhost", "6379", 0); err != nil {
		t.Error("Unable to connect to Redis instance!")
		return
	}
	defer client.Close()

	if err = client.Set("key_test1_token", "value_test1", 0).Err(); err != nil {
		t.Error("Unable to insert dummy value into Redis")
		return
	}

	type args struct {
		client *redis.Client
		key    string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "ok1",
			args: args{
				client: client,
				key:    "key_test1",
			},
			want:    "value_test1",
			wantErr: false,
		},
		{
			name: "ko1",
			args: args{
				client: client,
				key:    "key_test2",
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetTokenFromDB(tt.args.client, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetTokenFromDB() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetTokenFromDB() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetValueFromDB(t *testing.T) {
	var client *redis.Client
	var err error
	if client, err = ConnectToDb("localhost", "6379", 0); err != nil {
		t.Error("Unable to connect to Redis instance!")
		return
	}
	user := datastructures.User{
		Username: "username_test",
		Password: "password_test",
		Email:    "email_test",
		Active:   false,
	}

	if err = InsertValueIntoDB(client, user.Username, user); err != nil {
		t.Error("Unable to insert a dummy user | Err: " + err.Error())
		return
	}
	defer client.Close()
	user = datastructures.User{}
	type args struct {
		client *redis.Client
		key    string
		dest   interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ok1",
			args: args{
				client: client,
				key:    "username_test",
				dest:   &user,
			},
			wantErr: false,
		},
		{
			name: "test_ko",
			args: args{
				client: client,
				key:    "not_exists",
				dest:   nil,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := GetValueFromDB(tt.args.client, tt.args.key, tt.args.dest); (err != nil) != tt.wantErr {
				t.Errorf("GetValueFromDB() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestInsertTokenIntoDB(t *testing.T) {
	var client *redis.Client
	var err error
	if client, err = ConnectToDb("localhost", "6379", 0); err != nil {
		t.Error("Unable to connect to Redis instance!")
		return
	}
	defer client.Close()
	type args struct {
		client *redis.Client
		key    string
		value  string
		expire time.Duration
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "test_ok1",
			args: args{
				client: client,
				key:    "test",
				value:  "test_value",
				expire: 0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := InsertTokenIntoDB(tt.args.client, tt.args.key, tt.args.value, tt.args.expire); (err != nil) != tt.wantErr {
				t.Errorf("InsertTokenIntoDB() error = %v, wantErr %v", err, tt.wantErr)
			} else {
				k := tt.args.key + "_token"
				if result, err := client.Get(k).Result(); err == nil {
					if result != tt.args.value {
						t.Errorf("InsertTokenIntoDB() value = %s, wantValue %s", result, tt.args.value)
					}
				} else {
					t.Error("Unable to retrieve the data for the key: " + k)
				}
			}
		})
	}
}

//func TestInsertValueIntoDB(t *testing.T) {
//	type args struct {
//		client *redis.Client
//		key    string
//		value  interface{}
//	}
//	tests := []struct {
//		name    string
//		args    args
//		wantErr bool
//	}{
//		// TODO: Add test cases.
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			if err := InsertValueIntoDB(tt.args.client, tt.args.key, tt.args.value); (err != nil) != tt.wantErr {
//				t.Errorf("InsertValueIntoDB() error = %v, wantErr %v", err, tt.wantErr)
//			}
//		})
//	}
//}
//
//func TestRemoveValueFromDB(t *testing.T) {
//	type args struct {
//		client *redis.Client
//		key    string
//	}
//	tests := []struct {
//		name    string
//		args    args
//		wantErr bool
//	}{
//		// TODO: Add test cases.
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			if err := RemoveValueFromDB(tt.args.client, tt.args.key); (err != nil) != tt.wantErr {
//				t.Errorf("RemoveValueFromDB() error = %v, wantErr %v", err, tt.wantErr)
//			}
//		})
//	}
//}
