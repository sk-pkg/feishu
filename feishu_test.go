package feishu

import (
	"fmt"
	"testing"
)

func newFeishu() (*Manager, error) {
	logCfg := &LogConfig{Driver: "std"}
	redisCfg := &RedisConfig{Host: "127.0.0.1:6379", Prefix: ""}

	return New(
		WithLogConfig(logCfg),
		WithRedisConfig(redisCfg),
		WithAppID(""),
		WithAppSecret(""),
		WithGroupWebhook("https://open.feishu.cn/open-apis/bot/v2/hook/xxx"),
	)
}

func TestManager_GetUserIDByMobile(t *testing.T) {
	f, err := newFeishu()
	if err != nil {
		t.Error(err)
	}

	userId, err := f.GetUserIDByMobile("18888888888")
	if err != nil {
		t.Error(err)
	}

	if userId == "" {
		t.Error("user id is null")
	}

	fmt.Println(userId)
}

func TestManager_SendMsg(t *testing.T) {
	f, err := newFeishu()
	if err != nil {
		t.Error(err)
	}

	err = f.SendMsg("user_id", "text", "Hello World!")
	if err != nil {
		t.Error(err)
	}
}
