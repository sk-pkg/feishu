package feishu

import (
	"fmt"
	"testing"
)

type (
	CardAccountList struct {
		Pin    string `json:"pin"`
		Remark string `json:"remark"`
		Status string `json:"status"`
	}
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

	content := &CardData{Type: "template"}
	content.Data.TemplateID = "template_id"

	list := []CardAccountList{
		{
			"pin1",
			"r1",
			"s1",
		},
		{
			"pin2",
			"r2",
			"s2",
		}, {
			"pin3",
			"r3",
			"s3",
		}, {
			"pin4",
			"r4",
			"s4",
		}, {
			"pin5",
			"r5",
			"s5",
		},
	}

	content.Data.TemplateVariable = map[string][]CardAccountList{"account_list": list}

	err = f.SendMsg("user_id", "interactive", content)
	if err != nil {
		t.Error(err)
	}
}

func TestManager_GetEventOutboundIpList(t *testing.T) {
	f, err := newFeishu()
	if err != nil {
		t.Error(err)
	}

	list, err := f.GetEventOutboundIpList()
	if err != nil {
		t.Error(err)
	}

	fmt.Println(list)
}
