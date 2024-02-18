package feishu

import (
	"github.com/go-resty/resty/v2"
	"go.uber.org/zap"
)

type (
	GroupRobotResp struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
)

// SendGroupMsg 给指定飞书群发送消息
// msgType 飞书消息类型，可选值有interactive（消息卡片），image（图片），share_chat（群名片），post（富文本消息），text（文本消息）
// content 飞书消息内容
func (m *Manager) SendGroupMsg(msgType, content string) {
	params := make(map[string]interface{})
	params["msg_type"] = msgType

	switch msgType {
	case "text":
		params["content"] = map[string]string{"text": content}
	case "post":
		params["content"] = map[string]string{"post": content}
	case "share_chat":
		params["content"] = map[string]string{"share_chat_id": content}
	case "image":
		params["content"] = map[string]string{"image_key": content}
	case "interactive":
		params["card"] = map[string]string{"image_key": content}
	}

	rs := &GroupRobotResp{}
	client := resty.New()
	_, err := client.R().SetHeader("Content-Type", "application/json; charset=utf-8").
		SetBody(params).
		SetResult(rs).Post(m.groupWebhook)

	if err != nil {
		m.logger.Error("failed to get user auth identity", zap.Error(err))
	}

	if rs.Code != 0 {
		m.logger.Error("Send group robot message failed", zap.String("error", rs.Msg))
	}
}
