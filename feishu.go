package feishu

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/sk-pkg/logger"
	"github.com/sk-pkg/redis"
	"go.uber.org/zap"
	"strings"
	"time"
)

const (
	appAccessTokenAPI   = "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal/"
	userAuthIdentityAPI = "https://open.feishu.cn/open-apis/authen/v1/access_token"
	batchGetID          = "https://open.feishu.cn/open-apis/user/v1/batch_get_id"
	userInfo            = "https://open.feishu.cn/open-apis/contact/v3/users/"
	tokenKey            = "feishu:app:token"
	messageAPI          = "https://open.feishu.cn/open-apis/im/v1/messages"
)

type (
	Option func(*option)

	option struct {
		redis        *redis.Manager
		logger       *zap.Logger
		groupWebhook string
		appID        string
		appSecret    string
		encryptKey   string
		logConfig    *LogConfig
		redisConfig  *RedisConfig
	}

	Manager struct {
		redis        *redis.Manager
		logger       *zap.Logger
		groupWebhook string
		appID        string
		appSecret    string
		encryptKey   string
	}

	RedisConfig struct {
		Host        string        `json:"host"`         // HOST
		Auth        string        `json:"auth"`         // 授权
		MaxIdle     int           `json:"max_idle"`     // 最大空闲连接数
		MaxActive   int           `json:"max_active"`   // 一个pool所能分配的最大的连接数目
		IdleTimeout time.Duration `json:"idle_timeout"` // 空闲连接超时时间，超过超时时间的空闲连接会被关闭（单位：分钟）
		Prefix      string        `json:"prefix"`       // 前缀
		DB          int           `json:"db"`
	}

	LogConfig struct {
		Driver  string `json:"driver"` // 日志驱动 stdout, file
		Level   string `json:"level"`  // 日志级别 debug,info,warn,error,fatal
		LogPath string `json:"path"`   // 日志路径，仅当Driver为file时生效
	}

	getAppTokenParams struct {
		AppID     string `json:"app_id"`
		AppSecret string `json:"app_secret"`
	}

	appTokenResp struct {
		Code           int    `json:"code"`
		Msg            string `json:"msg"`
		AppAccessToken string `json:"app_access_token"`
		Expire         int    `json:"expire"`
	}

	Subscribe struct {
		Schema string          `json:"schema"`
		Header SubscribeHeader `json:"header"`
		Event  SubscribeEvent  `json:"event"`
	}

	SubscribeHeader struct {
		EventId    string `json:"event_id"`
		EventType  string `json:"event_type"`
		CreateTime string `json:"create_time"`
		Token      string `json:"token"`
		AppId      string `json:"app_id"`
		TenantKey  string `json:"tenant_key"`
	}

	SubscribeEvent struct {
		Object struct {
			OpenId string `json:"open_id"`
		}
	}

	SubscribeValidate struct {
		Encrypt string `json:"encrypt"`
	}

	Result struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
)

func WithRedisConfig(cfg *RedisConfig) Option {
	return func(o *option) {
		o.redisConfig = cfg
	}
}

func WithLogConfig(cfg *LogConfig) Option {
	return func(o *option) {
		o.logConfig = cfg
	}
}

func WithRedis(redis *redis.Manager) Option {
	return func(o *option) {
		o.redis = redis
	}
}

func WithLog(logger *zap.Logger) Option {
	return func(o *option) {
		o.logger = logger
	}
}

func WithAppID(appID string) Option {
	return func(o *option) {
		o.appID = appID
	}
}

func WithAppSecret(appSecret string) Option {
	return func(o *option) {
		o.appSecret = appSecret
	}
}

func WithGroupWebhook(groupWebhook string) Option {
	return func(o *option) {
		o.groupWebhook = groupWebhook
	}
}

func WithEncryptKey(encryptKey string) Option {
	return func(o *option) {
		o.encryptKey = encryptKey
	}
}

func New(opts ...Option) (*Manager, error) {
	opt := &option{}

	for _, f := range opts {
		f(opt)
	}

	if opt.logger == nil {
		if opt.logConfig != nil {
			l, err := logger.New(
				logger.WithLevel(opt.logConfig.Level),
				logger.WithDriver(opt.logConfig.Driver),
				logger.WithLogPath(opt.logConfig.LogPath),
			)
			if err != nil {
				return nil, err
			}

			opt.logger = l
		} else {
			return nil, errors.New("Logger Can't be Null ")
		}
	}

	if opt.redis == nil {
		if opt.redisConfig != nil {
			opt.redis = redis.New(
				redis.WithPrefix(opt.redisConfig.Prefix),
				redis.WithAddress(opt.redisConfig.Host),
				redis.WithPassword(opt.redisConfig.Auth),
				redis.WithIdleTimeout(opt.redisConfig.IdleTimeout*time.Minute),
				redis.WithMaxActive(opt.redisConfig.MaxActive),
				redis.WithMaxIdle(opt.redisConfig.MaxIdle),
				redis.WithDB(opt.redisConfig.DB),
			)
		} else {
			return nil, errors.New("Redis Can't be Null ")
		}
	}

	return &Manager{
		redis:        opt.redis,
		logger:       opt.logger,
		groupWebhook: opt.groupWebhook,
		appID:        opt.appID,
		appSecret:    opt.appSecret,
		encryptKey:   opt.encryptKey,
	}, nil
}

// getAppToken 获取飞书 app_access_token（企业自建应用）
func (m *Manager) getAppToken() (string, error) {
	token, err := m.redis.GetString(tokenKey)
	if err != nil || token == "" {
		rs := &appTokenResp{}
		client := resty.New()
		_, err = client.R().
			SetBody(getAppTokenParams{AppID: m.appID, AppSecret: m.appSecret}).
			SetResult(rs).Post(appAccessTokenAPI)

		if err == nil && rs.Code == 0 {
			token = rs.AppAccessToken
			err = m.redis.SetString(tokenKey, token, rs.Expire-100)
			if err != nil {
				m.logger.Error("failed to set feishu app access token", zap.Error(err))
			}
		} else {
			m.logger.Error("failed to get feishu app access token", zap.Error(err))
			return token, errors.New(rs.Msg)
		}
	}

	return token, err
}

// SendMsg 给指定飞书用户发送消息
// feishuID 飞书user_id
// msgType 飞书消息类型，可选值有text（文本）、interactive（消息卡片）
// content 飞书消息内容
// TODO 支持发送其他类型消息
func (m *Manager) SendMsg(feishuID, msgType string, content any) error {
	var marshal []byte
	token, err := m.getAppToken()
	if err != nil {
		m.logger.Error("failed to get feishu token", zap.Error(err))
		return err
	}

	params := map[string]string{"receive_id": feishuID, "msg_type": msgType}

	switch msgType {
	case "text":
		marshal, _ = json.Marshal(map[string]any{"text": content})
	case "interactive":
		marshal, _ = json.Marshal(content)
	}

	params["content"] = string(marshal)

	rs := &Result{}
	client := resty.New()
	_, err = client.R().SetHeader("Content-Type", "application/json; charset=utf-8").
		SetAuthToken(token).
		SetQueryParams(map[string]string{"receive_id_type": "user_id"}).
		SetBody(&params).SetResult(&rs).
		SetError(&rs).Post(messageAPI)

	if err != nil {
		m.logger.Error("failed to post send feishu message", zap.Error(err))
		return err
	}

	if rs.Code != 0 {
		m.logger.Error("failed to send feishu message", zap.String("msg", rs.Msg), zap.Any("params", params))
		return errors.New(rs.Msg)
	}

	return nil
}

// EventCalculateSignature
// @title   事件安全验证
// @param   timestamp (时间戳) | nonce (随机值) | bodyString (请求体)
// @return  string  (生成的加密字符串)
func (m *Manager) EventCalculateSignature(timestamp, nonce, bodyString string) string {
	var b strings.Builder
	b.WriteString(timestamp)
	b.WriteString(nonce)
	b.WriteString(m.encryptKey)
	b.WriteString(bodyString)
	bs := []byte(b.String())
	h := sha256.New()
	h.Write(bs)
	bs = h.Sum(nil)
	sig := fmt.Sprintf("%x", bs)

	return sig
}

// EventDecrypt
// @title   事件请求参数解密
// @param   encrypt (请求参数)
// @return  string  (解密的数据)
func (m *Manager) EventDecrypt(encrypt string) (string, error) {
	buf, err := base64.StdEncoding.DecodeString(encrypt)
	if err != nil {
		return "", fmt.Errorf("base64StdEncode Error[%v]", err)
	}
	if len(buf) < aes.BlockSize {
		return "", errors.New("cipher  too short")
	}

	keyBs := sha256.Sum256([]byte(m.encryptKey))
	block, err := aes.NewCipher(keyBs[:sha256.Size])
	if err != nil {
		return "", fmt.Errorf("AESNewCipher Error[%v]", err)
	}

	iv := buf[:aes.BlockSize]
	buf = buf[aes.BlockSize:]
	// CBC mode always works in whole blocks.
	if len(buf)%aes.BlockSize != 0 {
		return "", errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(buf, buf)
	n := strings.Index(string(buf), "{")
	if n == -1 {
		n = 0
	}

	sl := strings.LastIndex(string(buf), "}")
	if sl == -1 {
		sl = len(buf) - 1
	}

	return string(buf[n : sl+1]), nil
}
