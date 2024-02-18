package feishu

import (
	"errors"
	"github.com/go-resty/resty/v2"
	"go.uber.org/zap"
)

type (
	User struct {
		UnionID       string   `json:"union_id"`
		UserID        string   `json:"user_id"`
		OpenID        string   `json:"open_id"`
		Name          string   `json:"name"`
		EnName        string   `json:"en_name"`
		Email         string   `json:"email"`
		Mobile        string   `json:"mobile"`
		Avatar        Avatar   `json:"avatar"`
		Status        Status   `json:"status"`
		DepartmentIds []string `json:"department_ids"`
	}

	Status struct {
		IsFrozen    bool `json:"is_frozen"`
		IsResigned  bool `json:"is_resigned"`
		IsActivated bool `json:"is_activated"`
	}

	UserInfoResp struct {
		Code int          `json:"code"`
		Msg  string       `json:"msg"`
		Data UserInfoData `json:"data"`
	}

	UserInfoData struct {
		User User `json:"user"`
	}

	Avatar struct {
		Avatar72     string `json:"avatar_72"`
		Avatar240    string `json:"avatar_240"`
		Avatar640    string `json:"avatar_640"`
		AvatarOrigin string `json:"avatar_origin"`
	}

	// AuthIdentityResponse 飞书授权用户信息返回结构
	AuthIdentityResponse struct {
		Code int          `json:"code"`
		Msg  string       `json:"msg"`
		Data AuthIdentity `json:"data"`
	}

	// AuthIdentity 飞书授权用户信息
	AuthIdentity struct {
		AccessToken      string `json:"access_token"`
		AvatarURL        string `json:"avatar_url"`
		AvatarThumb      string `json:"avatar_thumb"`
		AvatarMiddle     string `json:"avatar_middle"`
		AvatarBig        string `json:"avatar_big"`
		ExpiresIn        int    `json:"expires_in"`
		Name             string `json:"name"`
		EnName           string `json:"en_name"`
		OpenID           string `json:"open_id"`
		UnionID          string `json:"union_id"`
		Email            string `json:"email"`
		UserID           string `json:"user_id"`
		Mobile           string `json:"mobile"`
		TenantKey        string `json:"tenant_key"`
		RefreshExpiresIn int    `json:"refresh_expires_in"`
		RefreshToken     string `json:"refresh_token"`
		TokenType        string `json:"token_type"`
	}

	BatchGetIDResp struct {
		Code int            `json:"code"`
		Msg  string         `json:"msg"`
		Data BatchGetIDData `json:"data"`
	}

	BatchGetIDData struct {
		MobileUsers     map[string][]OpenIDAndUserID `json:"mobile_users"`
		MobilesNotExist []string                     `json:"mobiles_not_exist"`
		EmailUsers      map[string][]OpenIDAndUserID `json:"email_users"`
		EmailsNotExist  []string                     `json:"emails_not_exist"`
	}

	OpenIDAndUserID struct {
		OpenID string `json:"open_id"`
		UserID string `json:"user_id"`
	}

	getAuthIdentityParams struct {
		GrantType string `json:"grant_type"`
		Code      string `json:"code"`
	}
)

// GetUserInfoByUserID 通过user_id获取单个用户信息
func (m *Manager) GetUserInfoByUserID(userID string) (*User, error) {
	token, err := m.getAppToken()
	if err != nil {
		return nil, err
	}

	rs := &UserInfoResp{}
	client := resty.New()
	_, err = client.R().SetHeader("Content-Type", "application/json; charset=utf-8").
		SetAuthToken(token).
		SetQueryParams(map[string]string{"user_id_type": "user_id"}).
		SetResult(rs).Get(userInfo + userID)

	if err != nil {
		m.logger.Error("failed to get user info", zap.Error(err))
		return nil, err
	}

	if rs.Code != 0 {
		return nil, errors.New(rs.Msg)
	}

	return &rs.Data.User, nil
}

// GetUserIDByMobile 使用手机号获取用户ID
// 需要开通权限1：通过手机号或邮箱获取用户 ID 2：获取用户 user ID
func (m *Manager) GetUserIDByMobile(mobile string) (string, error) {
	token, err := m.getAppToken()
	if err != nil {
		return "", err
	}

	rs := &BatchGetIDResp{}
	client := resty.New()
	_, err = client.R().SetHeader("Content-Type", "application/json; charset=utf-8").
		SetAuthToken(token).
		SetQueryParams(map[string]string{"mobiles": mobile}).
		SetResult(rs).Get(batchGetID)

	if err != nil {
		m.logger.Error("failed to get user ID", zap.Error(err))
		return "", err
	}

	if rs.Code != 0 {
		return "", errors.New(rs.Msg)
	}

	ids, ok := rs.Data.MobileUsers[mobile]
	if !ok {
		return "", nil
	}

	return ids[0].UserID, nil
}

// GetUserAuthIdentity 通过飞书授权码获取用户授权信息
// code 飞书授权码
func (m *Manager) GetUserAuthIdentity(code string) (*AuthIdentity, error) {
	token, err := m.getAppToken()
	if err != nil {
		return nil, err
	}

	rs := &AuthIdentityResponse{}
	client := resty.New()
	_, err = client.R().SetHeader("Content-Type", "application/json; charset=utf-8").
		SetAuthToken(token).
		SetBody(getAuthIdentityParams{GrantType: "authorization_code", Code: code}).
		SetResult(rs).Post(userAuthIdentityAPI)

	if err != nil {
		m.logger.Error("failed to get user auth identity", zap.Error(err))
		return nil, err
	}

	if rs.Code == 0 {
		return &rs.Data, err
	}

	return nil, errors.New(rs.Msg)
}
