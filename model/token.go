package model

import "time"

/**
一般来讲，OAth2Token会和OAuth2Details一一绑定，代表当前操作的用户和客户端
*/
type OAuth2Token struct {
	//刷新令牌
	RefreshToken *OAuth2Token
	//令牌类型
	TokenType string
	//令牌值
	TokenValue string
	//过期时间
	ExpiresTime *time.Time
}

func (oa *OAuth2Token) IsExpired() bool {
	return oa.ExpiresTime != nil && oa.ExpiresTime.Before(time.Now())
}

/**
令牌绑定的用户和客户端信息
*/
type OAuth2Details struct {
	Client *ClientDetails
	User   *UserDetails
}
