package model

type ClientDetails struct {
	//客户端ID
	ClientId string
	//客户端秘钥
	ClientSecret string
	//访问令牌的有效时间，秒
	AccessTokenValiditySeconds int
	//刷新令牌的有效时间，秒
	RefreshTokenValiditySeconds int
	//重定向地址，授权码类型中使用
	RegisteredRedirectUri string
	//可以使用的授权类型
	AuthorizedGrantTypes []string
}
