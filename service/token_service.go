package service

import (
	"context"
	"errors"
	uuid "github.com/satori/go.uuid"
	"net/http"
	. "security/model"
	"strconv"
	"time"
)

/**
令牌生成器
*/

var (
	ErrNotSupportGrantType               = errors.New("grant type is not supported")
	ErrInvalidUsernameAndPasswordRequest = errors.New("invalid username,password")
	ErrInvalidTokenRequest               = errors.New("invalid token")
	ErrExpiredToken                      = errors.New("token is expired")
)

//令牌生成器
//根据授权类型使用不同的方式对用户和客户端信息进行认真，认证成功后生成并返回访问令牌

type TokenGrant interface {
	Grant(ctx context.Context, grantType string, client *ClientDetails, r *http.Request) (*OAuth2Token, error)
}

/*
组成token字典
注意：使用组合模式，使得不同的授权类型使用不同的tokenGrant接口实现结构体来生成访问令牌
组合节点ComposeTokenGranter
*/
type ComposeTokenGranter struct {
	TokenGrantDict map[string]TokenGrant
}

func (c *ComposeTokenGranter) Grant(ctx context.Context, grantType string, client *ClientDetails, r *http.Request) (*OAuth2Token, error) {
	//根据grantType从map中获取对应的TokenGrant接口实现结构体，然后使用其验证客户端和用户凭证，并生成访问令牌返回
	dispatchGranter := c.TokenGrantDict[grantType]
	if dispatchGranter == nil {
		return nil, ErrNotSupportGrantType
	}
	return dispatchGranter.Grant(ctx, grantType, client, r)
}

func NewComposeTokenGranter(tokenGrantDict map[string]TokenGrant) TokenGrant {
	return &ComposeTokenGranter{
		TokenGrantDict: tokenGrantDict,
	}
}

/*使用户名和密码生成令牌授权*/
type UsernamePasswordTokenGranter struct {
	supportGrantType   string
	userDetailsService UserDetailsService
	tokenService       TokenService
}

func (upg UsernamePasswordTokenGranter) Grant(ctx context.Context, grantType string, client *ClientDetails, r *http.Request) (*OAuth2Token, error) {
	if grantType != upg.supportGrantType {
		return nil, ErrNotSupportGrantType
	}
	//从请求体中获取用户名和密码
	username := r.FormValue("username")
	passwrod := r.FormValue("password")

	if username == "" || passwrod == "" {
		return nil, ErrInvalidUsernameAndPasswordRequest
	}

	//验证用户名密码是否正确
	userDetails, err := upg.userDetailsService.GetUserDetailByUserName(ctx, username, passwrod)
	if err != nil {
		return nil, err
	}
	//根据用户信息和客户端信息生成访问令牌
	return upg.tokenService.CreateAccessToken(&OAuth2Details{
		Client: client,
		User:   userDetails,
	})
}

/**
令牌服务
用于令牌的管理，
*/
type TokenService interface {

	//根据访问令牌获取对应的用户信息和客户端信息
	GetOAuth2DetailsByAccessToken(tokenValue string) (*OAuth2Details, error)
	//根据用户信息和客户端信息生成访问令牌
	CreateAccessToken(oauth2Details *OAuth2Details) (*OAuth2Token, error)
	//根据刷新令牌获取访问令牌
	RefreshAccessToken(refreshTokenValue string) (*OAuth2Token, error)
	//根据用户信息和客户端信息获取访问令牌
	GetAccessToken(details *OAuth2Details) (*OAuth2Token, error)
	//根据访问令牌获取访问令牌结构体
	ReadAccessToken(tokenValue string) (*OAuth2Token, error)
}

func NewUsernamePasswordTokenGrant(grantType string, userDetailService UserDetailsService, tokenService TokenService) TokenGrant {
	return &UsernamePasswordTokenGranter{
		supportGrantType:   grantType,
		userDetailsService: userDetailService,
		tokenService:       tokenService,
	}
}

/*令牌刷新*/
type RefreshTokenGranter struct {
	supportGrantType string
	tokenService     TokenService
}

func (rfg *RefreshTokenGranter) Grant(ctx context.Context, grantType string, client *ClientDetails, r *http.Request) (*OAuth2Token, error) {
	if grantType != rfg.supportGrantType {
		return nil, ErrNotSupportGrantType
	}
	//从请求中获取刷新令牌
	refreshTokenValue := r.URL.Query().Get("fresh_token")
	if refreshTokenValue == "" {
		return nil, ErrInvalidTokenRequest
	}
	return rfg.tokenService.RefreshAccessToken(refreshTokenValue)
}

func NewRefreshGranter(grantType string, userDetailsService UserDetailsService, tokenService TokenService) TokenGrant {
	return &RefreshTokenGranter{
		supportGrantType: grantType,
		tokenService:     tokenService,
	}
}

/*默认令牌服务*/
type DefaultTokenService struct {
	tokenStore    TokenStore
	tokenEnhancer TokenEnhancer
}

func NewTokenService(store TokenStore, enhancer TokenEnhancer) TokenService {
	return &DefaultTokenService{
		tokenStore:    store,
		tokenEnhancer: enhancer,
	}
}

//生成访问令牌
//尝试根据用户信息和客户端信息从TokenSotre中获取保存的访问令牌
//如果访问令牌已经失效，那么尝试根据用户信息和客户端信息生成一个新的访问令牌并返回
func (ds *DefaultTokenService) CreateAccessToken(oauth2details *OAuth2Details) (*OAuth2Token, error) {
	existToken, err := ds.tokenStore.GetAccessToken(oauth2details)
	var refreshToken *OAuth2Token
	if err == nil {
		//存在未失效的访问令牌，直接返回
		if !existToken.IsExpired() {
			ds.tokenStore.StoreAccessToken(existToken, oauth2details)
			return existToken, nil
		}
		//访问令牌已经失效，移除
		ds.tokenStore.RemoveAccessToken(existToken.TokenValue)
		if existToken.RefreshToken != nil {
			refreshToken = existToken.RefreshToken
			ds.tokenStore.RemoveRefreshToken(refreshToken.TokenValue)
		}
	}
	if refreshToken == nil || refreshToken.IsExpired() {
		//重新生成refreshToken
		refreshToken, err = ds.createRefreshToken(oauth2details)
		if err != nil {
			return nil, err
		}
	}

	//生成新的访问令牌
	accessToken, err := ds.createAccessToken(refreshToken, oauth2details)
	if err == nil {
		//保存新生成令牌
		ds.tokenStore.StoreAccessToken(accessToken, oauth2details)
		ds.tokenStore.StoreRefreshToken(refreshToken, oauth2details)
	}
	return accessToken, err

}

//根据刷新令牌和客户端及用户信息创建访问令牌
func (ds *DefaultTokenService) createAccessToken(refreshToken *OAuth2Token, details *OAuth2Details) (*OAuth2Token, error) {
	//token的有效时间
	validitySecond := details.Client.AccessTokenValiditySeconds
	s, _ := time.ParseDuration(strconv.Itoa(validitySecond) + "s")
	expiredTime := time.Now().Add(s)
	accessToken := &OAuth2Token{
		RefreshToken: refreshToken,
		ExpiresTime:  &expiredTime,
		TokenValue:   uuid.NewV4().String(),
	}
	//转换访问令牌的类型
	//如果配置了tokenEnhancer，令牌转换器，最后还会使用他来转化令牌的样式
	if ds.tokenEnhancer != nil {
		return ds.tokenEnhancer.Enhance(accessToken, details)
	}
	return accessToken, nil

}

//根据客户端信息和用户信息创建刷新令牌
func (ds *DefaultTokenService) createRefreshToken(details *OAuth2Details) (*OAuth2Token, error) {
	//token的有效时间
	validitySecond := details.Client.AccessTokenValiditySeconds
	s, _ := time.ParseDuration(strconv.Itoa(validitySecond) + "s")
	expiredTime := time.Now().Add(s)
	refreshToken := &OAuth2Token{
		ExpiresTime: &expiredTime,
		TokenValue:  uuid.NewV4().String(),
	}
	//转换授权令牌的类型
	if ds.tokenEnhancer != nil {
		return ds.tokenEnhancer.Enhance(refreshToken, details)
	}
	return refreshToken, nil
}

//使用访问令牌获取客户端信息和用户信息
func (ds *DefaultTokenService) GetOAuth2DetailsByAccessToken(tokenValue string) (*OAuth2Details, error) {
	accessToken, err := ds.tokenStore.ReadAccessToken(tokenValue)
	if err == nil {
		if accessToken.IsExpired() {
			return nil, ErrExpiredToken
		}
		return ds.tokenStore.ReadOAuth2Details(tokenValue)
	}
	return nil, err

}

//根据刷新令牌生成新的访问令牌和刷新令牌
//在客户端持有的访问令牌失效时，客户端可以使用刷新令牌重新生成新的有效的访问令牌
func (ds *DefaultTokenService) RefreshAccessToken(refreshTokenValue string) (*OAuth2Token, error) {
	//使用使用tokenSotore将刷新令牌值对应的刷新令牌结构体查询出来，用于判断刷新令牌是否过期
	//再根据刷新令牌之获取绑定的用户信息和客户端信息
	//最后移除原有的访问令牌和已使用的刷新令牌,并根据用户信息和客户端信息生成新的访问令牌和刷新令牌
	refreshToken, err := ds.tokenStore.ReadRefreshToken(refreshTokenValue)
	if err == nil {
		if refreshToken.IsExpired() {
			return nil, err
		}
		//未过期
		oauthDetails, err := ds.tokenStore.ReadOAuth2DetailsForRefreshToken(refreshTokenValue)
		if err == nil {
			oauth2Token, err := ds.tokenStore.GetAccessToken(oauthDetails)
			//移除原有的访问令牌
			if err == nil {
				ds.tokenStore.RemoveAccessToken(oauth2Token.TokenValue)
			}
			//移除已使用的刷新令牌
			ds.tokenStore.RemoveRefreshToken(refreshTokenValue)
			newRefreshToken, err := ds.createRefreshToken(oauthDetails)
			if err == nil {
				newAccessToken, err := ds.createAccessToken(newRefreshToken, oauthDetails)
				if err == nil {
					ds.tokenStore.StoreAccessToken(newAccessToken, oauthDetails)
					ds.tokenStore.StoreRefreshToken(newRefreshToken, oauthDetails)
				}
				return newAccessToken, err
			}

		}

	}
	return nil, err

}

func (ds *DefaultTokenService) GetAccessToken(details *OAuth2Details) (*OAuth2Token, error) {
	return ds.tokenStore.GetAccessToken(details)
}

func (ds *DefaultTokenService) ReadAccessToken(tokenValue string) (*OAuth2Token, error) {
	return ds.tokenStore.ReadAccessToken(tokenValue)
}

/**
令牌存储器
负责存储生成的的令牌并维护令牌、用户、客户端之间的绑定关系
*/
type TokenStore interface {
	//存储访问令牌
	StoreAccessToken(token *OAuth2Token, details *OAuth2Details)
	//根据令牌值获取访问令牌结构体
	ReadAccessToken(tokenValue string) (*OAuth2Token, error)
	//根据令牌值获取令牌对应的客户端和用户信息
	ReadOAuth2Details(tokenValue string) (*OAuth2Details, error)
	//根据客户端信息和用户信息获取访问令牌
	GetAccessToken(details *OAuth2Details) (*OAuth2Token, error)
	//移除存储的访问令牌
	RemoveAccessToken(tokenValue string)
	//存储刷新令牌
	StoreRefreshToken(token *OAuth2Token, details *OAuth2Details)
	//移除存储的刷新令牌
	RemoveRefreshToken(oauth2Token string)
	//根据令牌值获取刷新令牌
	ReadRefreshToken(tokenValue string) (*OAuth2Token, error)
	//根据令牌值获取刷新令牌对应的客户端信息和用户信息
	ReadOAuth2DetailsForRefreshToken(tokenValue string) (*OAuth2Details, error)
}

//token增强
type TokenEnhancer interface {
	//组装token信息
	Enhance(token *OAuth2Token, details *OAuth2Details) (*OAuth2Token, error)
	//从token中还原信息
	Extract(tokenValue string) (*OAuth2Token, *OAuth2Details, error)
}

type JwtTokenStore struct {
	jwtTokenEnhancer *JWTTokenEnhancer
}
type JWTTokenEnhancer struct {
	secretKey []byte
}
