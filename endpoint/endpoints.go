package endpoint

import (
	"context"
	"errors"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"net/http"
	"security/model"
	"security/service"
)

const (
	OAuth2DetailsKey       = "OAuthDetails"
	OAuth2ClientDetailsKey = "OAuthClientDetails"
	OAuth2ErrorKey         = "OAuth2Error"
)

var (
	ErrInvalidClientRequest = errors.New("invalid client message")
	ErrInvalidUserRequest   = errors.New("invalid user message")
	ErrNotPermit            = errors.New("not permit")
)

type OAuth2Endpoints struct {
	TokenEndpoint       endpoint.Endpoint
	CheckTokenEndpoint  endpoint.Endpoint
	HealthCheckEndpoint endpoint.Endpoint
	SimpleEndpoint      endpoint.Endpoint
	AdminEndpoint       endpoint.Endpoint
}

type TokenRequest struct {
	GrantType string
	Reader    *http.Request
}

type TokenReponse struct {
	AccessToken *model.OAuth2Token `json:"access_token"`
	Error       string             `json:"error"`
}

//客户端验证中间件
//验证请求上下文中是否携带了客户端信息，如果请求中没有携带验证过的客户端信息，将直接返回错误给请求方
func MakeClientAuthorizationMiddleware(logger log.Logger) endpoint.Middleware {
	return func(e endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			//请求上下文是否存在错误
			if err, ok := ctx.Value(OAuth2ErrorKey).(error); ok {
				return nil, err
			}
			//验证客户端信息是否存在，不存在则返回异常
			if _, ok := ctx.Value(OAuth2ClientDetailsKey).(*model.ClientDetails); !ok {
				return nil, ErrInvalidClientRequest
			}
			return
		}
	}
}

/**
在transport层中，把MakeTokenEndpoint和MakeCheckTokenEndpoint暴露到/oauth/token 和/oauth/check_token端点中，
客户端就可以通过http的方式请求/oauth/token 和/oauth/check_token，获取访问令牌和验证访问令牌的有效性
*/
//从context中获取到请求客户端信息，然后委托给tokengrant根据授权类型和用户凭证为客户端生成访问令牌并返回
func MakeTokenEndpoint(grant service.TokenGrant, detailsService service.ClientDetailsService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(*TokenRequest)
		token, err := grant.Grant(ctx, req.GrantType, ctx.Value(OAuth2ClientDetailsKey).(*model.ClientDetails), req.Reader)
		var errString = ""
		if err != nil {
			errString = err.Error()
		}
		return TokenReponse{
			AccessToken: token,
			Error:       errString,
		}, nil
	}
}

type CheckTokenRequest struct {
	Token         string
	ClientDetails model.ClientDetails
}

type CheckTokenResponse struct {
	OAuthDetails *model.OAuth2Details `json:"o_auth_details"`
	Error        string               `json:"error"`
}

//将请求中的tokenValue传递给TokenService.GetOAuth2DetailsByAccessToken方法以验证token的有效性
func MakeCheckTokenEndpoint(tokenService service.TokenService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(*CheckTokenRequest)
		//根据访问令牌获取用户信息和客户端信息
		tokenDetails, err := tokenService.GetOAuth2DetailsByAccessToken(req.Token)
		var errString = ""
		if err != nil {
			errString = err.Error()
		}
		return CheckTokenResponse{
			OAuthDetails: tokenDetails,
			Error:        errString,
		}, nil
	}
}

type HealthRequest struct {
}
type HealthReponse struct {
	Status bool `json:"status"`
}

func MakeHealthCheckEndpoint(svc service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		status := svc.HealthCheck()
		return HealthReponse{
			Status: status,
		}, nil
	}
}
