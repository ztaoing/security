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

//令牌认证
//客户端验证中间件
//验证请求上下文中是否携带了客户端信息，如果请求中没有携带验证过的客户端信息，将直接返回错误给请求方
//在进入Endpoint之前统一验证context中的OAuthDetails是否存在
func MakeClientAuthorizationMiddleware(logger log.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			//请求上下文是否存在错误
			if err, ok := ctx.Value(OAuth2ErrorKey).(error); ok {
				return nil, err
			}
			//验证客户端信息和用户信息是否存在，不存在则拒绝访问
			if _, ok := ctx.Value(OAuth2ClientDetailsKey).(*model.ClientDetails); !ok {
				return nil, ErrInvalidClientRequest
			}
			return next(ctx, request)
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

//访问资源服务器受保护的资源的端点，不仅需要请求中携带有效的访问令牌，
//还需要访问令牌对应的用户和客户端具备足够的权限
//在transport层中makeOAuth2AuthroizationContext请求处理器中获得了用户信息和客户端信息，
//可以根据他们具备的权限等级，判断是否具备访问点的权限
func MakeAuthorityAuthorizationMiddleware(authority string, logger log.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			if err, ok := ctx.Value(OAuth2ErrorKey).(error); ok {
				return nil, err
			}
			if details, ok := ctx.Value(OAuth2ClientDetailsKey).(*model.OAuth2Details); !ok {
				return nil, ErrInvalidClientRequest
			} else {
				for _, value := range details.User.Authorities {
					//权限检查
					if value == authority {
						return next(ctx, request)
					}
				}
			}
			return nil, ErrNotPermit

		}
	}
}

//Simple 和 Admin

type SimpleRequest struct {
}

type SimpleResponse struct {
	Result string `json:"result"`
	Error  string `json:"error"`
}

type AdminRequest struct {
}

type AdminResponse struct {
	Result string `json:"result"`
	Error  string `json:"error"`
}

//对应/simple节点
//从context中获取用户和客户端信息
func MakeSimpleEndpoint(svc service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		result := svc.SimpleData(ctx.Value(OAuth2DetailsKey).(*model.OAuth2Details).User.UserName)
		return &SimpleResponse{
			Result: result,
		}, nil
	}
}

//对应/admin节点
//从context中获取用户和客户端信息
func MakeAdminEndpoint(svc service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		result := svc.AdminData(ctx.Value(OAuth2DetailsKey).(*model.OAuth2Details).User.UserName)
		return &AdminResponse{
			Result: result,
		}, nil
	}
}

//在进入endpoint之前统一验证context中的OAuth2Details是否存在
func MakeOAuth2AuthorizationMiddleware(logger log.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			if err, ok := ctx.Value(OAuth2ErrorKey).(error); !ok {
				return nil, err
			}
			if _, ok := ctx.Value(OAuth2ClientDetailsKey).(*model.OAuth2Details); !ok {
				return nil, ErrInvalidUserRequest
			}
			return next(ctx, request)
		}
	}
}
