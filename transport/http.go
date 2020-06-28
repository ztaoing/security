package transport

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/transport"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	endpoint2 "security/endpoint"
	"security/service"
)

var (
	ErrorGrantTypeRequest = errors.New("invalid gran type request")
	ErrorTokenRequest     = errors.New("invalid request token")
)

/**
在transport层中，把MakeTokenEndpoint和MakeCheckTokenEndpoint暴露到/oauth/token 和/oauth/check_token端点中，
客户端就可以通过http的方式请求/oauth/token 和/oauth/check_token，获取访问令牌和验证访问令牌的有效性
*/
func MakeHttpHandler(ctx context.Context, endpoints endpoint2.OAuth2Endpoints, tokenService service.TokenService, detailsService service.ClientDetailsService, logger log.Logger) http.Handler {
	r := mux.NewRouter()
	/*options := []kithttp.ServerOption{
		kithttp.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
		kithttp.ServerErrorEncoder(encodeError),
	}*/
	//指标
	r.Path("/metrics").Handler(promhttp.Handler())

	clientAuthorizationOptions := []kithttp.ServerOption{
		//为了确保endpoint能投获取到已验证的客户端信息，在请求前执行
		kithttp.ServerBefore(makeClientAuthorizationContext(detailsService, logger)),
		kithttp.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
		kithttp.ServerErrorEncoder(encodeError),
	}

	r.Methods("POST").Path("/oauth/token").Handler(kithttp.NewServer(
		endpoints.TokenEndpoint,
		decodeTokenRequest,
		encodeJsonReponse,
		clientAuthorizationOptions...,
	))

	r.Methods("POST").Path("/oauth/check_token").Handler(kithttp.NewServer(
		endpoints.CheckTokenEndpoint,
		decodeCheckTokenRequest,
		encodeJsonReponse,
		clientAuthorizationOptions...,
	))

	oauth2AuthorizationOptions := []kithttp.ServerOption{
		kithttp.ServerBefore(makeOAuth2AuthroizationContext(tokenService, logger)),
		kithttp.ServerErrorHandler(transport.NewLogErrorHandler(logger)),
		kithttp.ServerErrorEncoder(encodeError),
	}

	r.Methods("GET").Path("/simple").Handler(kithttp.NewServer(
		endpoints.SimpleEndpoint,
		decodeSimpleRequest,
		encodeJsonReponse,
		oauth2AuthorizationOptions...,
	))

	r.Methods("GET").Path("/admin").Handler(kithttp.NewServer(
		endpoints.AdminEndpoint,
		decodeAdminRequest,
		encodeJsonReponse,
		oauth2AuthorizationOptions...,
	))

	return r
}

///oauth/token 端点用于请求访问令牌，它通过请求参数中的gran_type来识别请求访问令牌的授权类型，并验证请求中携带的客户端凭证和用户凭证是否有效
//只有通过验证的客户端请求才能获取访问令牌

// /oauth/check_token 端点提供给客户端和资源服务器验证访问令牌的有效性；如果访问令牌有效，则返回访问令牌绑定的用户信息和客户端信息

//在请求访问令牌之前，需要验证Authorization请求头中携带的客户端信息
func makeClientAuthorizationContext(service service.ClientDetailsService, logger log.Logger) kithttp.RequestFunc {
	return func(ctx context.Context, request *http.Request) context.Context {
		if clientId, clientSecret, ok := request.BasicAuth(); ok {
			clientDetail, err := service.GetClientDetailsByClientId(ctx, clientId, clientSecret)
			if err == nil {
				return context.WithValue(ctx, endpoint2.OAuth2ClientDetailsKey, clientDetail)
			}
		}
		return nil
	}
}

func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	switch err {
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": err.Error(),
	})

}

func decodeTokenRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	grantType := r.URL.Query().Get("grant_type")
	if grantType == "" {
		return nil, ErrorGrantTypeRequest
	}
	return &endpoint2.TokenRequest{
		GrantType: grantType,
		Reader:    r,
	}, nil
}

func decodeCheckTokenRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	tokenValue := r.URL.Query().Get("token")
	if tokenValue == "" {
		return nil, ErrorTokenRequest
	}
	return &endpoint2.CheckTokenRequest{
		Token: tokenValue,
	}, nil
}

func encodeJsonReponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	return json.NewEncoder(w).Encode(response)
}

//令牌认证
//从Authorization请求解析出访问令牌，然后使用TokenService根据访问令牌获取到用户信息和客户端信息
func makeOAuth2AuthroizationContext(tokenService service.TokenService, logger log.Logger) kithttp.RequestFunc {
	return func(ctx context.Context, r *http.Request) context.Context {
		//获取令牌
		accessToken := r.Header.Get("Authrization")
		var err error
		if accessToken != "" {
			//获取令牌对应的用户信息和客户端信息
			details, err := tokenService.GetOAuth2DetailsByAccessToken(accessToken)
			if err == nil {
				return context.WithValue(ctx, endpoint2.OAuth2ClientDetailsKey, details)
			}
		} else {
			err = ErrorGrantTypeRequest
		}
		return context.WithValue(ctx, endpoint2.OAuth2ErrorKey, err)
	}
}

func decodeSimpleRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	return &endpoint2.SimpleRequest{}, nil
}

func decodeAdminRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	return &endpoint2.AdminResponse{}, nil
}
