package main

import (
	"context"
	"flag"
	"fmt"
	uuid "github.com/satori/go.uuid"
	"net/http"
	"os"
	"os/signal"
	"security/common/discover"
	"security/config"
	"security/endpoint"
	"security/model"
	"security/service"
	"security/transport"
	"strconv"
	"syscall"
)

/**
在完成service层、endpoint层、transport层之后，完成main
使用搭建好的授权服务器请求访问令牌和验证访问令牌
*/
func main() {
	//依次构建service层、endpoint层、transport层
	var (
		servicePort = flag.Int("service.port", 10098, "service port")
		serviceHost = flag.String("service.host", "127.0.0.1", "service host")
		consulPort  = flag.Int("consul.port", 8500, "consul port")
		consulHost  = flag.String("consul.host", "127.0.0.1", "consul host")
		serviceName = flag.String("service.name", "oauth", "service name")
	)
	flag.Parse()

	ctx := context.Background()
	errChan := make(chan error)

	//发现服务
	var discoveryClient discover.DiscoveryClient

	discoveryClient, err := discover.NewKitDiscoverClient(*consulHost, *consulPort)
	if err != nil {
		config.Logger.Println("get consul client failed")
		os.Exit(-1)
	}

	var (
		svc service.Service
		//令牌管理
		tokenService service.TokenService
		//令牌生成
		tokenGranter service.TokenGrant
		//令牌加强
		tokenEnhancer service.TokenEnhancer
		//令牌存储
		tokenStore service.TokenStore
		//用户信息
		userDetailsService service.UserDetailsService
		//客户端信息
		clientDetailsService service.ClientDetailsService
	)

	tokenEnhancer = service.NewJWTTokenEnhancer("secret")
	tokenStore = service.NewJwtTokenStore(tokenEnhancer.(*service.JWTTokenEnhancer))
	tokenService = service.NewTokenService(tokenStore, tokenEnhancer)

	//用户信息
	userDetailsService = service.NewInMemoryUserDetailsService([]*model.UserDetails{{
		UserName:    "simple",
		Password:    "123456",
		UserId:      1,
		Authorities: []string{"Simple"},
	},
		{
			UserName:    "admin",
			Password:    "123456",
			UserId:      1,
			Authorities: []string{"Admin"},
		},
	})
	//客户端信息
	clientDetailsService = service.NewInMemoryClientDetailService([]*model.ClientDetails{{
		"clientId",
		"clientSecret",
		1800,
		18000,
		"http://127.0.0.1",
		[]string{"password", "refresh_token"},
	},
	})

	//token生成器
	tokenGranter = service.NewComposeTokenGranter(map[string]service.TokenGrant{
		//访问令牌：用户密码令牌生成
		"password": service.NewUsernamePasswordTokenGrant("password", userDetailsService, tokenService),
		//刷新令牌
		"refresh_token": service.NewRefreshGranter("fresh_token", userDetailsService, tokenService),
	})

	svc = service.NewCommonService()

	//endpoint层
	simpleEndpoint := endpoint.MakeSimpleEndpoint(svc)
	//认证
	simpleEndpoint = endpoint.MakeOAuth2AuthorizationMiddleware(config.KitLogger)(simpleEndpoint)

	adminEndpoint := endpoint.MakeAdminEndpoint(svc)
	//认证
	adminEndpoint = endpoint.MakeOAuth2AuthorizationMiddleware(config.KitLogger)(adminEndpoint)
	//鉴权
	adminEndpoint = endpoint.MakeAuthorityAuthorizationMiddleware("Admin", config.KitLogger)(adminEndpoint)

	//从context中获取到请求客户端信息，然后委托给tokengrant根据授权类型和用户凭证为客户端生成访问令牌并返回
	tokenEndpoint := endpoint.MakeTokenEndpoint(tokenGranter, clientDetailsService)
	//验证请求上下文中是否携带了客户端信息，如果请求中没有携带验证过的客户端信息，将直接返回错误给请求方
	tokenEndpoint = endpoint.MakeClientAuthorizationMiddleware(config.KitLogger)(tokenEndpoint)

	//将请求中的tokenValue传递给TokenService.GetOAuth2DetailsByAccessToken方法以验证token的有效性
	checkTokenEndpoint := endpoint.MakeCheckTokenEndpoint(tokenService)
	//验证请求上下文中是否携带了客户端信息，如果请求中没有携带验证过的客户端信息，将直接返回错误给请求方
	checkTokenEndpoint = endpoint.MakeClientAuthorizationMiddleware(config.KitLogger)(checkTokenEndpoint)

	//创建健康检查的endpoint
	healthEndpoint := endpoint.MakeHealthCheckEndpoint(svc)

	endpts := endpoint.OAuth2Endpoints{
		TokenEndpoint:       tokenEndpoint,
		CheckTokenEndpoint:  checkTokenEndpoint,
		HealthCheckEndpoint: healthEndpoint,
		SimpleEndpoint:      simpleEndpoint,
		AdminEndpoint:       adminEndpoint,
	}

	//transport层
	r := transport.MakeHttpHandler(ctx, endpts, tokenService, clientDetailsService, config.KitLogger)

	//实例的id
	instanceId := *serviceName + "-" + uuid.NewV4().String()

	//http server
	go func() {
		config.Logger.Println("http server start at port:" + strconv.Itoa(*servicePort))
		//注册服务
		if !discoveryClient.Register(*serviceName, instanceId, "/health", *serviceHost, *servicePort, nil, config.Logger) {
			//注册失败
			config.Logger.Println("use-string-service for service %s failed.", serviceName)
			os.Exit(-1)
		}
		handler := r
		errChan <- http.ListenAndServe(":"+strconv.Itoa(*servicePort), handler)
	}()

	//停止
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errChan <- fmt.Errorf("%s", <-c)
	}()

	//退出
	error := <-errChan
	//注销服务
	discoveryClient.Deregister(instanceId, config.Logger)
	config.Logger.Println(error)
}
