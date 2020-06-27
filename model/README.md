## 授权服务器
授权服务器的主要职责为办法访问令牌和验证访问令牌，对此需要对外提供两个接口：
* /oauth/get_token 用于客户端携带用户用户凭证请求访问令牌
* /oauth/check_token 用于验证访问令牌的有效性，返回访问令牌对应的客户端和用户信息

一般来讲，每个客户端都可以为用户申请访问令牌，因此一个有效的访问令牌是和客户端、用户，绑定的，这表示某一用户授予某一个客户端访问资源的权限。

实现授权服务器主要包含以下所示的模块：
* ClientDetailsService :用于获取客户端信息
* UserSeDetailsService :用于获取用户信息
* TokenGrant :用于根据授权类型进行不同的验证流程，并使用TokenService生成访问令牌
* TokenService :生成并管理令牌，使用TokenStore存储令牌
* TokenStore :负责存储令牌