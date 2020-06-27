package model

type UserDetails struct {
	//用户id
	UserId int64
	//用户名 唯一
	UserName string
	//密码
	Password string
	//拥有的权限
	Authorities []string
}
