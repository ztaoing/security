package service

import (
	"context"
	"errors"
	"security/model"
)

var (
	ErrUserNotExist = errors.New("username is not exist")
	ErrPassword     = errors.New("invalid password")
)

type UserDetailsService interface {
	//根据用户名加载并验证用户信息
	GetUserDetailByUserName(ctx context.Context, username string, password string) (*model.UserDetails, error)
}

//实现UserDetailsService接口
type InMemoryUserDetailsService struct {
	userDetailsDict map[string]*model.UserDetails
}

func NewInMemoryUserDetailsService(userDetailsList []*model.UserDetails) *InMemoryUserDetailsService {
	userDetailsDict := make(map[string]*model.UserDetails)
	if userDetailsList != nil {
		for _, value := range userDetailsList {
			userDetailsDict[value.UserName] = value
		}
	}
	return &InMemoryUserDetailsService{
		userDetailsDict: userDetailsDict,
	}
}

//通过用户名获取用户信息
func (us *InMemoryUserDetailsService) GetUserDetailsByUsername(ctx context.Context, username, password string) (*model.UserDetails, error) {
	//根据username获取用户信息
	if userDetails, ok := us.userDetailsDict[username]; ok {
		//获取到用户信息
		if userDetails.Password == password {
			return userDetails, nil
		} else {
			return nil, ErrPassword
		}

	} else {
		return nil, ErrUserNotExist
	}
}
