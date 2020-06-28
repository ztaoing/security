package service

import (
	"context"
	"errors"
	"security/model"
)

var (
	ErrClientExits  = errors.New("client id is not exits")
	ErrClientSecret = errors.New("invalid client secret")
)

type ClientDetailsService interface {
	//根据客户端id加载并验证客户端信息
	GetClientDetailsByClientId(ctx context.Context, clientId string, clientSecret string) (*model.ClientDetails, error)
}

type InMemoryClientDetailsService struct {
	clientDetailsDict map[string]*model.ClientDetails
}

func (service *InMemoryClientDetailsService) GetClientDetailsByClientId(ctx context.Context, clientId string, clientSecret string) (*model.ClientDetails, error) {
	//根据clientId 获取clientDetails
	clientDetails, ok := service.clientDetailsDict[clientId]
	if ok {
		//比较clientSecret是否正确
		if clientDetails.ClientSecret == clientSecret {
			return clientDetails, nil
		} else {
			return nil, ErrClientSecret
		}
	} else {
		return nil, ErrClientExits
	}
}

func NewInMemoryClientDetailService(clientDetailsList []*model.ClientDetails) *InMemoryClientDetailsService {

	clientDetailsDict := make(map[string]*model.ClientDetails)

	if clientDetailsDict != nil {
		for _, value := range clientDetailsList {
			clientDetailsDict[value.ClientId] = value
		}
	}
	return &InMemoryClientDetailsService{
		clientDetailsDict: clientDetailsDict,
	}

}
