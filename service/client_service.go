package service

import (
	"context"
	"security/model"
)

type ClientDetailsService interface {
	//根据客户端id加载并验证客户端信息
	GetClientDetailsByClientId(ctx context.Context, clientId string, clientSecret string) (*model.ClientDetails, error)
}
