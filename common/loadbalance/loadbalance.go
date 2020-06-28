package loadbalance

import (
	"errors"
	"github.com/hashicorp/consul/api"
	"math/rand"
)

//负载均衡器
type LoadBalance interface {
	SelectService(service []*api.AgentService) (*api.AgentService, error)
}

type RandomLoadBalance struct {
}

var ErrNoInstance = errors.New("service instance are not existed")

//随机负载均衡
func (rb *RandomLoadBalance) SelectService(services []*api.AgentService) (*api.AgentService, error) {
	if services == nil || len(services) == 0 {
		return nil, ErrNoInstance
	}
	return services[rand.Intn(len(services))], nil
}

type WeightRoundRobinLoadBalance struct {
}
