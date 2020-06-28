package discover

import (
	"github.com/go-kit/kit/sd/consul"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/api/watch"
	"log"
	"strconv"
	"sync"
)

type KitConsulDiscoverClient struct {
	Host         string
	Port         int
	client       consul.Client
	config       *api.Config
	mutex        sync.Mutex
	instancesMap sync.Map
}

func NewKitDiscoverClient(consulHost string, consulPort int) (DiscoveryClient, error) {
	//通过host和port,组成config创建一个client
	consulConfig := api.DefaultConfig()
	consulConfig.Address = consulHost + ":" + strconv.Itoa(consulPort)
	apiClient, err := api.NewClient(consulConfig)
	if err != nil {
		return nil, err
	}
	client := consul.NewClient(apiClient)
	return &KitConsulDiscoverClient{
		Host:   consulHost,
		Port:   consulPort,
		config: consulConfig,
		client: client,
	}, err
}

//基于kit的consul服务注册
func (consulC *KitConsulDiscoverClient) Register(serviceName, instanceId, healthCheckUrl string, instanceHost string, instancePort int, meta map[string]string, logger *log.Logger) bool {
	//构建服务实例元数据
	serviceRegistration := &api.AgentServiceRegistration{
		ID:      instanceId,
		Name:    serviceName,
		Address: instanceHost,
		Port:    instancePort,
		Meta:    meta,
		Check: &api.AgentServiceCheck{
			DeregisterCriticalServiceAfter: "30s",
			HTTP:                           "http://" + instanceHost + ":" + strconv.Itoa(instancePort) + healthCheckUrl,
			Interval:                       "15s",
		},
	}

	//发送服务注册到 consul
	err := consulC.client.Register(serviceRegistration)
	if err != nil {
		log.Println("register service error")
		return false
	}

	log.Println("register service success")
	return true
}

//基于kit的consul注销
func (consulC *KitConsulDiscoverClient) Deregister(instanceId string, logger *log.Logger) bool {
	//构建包含服务实例ID的元数据
	serviceRegisteration := &api.AgentServiceRegistration{
		ID: instanceId,
	}

	//发送服务注销到consul
	err := consulC.client.Deregister(serviceRegisteration)
	if err != nil {
		logger.Println("deregister service err")
		return false
	}
	log.Println("deregister service success")
	return true
}

//基于kit的服务发现
func (consulC *KitConsulDiscoverClient) DiscoverServices(serviceName string, logger *log.Logger) []interface{} {
	//该服务已监控并缓存
	instanceList, ok := consulC.instancesMap.Load(serviceName)
	if ok {
		return instanceList.([]interface{})
	}

	//无缓存时
	consulC.mutex.Lock()
	//再次检查是否监控
	instanceList, ok = consulC.instancesMap.Load(serviceName)
	if ok {
		return instanceList.([]interface{})
	} else {
		//注册并run 一个watch
		go func() {
			//使用consul服务实例来监控某个服务名的服务实例是否变化
			params := make(map[string]interface{})
			params["type"] = "service"
			params["service"] = serviceName
			//保留处理程序是为了向后兼容，但仅支持基于
			//在索引参数上。 要支持基于哈希的监视，请设置HybridHandler。
			plan, _ := watch.Parse(params)
			plan.Handler = func(u uint64, i interface{}) {
				if i == nil {
					return
				}
				v, ok := i.([]*api.ServiceEntry)
				if !ok {
					return //数据异常
				}
				//没有服务实例在线
				if len(v) == 0 {
					consulC.instancesMap.Store(serviceName, []interface{}{})
				}

				var healthServices []interface{}
				for _, service := range v {
					//maintenance > critical > warning > passing
					//当服务实例的状态为passing时
					if service.Checks.AggregatedStatus() == api.HealthPassing {
						//将此实例加入健康实例列表中
						healthServices = append(healthServices, service.Service)
					}
				}
				consulC.instancesMap.Store(serviceName, healthServices)
			}
			defer plan.Stop()
			//run a watch plan
			plan.Run(consulC.config.Address)

		}()
	}
	defer consulC.mutex.Unlock()

	//根据服务名请求服务列表
	entries, _, err := consulC.client.Service(serviceName, "", false, nil)
	if err != nil {
		//没有可用的服务实例,注册此服务名称
		consulC.instancesMap.Store(serviceName, []interface{}{})
		logger.Println("discover service error")
		return nil
	}

	instances := make([]interface{}, len(entries))
	for i := 0; i < len(instances); i++ {
		instances[i] = entries[i].Service
	}
	consulC.instancesMap.Store(serviceName, instances)
	return instances
}
