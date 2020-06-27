package service

type Service interface {
	SimpleData(username string) string
	AdminData(username string) string
	HealthCheck() bool
}

//实现service接口
type CommonServices struct {
}

func NewCommonService() *CommonServices {
	return &CommonServices{}
}

func (cs *CommonServices) SimpleData(username string) string {
	return "hello" + username + " ,simple data,with simple authority"
}

func (cs *CommonServices) AdminData(username string) string {
	return "hello" + username + " ,admin data,with admin authority"
}

//这里仅仅返回true
func (cs *CommonServices) HealthCheck() bool {
	return true
}
