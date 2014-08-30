package eventapi

import (
	"encoding/json"
	"github.com/agoravoting/authapi/util"
)

type Event struct {
	Id               int64       `json:"-"`
	Name             string      `json:"name" db:"name"`
	AuthMethod       string      `json:"auth_method" db:"auth_method"`
	AuthMethodConfig interface{} `json:"auth_method_config" db:"auth_method_config"`
}

func ParseEvent(data []byte) (e *Event, err error) {
	e = &Event{}
	err = json.Unmarshal(data, e)
	return
}

func (e *Event) Marshal() ([]byte, error) {
	j, err := e.Json()
	if err != nil {
		return []byte(""), err
	}
	return util.JsonSortedMarshal(j)
}

func (e *Event) Json() (ret map[string]interface{}, err error) {
	config, err := util.JsonSortedMarshal(e.AuthMethodConfig)
	if err != nil {
		return
	}

	ret = map[string]interface{}{
		"name":               e.Name,
		"auth_method":        e.AuthMethod,
		"auth_method_config": config,
	}
	return
}
