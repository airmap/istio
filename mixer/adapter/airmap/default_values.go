package airmap

import (
	"time"

	"istio.io/istio/mixer/adapter/airmap/access"
)

var (
	defaultValidCount    int32 = 1
	defaultValidDuration       = 5 * time.Second
	defaultValues        struct {
		subject struct {
			ip        *access.Source_IP
			key       *access.API_Key
			userAgent *access.Source_UserAgent
		}

		action struct {
			namespace *access.API_Namespace
			name      *access.API_Name
			version   *access.API_Version
			method    *access.API_Method
			resource  *access.API_Resource
		}

		response struct {
			code    *access.Log_Response_Code
			message *access.Log_Response_Message
		}
	}
)

func init() {
	defaultValues.subject.ip = &access.Source_IP{
		AsBytes: []byte{255, 255, 255, 255},
	}
	defaultValues.subject.key = &access.API_Key{
		AsString: "unknown",
	}
	defaultValues.subject.userAgent = &access.Source_UserAgent{
		AsString: "unknown",
	}
	defaultValues.action.namespace = &access.API_Namespace{
		AsString: "unknown",
	}
	defaultValues.action.name = &access.API_Name{
		AsString: "unknown",
	}
	defaultValues.action.version = &access.API_Version{
		AsString: "unknown",
	}
	defaultValues.action.method = &access.API_Method{
		AsString: "unknown",
	}
	defaultValues.action.resource = &access.API_Resource{
		AsString: "unknown",
	}

	defaultValues.response.code = &access.Log_Response_Code{
		AsInt64: -1,
	}
	defaultValues.response.message = &access.Log_Response_Message{
		AsString: "unknown",
	}
}
