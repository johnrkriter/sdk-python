# incountry.DefaultApi

All URIs are relative to *https://87lh3zngr4.execute-api.us-east-1.amazonaws.com/prod*

Method | HTTP request | Description
------------- | ------------- | -------------
[**delete_post**](DefaultApi.md#delete_post) | **POST** /delete | 
[**keylookup_post**](DefaultApi.md#keylookup_post) | **POST** /keylookup | 
[**lookup_post**](DefaultApi.md#lookup_post) | **POST** /lookup | 
[**read_post**](DefaultApi.md#read_post) | **POST** /read | 
[**write_post**](DefaultApi.md#write_post) | **POST** /write | 


# **delete_post**
> Data delete_post(config, country, rowid)



### Example
```python
from __future__ import print_function
import time
import incountry
from incountry.rest import ApiException
from pprint import pprint

# Configure API key authorization: api_key
configuration = incountry.Configuration()
configuration.api_key['x-api-key'] = 'YOUR_API_KEY'
# Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
# configuration.api_key_prefix['x-api-key'] = 'Bearer'

# create an instance of the API class
api_instance = incountry.DefaultApi(incountry.ApiClient(configuration))
config = 'config_example' # str | 
country = 'country_example' # str | 
rowid = 'rowid_example' # str | 

try:
    api_response = api_instance.delete_post(config, country, rowid)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->delete_post: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **config** | **str**|  | 
 **country** | **str**|  | 
 **rowid** | **str**|  | 

### Return type

[**Data**](Data.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **keylookup_post**
> Data keylookup_post(config, country, key1=key1, key2=key2, key3=key3, key4=key4, key5=key5)



### Example
```python
from __future__ import print_function
import time
import incountry
from incountry.rest import ApiException
from pprint import pprint

# Configure API key authorization: api_key
configuration = incountry.Configuration()
configuration.api_key['x-api-key'] = 'YOUR_API_KEY'
# Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
# configuration.api_key_prefix['x-api-key'] = 'Bearer'

# create an instance of the API class
api_instance = incountry.DefaultApi(incountry.ApiClient(configuration))
config = 'config_example' # str | 
country = 'country_example' # str | 
key1 = 'key1_example' # str |  (optional)
key2 = 'key2_example' # str |  (optional)
key3 = 'key3_example' # str |  (optional)
key4 = 'key4_example' # str |  (optional)
key5 = 'key5_example' # str |  (optional)

try:
    api_response = api_instance.keylookup_post(config, country, key1=key1, key2=key2, key3=key3, key4=key4, key5=key5)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->keylookup_post: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **config** | **str**|  | 
 **country** | **str**|  | 
 **key1** | **str**|  | [optional] 
 **key2** | **str**|  | [optional] 
 **key3** | **str**|  | [optional] 
 **key4** | **str**|  | [optional] 
 **key5** | **str**|  | [optional] 

### Return type

[**Data**](Data.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **lookup_post**
> Data lookup_post(config, country, key1=key1, key2=key2, key3=key3, key4=key4, key5=key5)



### Example
```python
from __future__ import print_function
import time
import incountry
from incountry.rest import ApiException
from pprint import pprint

# Configure API key authorization: api_key
configuration = incountry.Configuration()
configuration.api_key['x-api-key'] = 'YOUR_API_KEY'
# Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
# configuration.api_key_prefix['x-api-key'] = 'Bearer'

# create an instance of the API class
api_instance = incountry.DefaultApi(incountry.ApiClient(configuration))
config = 'config_example' # str | 
country = 'country_example' # str | 
key1 = 'key1_example' # str |  (optional)
key2 = 'key2_example' # str |  (optional)
key3 = 'key3_example' # str |  (optional)
key4 = 'key4_example' # str |  (optional)
key5 = 'key5_example' # str |  (optional)

try:
    api_response = api_instance.lookup_post(config, country, key1=key1, key2=key2, key3=key3, key4=key4, key5=key5)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->lookup_post: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **config** | **str**|  | 
 **country** | **str**|  | 
 **key1** | **str**|  | [optional] 
 **key2** | **str**|  | [optional] 
 **key3** | **str**|  | [optional] 
 **key4** | **str**|  | [optional] 
 **key5** | **str**|  | [optional] 

### Return type

[**Data**](Data.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **read_post**
> Data read_post(config, country, rowid)



### Example
```python
from __future__ import print_function
import time
import incountry
from incountry.rest import ApiException
from pprint import pprint

# Configure API key authorization: api_key
configuration = incountry.Configuration()
configuration.api_key['x-api-key'] = 'YOUR_API_KEY'
# Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
# configuration.api_key_prefix['x-api-key'] = 'Bearer'

# create an instance of the API class
api_instance = incountry.DefaultApi(incountry.ApiClient(configuration))
config = 'config_example' # str | 
country = 'country_example' # str | 
rowid = 'rowid_example' # str | 

try:
    api_response = api_instance.read_post(config, country, rowid)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->read_post: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **config** | **str**|  | 
 **country** | **str**|  | 
 **rowid** | **str**|  | 

### Return type

[**Data**](Data.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **write_post**
> Data write_post(config, country, rowid, blob, key1=key1, key2=key2, key3=key3, key4=key4, key5=key5)



### Example
```python
from __future__ import print_function
import time
import incountry
from incountry.rest import ApiException
from pprint import pprint

# Configure API key authorization: api_key
configuration = incountry.Configuration()
configuration.api_key['x-api-key'] = 'YOUR_API_KEY'
# Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
# configuration.api_key_prefix['x-api-key'] = 'Bearer'

# create an instance of the API class
api_instance = incountry.DefaultApi(incountry.ApiClient(configuration))
config = 'config_example' # str | 
country = 'country_example' # str | 
rowid = 'rowid_example' # str | 
blob = 'blob_example' # str | 
key1 = 'key1_example' # str |  (optional)
key2 = 'key2_example' # str |  (optional)
key3 = 'key3_example' # str |  (optional)
key4 = 'key4_example' # str |  (optional)
key5 = 'key5_example' # str |  (optional)

try:
    api_response = api_instance.write_post(config, country, rowid, blob, key1=key1, key2=key2, key3=key3, key4=key4, key5=key5)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->write_post: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **config** | **str**|  | 
 **country** | **str**|  | 
 **rowid** | **str**|  | 
 **blob** | **str**|  | 
 **key1** | **str**|  | [optional] 
 **key2** | **str**|  | [optional] 
 **key3** | **str**|  | [optional] 
 **key4** | **str**|  | [optional] 
 **key5** | **str**|  | [optional] 

### Return type

[**Data**](Data.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

