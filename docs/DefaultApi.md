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
> Data delete_post()



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

try:
    api_response = api_instance.delete_post()
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->delete_post: %s\n" % e)
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**Data**](Data.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **keylookup_post**
> Data keylookup_post()



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

try:
    api_response = api_instance.keylookup_post()
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->keylookup_post: %s\n" % e)
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**Data**](Data.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **lookup_post**
> Data lookup_post()



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

try:
    api_response = api_instance.lookup_post()
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->lookup_post: %s\n" % e)
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**Data**](Data.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **read_post**
> Data read_post()



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

try:
    api_response = api_instance.read_post()
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->read_post: %s\n" % e)
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**Data**](Data.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **write_post**
> Data write_post()



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

try:
    api_response = api_instance.write_post()
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->write_post: %s\n" % e)
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**Data**](Data.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

