import requests
import json
import pdb

PORTALBACKEND_HOST = 'portal-api-staging.incountry.io'
FALLBACK_HOST = 'us.staging-api.incountry.io'

class StorageError(Exception):
	pass

class StorageClientError(StorageError):
	pass

class StorageServerError(StorageError):
	pass


class Storage(object):
	def __init__(self, zone_id, api_key, host=FALLBACK_HOST):
		"""
			Returns a client to talk to the InCountry storage network. On init
			this class queries the storage network for the per-country API
			endpoints.

			@param zone_id: The id of the zone into which you wll store data
			@param api_key: Your API key
			@param host: Host name for the storage API endpoint
		"""
		self.api_key = api_key
		self.zone_id = zone_id
		# Map of country code to dict with 'endpoint' and 'name'
		self.poplist = {} 
		self.fallback_host = host
		# Load countries list. FIXME: Cache this data

		r = requests.get(f'http://{PORTALBACKEND_HOST}/countries')
		if r.status_code != 200:
			raise StorageClientError("Failed to retrieve country endpoint list")

		clist = r.json()
		if 'countries' in clist:
			for country in clist['countries']:
				if country['direct']:
					cc = country['id'].lower()
					# FIXME: Have countries API return the full endpoint
					self.poplist[cc] = \
						{'host': f"{cc}.api.incountry.io", 'name': country['name']}


	def getendpoint(self, country, path):
		# TODO: Make countries set cover ALL countries, indicating mini or med POP
		if not path.startswith("/"):
			path = f"/{path}"

		if country in self.poplist:
			return f"http://{self.poplist[country].host}{path}"
		else:
			return f"http://{self.fallback_host}{path}"


	def headers(self):
		return {'Authorization': f'Bearer {self.api_key}',
				'x-zone-id': self.zone_id,
				'Content-Type': 'application/json'}


	def check_parameters(self, country, key):
		if country is None:
			raise StorageClientError("Missing country")
		if key is None:
			raise StorageClientError("Missing key")


	def raise_if_server_error(self, response):
		if response.status_code >= 400:
			raise StorageServerError( \
				"{} {} - {}".format(response.status_code, response.url, response.text))



	def write(self,
		country, 
		key, 
		body=None, 
		profile_key=None, 
		range_key=None,
		key2=None,
		key3=None):

		self.check_parameters(country, key)		
		country = country.lower()
		data = {"country":country, "key":key}
		if body:
			data['body'] = body
		if profile_key:
			data['profile_key'] = profile_key
		if range_key:
			data['range_key'] = range_key
		if key2:
			data['key2'] = key2
		if key3:
			data['key3'] = key3

		r = requests.post(
			self.getendpoint(country, "/v2/storage/records"),
			headers=self.headers(),
			data=json.dumps(data))
		
		self.raise_if_server_error(r)

	def read(self, country, key):
		self.check_parameters(country, key)		
		country = country.lower()

		r = requests.get(
			self.getendpoint(country, f"/v2/storage/records/{key}"),
			headers=self.headers())
		if r.status_code == 404:
			# Not found is ok
			return None

		self.raise_if_server_error(r)
		return r.json()

	def delete(self, country, key):
		self.check_parameters(country, key)		
		country = country.lower()

		r = requests.delete(
			self.getendpoint(country, f"/v2/storage/records/{key}"),
			headers=self.headers())
		self.raise_if_server_error(r)
		return r.json()
